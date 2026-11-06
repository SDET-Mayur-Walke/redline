"""The support agent: a plain tool-calling loop over LiteLLM, sessions kept in memory.

Nothing clever on purpose. The loop sends the conversation plus the tool
schemas, runs whatever tools the model asks for, feeds the results back, and
stops when the model answers in text or after `max_steps` model calls. What
the agent *did* (every tool call with its arguments and result) is recorded
so the graders can judge actions, not just the reply.

The LLM is injectable (`LLM` below) so tests can script it.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from string import Template
from typing import Protocol

from agentproof import ToolCall, Transcript

from redline.agent.tools import SCHEMAS, Session, SupportTools, ToolPolicy, to_json
from redline.config import ROOT, Config
from redline.store.store import AUTO_REFUND_LIMIT, RETURN_WINDOW_DAYS, Store

PROMPTS = ROOT / "prompts"
CITATION = re.compile(r"\[([a-z0-9-]+#[a-z0-9-]+)\]")
THINK = re.compile(r"<think>.*?</think>", re.S)
MAX_STEPS_REPLY = "Sorry, I couldn't finish that. Shall I create a ticket for our support team?"
AUTO_SEARCH_MIN_WORDS = 3     # "yes", "ok thanks": confirmations, not questions; searching them only adds noise


@dataclass
class LLMToolCall:
    id: str
    name: str
    arguments: str          # raw JSON text as the model produced it; may be malformed


@dataclass
class LLMReply:
    content: str
    tool_calls: list[LLMToolCall] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLM(Protocol):
    def __call__(self, messages: list[dict], tools: list[dict]) -> LLMReply: ...


class LiteLLMChat:
    """ollama_chat/<model> through LiteLLM, thinking off, with an explicit context window."""

    def __init__(self, cfg: Config):
        import litellm

        litellm.suppress_debug_info = True
        self._completion = litellm.completion
        self.model = f"ollama_chat/{cfg.models.agent}"
        self.kwargs = {"api_base": cfg.models.ollama_base_url, "temperature": cfg.agent.temperature,
                       "num_ctx": cfg.agent.num_ctx, "timeout": cfg.agent.timeout,
                       # litellm maps reasoning_effort to Ollama's `think`; "none" turns qwen3 reasoning off
                       "reasoning_effort": "medium" if cfg.agent.think else "none"}

    def __call__(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        r = self._completion(model=self.model, messages=messages, tools=tools, **self.kwargs)
        m = r.choices[0].message
        calls = [LLMToolCall(tc.id or f"call_{i}", tc.function.name, tc.function.arguments or "{}")
                 for i, tc in enumerate(m.tool_calls or [])]
        return LLMReply(m.content or "", calls, r.usage.prompt_tokens or 0, r.usage.completion_tokens or 0)


@dataclass
class TurnResult:
    reply: str
    tool_calls: list[ToolCall]
    citations: list[str]
    steps: int
    stopped: str            # "answer" or "max_steps"
    usage: dict


@dataclass
class Conversation:
    """Everything one session has done, across turns: maps onto agentproof's Transcript."""
    session: Session
    turns: list[dict] = field(default_factory=list)          # {"role", "content"}; assistant turns also list
                                                             # the tools called in that turn, in order
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict = field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "llm_calls": 0,
                                                 "latency_s": 0.0})

    def transcript(self, store: Store, error: str | None = None) -> Transcript:
        final = next((t["content"] for t in reversed(self.turns) if t["role"] == "assistant"), "")
        return Transcript(final_output=final, tool_calls=list(self.tool_calls), outcome=store.effects.as_dict(),
                          turns=list(self.turns), usage=dict(self.usage), error=error)


def render_prompt(name: str, store: Store, customer_id: str) -> str:
    c = store.customer(customer_id)
    return Template((PROMPTS / f"{name}.md").read_text()).substitute(
        today=store.now.date().isoformat(), customer_name=c["name"], customer_id=customer_id,
        return_window=RETURN_WINDOW_DAYS, auto_refund_limit=f"{AUTO_REFUND_LIMIT:,}")


def _parse_args(raw: str) -> dict | None:
    try:
        args = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return None
    return args if isinstance(args, dict) else None


class Agent:
    def __init__(self, cfg: Config, store: Store, retriever, llm: LLM | None = None,
                 policy: ToolPolicy | None = None, transport=None):
        self.cfg, self.store, self.retriever = cfg, store, retriever
        self.llm = llm or LiteLLMChat(cfg)
        self.tools = SupportTools(store, retriever, cfg.retrieval.index_metadata, policy, transport)
        self.conversations: dict[str, Conversation] = {}
        self._lock = threading.Lock()   # one store, one local model: serialise turns

    def reset(self) -> None:
        """Back to the pristine world: store data and effects, planted documents, sessions."""
        with self._lock:
            self.store.reset()
            self.retriever.reset()
            self.conversations.clear()

    def conversation(self, session_id: str, customer_id: str) -> Conversation:
        conv = self.conversations.get(session_id)
        if conv is None:
            s = Session(session_id, customer_id)
            s.messages.append({"role": "system", "content": render_prompt(self.cfg.agent.prompt, self.store,
                                                                          customer_id)})
            conv = self.conversations[session_id] = Conversation(s)
        elif conv.session.customer_id != customer_id:
            raise ValueError(f"session {session_id} belongs to another customer")
        return conv

    def chat(self, session_id: str, customer_id: str, message: str) -> TurnResult:
        with self._lock:
            return self._chat(self.conversation(session_id, customer_id), message)

    def _auto_search(self, s: Session, message: str):
        """Run search_help_center for the user's message and insert it as if the model had called it."""
        args = {"query": message}
        result = self.tools.call("search_help_center", args, s)
        call_id = f"auto_{len(s.messages)}"
        s.messages.append({"role": "assistant", "content": "", "tool_calls": [
            {"id": call_id, "type": "function", "function": {"name": "search_help_center",
                                                             "arguments": json.dumps(args)}}]})
        s.messages.append({"role": "tool", "tool_call_id": call_id, "name": "search_help_center",
                           "content": to_json(result)})
        return ToolCall("search_help_center", args, result)

    def _chat(self, conv: Conversation, message: str) -> TurnResult:
        s, calls = conv.session, []
        s.messages.append({"role": "user", "content": message})
        conv.turns.append({"role": "user", "content": message})
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "llm_calls": 0, "latency_s": 0.0}
        reply, stopped, steps = MAX_STEPS_REPLY, "max_steps", 0
        if self.cfg.agent.auto_retrieve and len(message.split()) >= AUTO_SEARCH_MIN_WORDS:
            calls.append(self._auto_search(s, message))

        while steps < self.cfg.agent.max_steps:
            steps += 1
            t0 = time.perf_counter()
            out = self.llm(s.messages, SCHEMAS)
            usage["latency_s"] += time.perf_counter() - t0
            usage["prompt_tokens"] += out.prompt_tokens
            usage["completion_tokens"] += out.completion_tokens
            usage["llm_calls"] += 1
            text = THINK.sub("", out.content).strip()

            if not out.tool_calls:
                reply, stopped = text, "answer"
                break
            s.messages.append({"role": "assistant", "content": text, "tool_calls": [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": c.arguments}}
                for c in out.tool_calls]})
            for c in out.tool_calls:
                args = _parse_args(c.arguments)
                result = (self.tools.call(c.name, args, s) if args is not None
                          else {"error": "arguments were not a JSON object"})
                calls.append(ToolCall(c.name, args if args is not None else {"_raw": c.arguments}, result))
                s.messages.append({"role": "tool", "tool_call_id": c.id, "name": c.name, "content": to_json(result)})

        s.messages.append({"role": "assistant", "content": reply})
        conv.turns.append({"role": "assistant", "content": reply, "tool_calls": [c.name for c in calls]})
        conv.tool_calls += calls
        for k, v in usage.items():
            conv.usage[k] += v
        usage["latency_s"] = round(usage["latency_s"], 3)
        return TurnResult(reply, calls, sorted(set(CITATION.findall(reply))), steps, stopped, usage)
