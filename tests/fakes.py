"""A scripted stand-in for the LLM, so the agent loop runs offline and deterministically."""

import json
from itertools import count

from redline.agent.agent import LLMReply, LLMToolCall


def call(name: str, **args) -> LLMToolCall:
    return LLMToolCall(id="", name=name, arguments=json.dumps(args))


class ScriptedLLM:
    """Each item in `script` is one model reply: a string (final answer) or a list of tool calls.
    Records the messages it was shown, so tests can check what reached the model."""

    def __init__(self, *script):
        self.script, self.seen, self._ids = list(script), [], count(1)

    def __call__(self, messages, tools):
        self.seen.append([dict(m) for m in messages])
        step = self.script.pop(0) if self.script else "(script exhausted)"
        if isinstance(step, str):
            return LLMReply(step, prompt_tokens=100, completion_tokens=10)
        calls = [LLMToolCall(c.id or f"call_{next(self._ids)}", c.name, c.arguments) for c in step]
        return LLMReply("", calls, prompt_tokens=100, completion_tokens=5)


class LoopingLLM:
    """Never stops calling tools: for max-steps tests."""

    def __call__(self, messages, tools):
        return LLMReply("", [LLMToolCall("c", "list_my_orders", "{}")])
