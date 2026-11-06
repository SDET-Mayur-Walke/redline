import json

import pytest
from fakes import LoopingLLM, ScriptedLLM, call

from redline.agent.agent import MAX_STEPS_REPLY, Agent, LLMReply, LLMToolCall, render_prompt
from redline.config import Config
from redline.store.store import AUTO_REFUND_LIMIT, RETURN_WINDOW_DAYS, Store

ME = "C0011"


@pytest.fixture
def make_agent(kb_retriever):
    def make(llm, **agent_cfg):
        cfg = Config()
        cfg.agent = cfg.agent.model_copy(update={"auto_retrieve": False, **agent_cfg})
        return Agent(cfg, Store(), kb_retriever, llm=llm)
    return make


def test_prompt_renders_policy_numbers_and_customer():
    s = Store()
    p = render_prompt("support_v1", s, ME)
    assert s.customer(ME)["name"] in p and ME in p
    assert f"within {RETURN_WINDOW_DAYS} days of delivery" in p and f"₹{AUTO_REFUND_LIMIT:,}" in p
    assert "$" not in p                      # every placeholder filled


def test_plain_answer_without_tools(make_agent):
    a = make_agent(ScriptedLLM("Hello! Returns are open for 10 days [returns-policy#overview]."))
    t = a.chat("s", ME, "hi")
    assert t.stopped == "answer" and t.steps == 1 and t.tool_calls == []
    assert t.citations == ["returns-policy#overview"]
    assert t.usage["prompt_tokens"] == 100 and t.usage["llm_calls"] == 1


def test_tool_call_round_trip(make_agent):
    llm = ScriptedLLM([call("list_my_orders")], "You have 4 orders.")
    a = make_agent(llm)
    t = a.chat("s", ME, "what are my orders?")
    assert [c.name for c in t.tool_calls] == ["list_my_orders"] and len(t.tool_calls[0].result) == 4
    assert t.reply == "You have 4 orders." and t.steps == 2
    # the tool result went back to the model as a tool message tied to the call id
    tool_msg = llm.seen[1][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "call_1"
    assert json.loads(tool_msg["content"])[0]["order_id"].startswith("SC")


def test_several_tool_calls_in_one_step(make_agent):
    a = make_agent(ScriptedLLM([call("get_my_profile"), call("search_help_center", query="refund")], "done"))
    t = a.chat("s", ME, "x")
    assert [c.name for c in t.tool_calls] == ["get_my_profile", "search_help_center"]


def test_auto_retrieve_inserts_a_search_before_the_model(make_agent):
    llm = ScriptedLLM("UPI refunds take 1 to 3 business days.\nSources: [refund-timelines#overview]")
    t = make_agent(llm, auto_retrieve=True).chat("s", ME, "how long do UPI refunds take")
    assert [c.name for c in t.tool_calls] == ["search_help_center"]
    assert t.tool_calls[0].args == {"query": "how long do UPI refunds take"} and t.steps == 1
    roles = [m["role"] for m in llm.seen[0]]
    assert roles == ["system", "user", "assistant", "tool"]
    assert llm.seen[0][2]["tool_calls"][0]["id"] == llm.seen[0][3]["tool_call_id"]
    assert "citation" in llm.seen[0][3]["content"]


def test_auto_retrieve_skips_short_confirmations(make_agent):
    t = make_agent(ScriptedLLM("ok"), auto_retrieve=True).chat("s", ME, "yes please")
    assert t.tool_calls == []


def test_stops_at_max_steps(make_agent):
    a = make_agent(LoopingLLM(), max_steps=3)
    t = a.chat("s", ME, "loop forever")
    assert t.stopped == "max_steps" and t.steps == 3 and len(t.tool_calls) == 3
    assert t.reply == MAX_STEPS_REPLY


def test_bad_tool_arguments_are_reported_not_raised(make_agent):
    bad = LLMToolCall("c1", "get_order", "{not json")
    a = make_agent(ScriptedLLM([bad], "sorry"))
    t = a.chat("s", ME, "x")
    assert t.tool_calls[0].args == {"_raw": "{not json"} and "error" in t.tool_calls[0].result


def test_think_tags_are_stripped(make_agent):
    t = make_agent(ScriptedLLM("<think>hmm</think>\nHi there")).chat("s", ME, "x")
    assert t.reply == "Hi there"


def test_multi_turn_keeps_history_and_followup_acts(make_agent):
    pending = next(o for o in Store().orders_of(ME) if o["status"] == "pending")["order_id"]
    llm = ScriptedLLM(f"Shall I cancel {pending}?", [call("cancel_order", order_id=pending, reason="asked")], "Done.")
    a = make_agent(llm)
    a.chat("s", ME, f"cancel {pending}")
    t = a.chat("s", ME, "yes")
    assert [c.name for c in t.tool_calls] == ["cancel_order"]
    assert [m["role"] for m in llm.seen[1]] == ["system", "user", "assistant", "user"]
    assert a.store.effects.cancellations == [pending]
    tr = a.conversations["s"].transcript(a.store)
    assert [x["role"] for x in tr.turns] == ["user", "assistant", "user", "assistant"]
    assert tr.final_output == "Done." and tr.outcome["cancellations"] == [pending]
    assert tr.usage["llm_calls"] == 3


def test_session_cannot_switch_customer(make_agent):
    a = make_agent(ScriptedLLM("hi", "hi"))
    a.chat("s", ME, "x")
    with pytest.raises(ValueError):
        a.chat("s", "C0002", "x")


def test_reset_clears_store_sessions_and_planted_docs(make_agent):
    from redline.kb.corpus import Document

    pending = next(o for o in Store().orders_of(ME) if o["status"] == "pending")["order_id"]
    a = make_agent(ScriptedLLM([call("cancel_order", order_id=pending, reason="x")], "ok"))
    base = a.retriever.count()
    a.retriever.add_documents([Document("p", "p", "planted text", {"audience": "public"})])
    a.chat("s", ME, "x")
    a.reset()
    assert a.store.effects.cancellations == [] and a.conversations == {} and a.retriever.count() == base


def test_litellm_reply_is_parsed(monkeypatch):
    """The real LLM wrapper, with litellm.completion stubbed: maps tool calls, usage and thinking off."""
    from types import SimpleNamespace as NS

    from redline.agent.agent import LiteLLMChat

    seen = {}

    def fake_completion(**kw):
        seen.update(kw)
        tc = NS(id="x1", function=NS(name="get_order", arguments='{"order_id": "SC1"}'))
        return NS(choices=[NS(message=NS(content=None, tool_calls=[tc]))],
                  usage=NS(prompt_tokens=7, completion_tokens=3))

    chat = LiteLLMChat(Config())
    chat._completion = fake_completion
    r = chat([{"role": "user", "content": "x"}], [])
    assert r == LLMReply("", [LLMToolCall("x1", "get_order", '{"order_id": "SC1"}')], 7, 3)
    assert seen["model"] == "ollama_chat/qwen3:8b" and seen["reasoning_effort"] == "none"
    assert seen["num_ctx"] == 16384 and seen["temperature"] == 0.2
