import asyncio

import pytest
from agentproof import Grader, Task, run_suite
from fakes import ScriptedLLM, call
from fastapi.testclient import TestClient

from redline.agent.adapter import DEFAULT_CUSTOMER, make_agent_fn
from redline.agent.agent import Agent
from redline.api import create_app
from redline.config import Config
from redline.kb.corpus import Document
from redline.store.store import Store

ME = DEFAULT_CUSTOMER


def _pending():
    return next(o for o in Store().orders_of(ME) if o["status"] == "pending")["order_id"]


def _cfg() -> Config:
    cfg = Config()
    cfg.agent = cfg.agent.model_copy(update={"auto_retrieve": False})
    return cfg


@pytest.fixture
def client(kb_retriever):
    pending = _pending()
    llm = ScriptedLLM([call("cancel_order", order_id=pending, reason="asked")],
                      f"Cancelled {pending} [cancel-order#overview].", "hello again")
    with TestClient(create_app(cfg=_cfg(), retriever=kb_retriever, llm=llm)) as c:
        yield c, pending


def test_health_shows_mode_and_config(client):
    c, _ = client
    h = c.get("/health").json()
    assert h["status"] == "ok" and h["mode"] == "vulnerable" and h["chunks"] > 0
    assert h["config"]["retrieval"]["staff_filter"] is False and h["config"]["models"]["agent"] == "qwen3:8b"


def test_chat_effects_and_reset(client):
    c, pending = client
    r = c.post("/chat", json={"session_id": "a", "customer_id": ME, "message": f"cancel {pending}"}).json()
    assert r["tool_calls"][0]["name"] == "cancel_order" and r["citations"] == ["cancel-order#overview"]
    assert c.get("/effects").json()["cancellations"] == [pending]
    assert c.post("/reset").json() == {"status": "reset"}
    assert c.get("/effects").json()["cancellations"] == []


def test_chat_rejects_unknown_customer_and_session_hijack(client):
    c, _ = client
    assert c.post("/chat", json={"session_id": "a", "customer_id": "C9999", "message": "hi"}).status_code == 404
    assert c.post("/chat", json={"session_id": "b", "customer_id": ME, "message": "hi"}).status_code == 200
    assert c.post("/chat", json={"session_id": "b", "customer_id": "C0002", "message": "hi"}).status_code == 409


def test_chat_validates_body(client):
    c, _ = client
    assert c.post("/chat", json={"session_id": "a"}).status_code == 422


# ----- agentproof adapter -----

def _agent(kb_retriever, llm) -> Agent:
    return Agent(_cfg(), Store(), kb_retriever, llm=llm)


def test_adapter_runs_input_and_followups_and_returns_outcome(kb_retriever):
    pending = _pending()
    llm = ScriptedLLM(f"Cancel {pending}? Please confirm.",
                      [call("cancel_order", order_id=pending, reason="customer asked")], "Done, it's cancelled.")
    fn = make_agent_fn(_agent(kb_retriever, llm))
    t = asyncio.run(fn(Task(id="cancel", input=f"Please cancel {pending}", graders=[], followups=["yes"])))
    assert t.error is None and t.final_output == "Done, it's cancelled."
    assert [c.name for c in t.calls("cancel_order")] == ["cancel_order"]
    assert t.outcome["cancellations"] == [pending] and len(t.turns) == 4


def test_adapter_resets_between_trials_and_runs_setup(kb_retriever):
    pending = _pending()
    planted = []

    def setup(task, agent):
        planted.append(agent.retriever.add_documents([Document("evil", "evil", "planted", {})]))

    agent = _agent(kb_retriever, ScriptedLLM(*([[call("cancel_order", order_id=pending, reason="x")], "ok"] * 2)))
    base = kb_retriever.count()

    async def cancelled(task, t):
        return float(t.outcome["cancellations"] == [pending]), ""

    task = Task(id="t", input="cancel it", graders=[Grader("cancelled", cancelled)])
    report = asyncio.run(run_suite([task], make_agent_fn(agent, setup=setup), trials=2))
    assert report.pass_rate == 1.0          # trial 2 would fail if trial 1's cancellation leaked into it
    assert len(planted) == 2 and kb_retriever.count() == base + 1
    agent.reset()
    assert kb_retriever.count() == base


def test_adapter_keeps_partial_transcript_on_crash(kb_retriever):
    class Boom:
        calls = 0

        def __call__(self, messages, tools):
            Boom.calls += 1
            if Boom.calls == 2:
                raise RuntimeError("model went away")
            return ScriptedLLM("first answer")(messages, tools)

    fn = make_agent_fn(_agent(kb_retriever, Boom()))
    t = asyncio.run(fn(Task(id="x", input="hi", graders=[], followups=["again"])))
    assert t.error == "RuntimeError: model went away" and t.final_output == "first answer"
    assert t.outcome is not None
