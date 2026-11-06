"""Tool rules, offline: session authorization, refund rules and human confirmation for side effects."""

import pytest
from fakes import ScriptedLLM, call
from fastapi.testclient import TestClient

from redline.agent.agent import Agent
from redline.agent.tools import PENDING, Session, SupportTools
from redline.api import create_app
from redline.config import Config
from redline.defenses.guard import LlamaGuard
from redline.defenses.pipeline import REFUSAL, Defenses
from redline.defenses.policy import EgressRule, PolicyChain, RefundRules, SessionAuthz, build_policy
from redline.store.store import AUTO_REFUND_LIMIT, Store

ME = "C0011"
RECENT, OLD, PENDING_COD = "SC0102109", "SC0112321", "SC0115059"   # delivered ~5 days, ~28 days; pending COD


@pytest.fixture
def store():
    return Store()


@pytest.fixture
def session():
    return Session("s", ME)


def foreign_order(store, status="pending"):
    return next(o for o in store.orders.values() if o["customer_id"] != ME and o["status"] == status)["order_id"]


def tools(store, kb_retriever, *rules, confirm=False):
    return SupportTools(store, kb_retriever, policy=PolicyChain(list(rules)), confirm_side_effects=confirm)


# ----- session authorization -----

@pytest.mark.parametrize("tool,extra", [
    ("get_order", {}), ("cancel_order", {"reason": "r"}), ("request_return", {"item_ids": ["x"], "reason": "r"}),
    ("update_order_address", {"address": {"line1": "1 Test Lane", "city": "Pune", "state": "MH", "pincode": "411001"}}),
    ("issue_refund", {"amount": 10, "method": "wallet", "reason": "r"}),
])
def test_foreign_orders_are_refused_for_every_order_tool(store, kb_retriever, session, tool, extra):
    t = tools(store, kb_retriever, SessionAuthz(store))
    r = t.call(tool, {"order_id": foreign_order(store), **extra}, session)
    assert r["blocked_by"] == "tool_authz"
    assert store.effects.as_dict()["refund_total"] == 0 and not store.effects.cancellations
    assert not store.effects.address_changes and not store.effects.returns


def test_missing_and_foreign_orders_look_the_same(store, kb_retriever, session):
    t = tools(store, kb_retriever, SessionAuthz(store))
    a = t.call("get_order", {"order_id": foreign_order(store)}, session)["error"]
    b = t.call("get_order", {"order_id": "SC9999999"}, session)["error"]
    assert a.replace(foreign_order(store), "X") == b.replace("SC9999999", "X")


def test_own_orders_pass(store, kb_retriever, session):
    t = tools(store, kb_retriever, SessionAuthz(store))
    assert t.call("get_order", {"order_id": RECENT}, session)["order_id"] == RECENT


def test_email_only_to_own_address(store, kb_retriever, session):
    t = tools(store, kb_retriever, SessionAuthz(store))
    own = store.customer(ME)["email"]
    assert t.call("send_email", {"to": "someone.else@example.com", "subject": "s", "body": "b"},
                  session)["blocked_by"] == "tool_authz"
    assert t.call("send_email", {"to": f"{own}, someone.else@example.com", "subject": "s", "body": "b"},
                  session)["blocked_by"] == "tool_authz"
    assert t.call("send_email", {"to": own.upper(), "subject": "s", "body": "b"}, session)["status"] == "sent"


# ----- refund rules -----

def refund(store, kb_retriever, session, **args):
    t = tools(store, kb_retriever, RefundRules(store))
    base = {"order_id": RECENT, "amount": 100, "method": "card_1", "reason": "damaged"}
    return t.call("issue_refund", {**base, **args}, session)


def test_refund_rules_allow_a_policy_refund(store, kb_retriever, session):
    assert refund(store, kb_retriever, session)["amount"] == 100


@pytest.mark.parametrize("args,why", [
    ({"amount": AUTO_REFUND_LIMIT + 1}, "limit"),
    ({"order_id": OLD}, "window"),
    ({"order_id": PENDING_COD, "method": "wallet"}, "not been delivered"),
    ({"method": "upi_1"}, "original payment method"),
    ({"amount": 0}, "positive"),
    ({"amount": "lots"}, "numeric"),
])
def test_refund_rules_refuse(store, kb_retriever, session, args, why):
    r = refund(store, kb_retriever, session, **args)
    assert r["blocked_by"] == "refund_rules" and why in r["error"]
    assert store.effects.refunds == []


def test_refund_never_exceeds_what_is_owed(store, kb_retriever, session):
    total = store.order(RECENT)["total"]
    assert refund(store, kb_retriever, session, amount=total - 100)["amount"] == total - 100
    r = refund(store, kb_retriever, session, amount=200)
    assert r["blocked_by"] == "refund_rules" and "still refundable" in r["error"]


def test_cod_refunds_go_to_wallet_or_saved_upi(store):
    rules = RefundRules(store)
    cod = next(o for o in store.orders.values() if o["payment"]["type"] == "cod")
    allowed = rules._allowed_methods(cod)
    assert "wallet" in allowed and "card_1" not in allowed and "cod" not in allowed


# ----- egress rule on fetch_url -----

def test_egress_rule_pins_the_allowlisted_port(store, kb_retriever, session):
    t = tools(store, kb_retriever, EgressRule(["localhost:8000"]))
    assert t.call("fetch_url", {"url": "http://localhost:9000/x"}, session)["blocked_by"] == "egress"
    assert store.effects.fetched_urls == []      # refused before the tool ran


# ----- human confirmation -----

def test_side_effects_wait_for_a_confirm(store, kb_retriever, session):
    t = tools(store, kb_retriever, confirm=True)
    r = t.call("cancel_order", {"order_id": PENDING_COD, "reason": "changed my mind"}, session)
    assert r["status"] == PENDING and store.effects.cancellations == []
    assert t.call("list_my_orders", {}, session)                      # reads are never held
    out = t.confirm(session, r["action_id"])
    assert out["status"] == "cancelled" and store.effects.cancellations == [PENDING_COD]
    assert "error" in t.confirm(session, r["action_id"])            # one confirm per action


def test_confirm_rechecks_policy(store, kb_retriever, session):
    t = SupportTools(store, kb_retriever, policy=RefundRules(store), confirm_side_effects=True)
    total = store.order(RECENT)["total"]
    a = t.call("issue_refund", {"order_id": RECENT, "amount": total, "method": "card_1", "reason": "r"}, session)
    b = t.call("issue_refund", {"order_id": RECENT, "amount": total, "method": "card_1", "reason": "r"}, session)
    assert t.confirm(session, a["action_id"])["amount"] == total
    assert t.confirm(session, b["action_id"])["blocked_by"] == "refund_rules"   # nothing left to refund
    assert len(store.effects.refunds) == 1


def _cfg(**defenses) -> Config:
    cfg = Config()
    cfg.agent = cfg.agent.model_copy(update={"auto_retrieve": False})
    cfg.defenses = cfg.defenses.model_copy(update=defenses)
    return cfg


def test_a_yes_in_chat_is_not_a_confirm(kb_retriever):
    llm = ScriptedLLM([call("cancel_order", order_id=PENDING_COD, reason="mistake")], "Please press Confirm.",
                      [call("cancel_order", order_id=PENDING_COD, reason="mistake")], "Please press Confirm.")
    a = Agent(_cfg(confirm_side_effects=True), Store(), kb_retriever, llm=llm)
    a.chat("s", ME, "cancel my order please")
    a.chat("s", ME, "yes")
    assert a.store.effects.cancellations == [] and len(a.conversations["s"].session.pending) == 2


def test_api_confirm_executes_the_pending_action(kb_retriever):
    llm = ScriptedLLM([call("cancel_order", order_id=PENDING_COD, reason="mistake")], "Please press Confirm.")
    with TestClient(create_app(cfg=_cfg(confirm_side_effects=True), retriever=kb_retriever, llm=llm)) as c:
        out = c.post("/chat", json={"session_id": "s", "customer_id": ME, "message": "cancel it"}).json()
        action = out["tool_calls"][0]["result"]["action_id"]
        assert c.get("/effects").json()["cancellations"] == []
        r = c.post("/confirm", json={"session_id": "s", "customer_id": ME, "action_id": action})
        assert r.status_code == 200 and c.get("/effects").json()["cancellations"] == [PENDING_COD]
        assert c.post("/confirm", json={"session_id": "s", "customer_id": "C0001",
                                        "action_id": action}).status_code == 404


def test_a_replaced_reply_cancels_that_turns_pending_actions(kb_retriever):
    """The guard refuses the reply, so the action proposed in the same turn must not stay confirmable."""
    def guard_chat(messages):                       # input safe, reply unsafe
        return "unsafe\nS6" if messages[-1]["role"] == "assistant" else "safe"

    llm = ScriptedLLM([call("cancel_order", order_id=PENDING_COD, reason="mistake")], "Please press Confirm.",
                      [call("cancel_order", order_id=PENDING_COD, reason="mistake")], "Please press Confirm.")
    cfg = _cfg(confirm_side_effects=True, guard_llm=True)
    a = Agent(cfg, Store(), kb_retriever, llm=llm,
              defenses=Defenses(cfg, guard=LlamaGuard("g", "http://x", chat=guard_chat)))
    t = a.chat("s", ME, "cancel my order please")
    s = a.conversations["s"].session
    held = t.tool_calls[0].result["action_id"]
    assert t.reply == REFUSAL and s.pending == {} and held in s.cancelled
    assert {"layer": "confirmation", "action": "block"}.items() <= s.events[-1].items()
    assert "cancelled" in a.confirm("s", ME, held)["error"]
    assert a.store.effects.cancellations == []

    a.defenses.guard = None                         # a later, unblocked turn holds its action as usual
    t2 = a.chat("s", ME, "cancel it")
    assert list(s.pending) == [t2.tool_calls[0].result["action_id"]]


# ----- wiring -----

def test_build_policy_follows_the_switches(store):
    assert type(build_policy(_cfg(), store)).__name__ == "ToolPolicy"
    chain = build_policy(_cfg(tool_authz=True, refund_rules=True, egress_filter=True), store)
    assert [type(r).__name__ for r in chain.rules] == ["SessionAuthz", "RefundRules", "EgressRule"]
