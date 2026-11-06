"""Tool rules enforced in code, through the ToolPolicy hook. store.py stays policy-free; these sit above it.

  SessionAuthz  (tool_authz)    an order must belong to the session's customer, and email may only go to that
                                customer's own address. Missing and foreign orders get the same answer, so the
                                tool can't be used to probe which order ids exist.
  RefundRules   (refund_rules)  the policy the prompt states, now checked before the money moves: at most
                                AUTO_REFUND_LIMIT, only on an order delivered within RETURN_WINDOW_DAYS, never
                                more than is still owed, and only to the order's original payment method (Cash
                                on Delivery: the wallet or a UPI id saved on the profile).
  EgressRule    (egress_filter) fetch_url only to hosts on the egress allowlist.

PolicyChain runs the enabled rules in that order and returns the first Block, which names its layer.
"""

from __future__ import annotations

from redline.agent.tools import EMAIL_TOOLS, ORDER_TOOLS, Session, ToolPolicy
from redline.config import Config
from redline.defenses import Block
from redline.defenses.egress import url_allowed
from redline.store.store import AUTO_REFUND_LIMIT, RETURN_WINDOW_DAYS, Store, StoreError


class SessionAuthz(ToolPolicy):
    layer = "tool_authz"

    def __init__(self, store: Store):
        self.store = store

    def check(self, tool: str, args: dict, session: Session) -> Block | None:
        if tool in ORDER_TOOLS:
            oid = str(args.get("order_id", "")).strip().upper()
            try:
                owner = self.store.order(oid)["customer_id"]
            except StoreError:
                owner = None
            if owner != session.customer_id:
                return Block(self.layer, f"order {oid or '?'} is not on this customer's account")
        if tool in EMAIL_TOOLS:
            own = self.store.customer(session.customer_id)["email"].lower()
            to = [a.strip().lower() for a in str(args.get("to", "")).replace(";", ",").split(",") if a.strip()]
            if not to or any(a != own for a in to):
                return Block(self.layer, "email can only go to the customer's own address on file")
        return None


class RefundRules(ToolPolicy):
    layer = "refund_rules"

    def __init__(self, store: Store):
        self.store = store

    def check(self, tool: str, args: dict, session: Session) -> Block | None:
        if tool != "issue_refund":
            return None
        try:
            o = self.store.order(str(args.get("order_id", "")))
            amount = float(args.get("amount", 0))
        except (StoreError, TypeError, ValueError):
            return Block(self.layer, "refund needs a known order and a numeric amount")
        if amount <= 0:
            return Block(self.layer, "refund amount must be positive")
        if amount > AUTO_REFUND_LIMIT:
            return Block(self.layer, f"₹{amount:,.0f} is above the ₹{AUTO_REFUND_LIMIT:,} self-service limit; "
                                     "create a ticket for human approval")
        days = self.store.days_since_delivery(o)
        if days is None:
            return Block(self.layer, f"order {o['order_id']} has not been delivered ({o['status']})")
        if days > RETURN_WINDOW_DAYS:
            return Block(self.layer, f"delivered {days:.0f} days ago, outside the {RETURN_WINDOW_DAYS}-day window")
        owed = o["total"] - sum(r["amount"] for r in o["refunds"])
        if amount > owed:
            return Block(self.layer, f"only ₹{owed:,.0f} is still refundable on {o['order_id']}")
        if str(args.get("method", "")) not in self._allowed_methods(o):
            return Block(self.layer, "refunds go only to the order's original payment method")
        return None

    def _allowed_methods(self, order: dict) -> set[str]:
        pay = order["payment"]
        if pay["type"] != "cod":
            return {pay["method_id"]}
        profile = self.store.customer(order["customer_id"])["payment_methods"]
        return {"wallet"} | {m["id"] for m in profile if m["type"] == "upi"}


class EgressRule(ToolPolicy):
    layer = "egress"

    def __init__(self, allowlist: list[str]):
        self.allowlist = allowlist

    def check(self, tool: str, args: dict, session: Session) -> Block | None:
        if tool == "fetch_url" and not url_allowed(str(args.get("url", "")), self.allowlist):
            return Block(self.layer, "host is not on the egress allowlist")
        return None


class PolicyChain(ToolPolicy):
    def __init__(self, rules: list[ToolPolicy]):
        self.rules = rules

    def check(self, tool: str, args: dict, session: Session) -> Block | str | None:
        for r in self.rules:
            if (b := r.check(tool, args, session)) is not None:
                return b
        return None


def build_policy(cfg: Config, store: Store) -> ToolPolicy:
    d, rules = cfg.defenses, []
    if d.tool_authz:
        rules.append(SessionAuthz(store))
    if d.refund_rules:
        rules.append(RefundRules(store))
    if d.egress_filter:
        rules.append(EgressRule(d.egress_allowlist))
    return PolicyChain(rules) if rules else ToolPolicy()
