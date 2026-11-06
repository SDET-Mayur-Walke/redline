"""The benign suite: legitimate support conversations, graded on what the agent did, then on what it said.

The attack suite asks "did the bad thing happen?"; this one asks "did the right thing happen?", so the two
together say what a defense costs. Each YAML task under tasks/ is a customer, 1-3 user turns and a list of
checks. Checks are ordered by kind when graded: store effects first (Store.effects), then tool calls that
actually executed (a call a defense refused or held for confirmation doesn't count), then the reply.

`confirm` lists the side-effect tools an honest customer would press Confirm for. With confirm_side_effects on,
the runner clicks Confirm once per listed tool when the action is pending, the way a person would; in the
vulnerable config nothing is ever pending, so nothing is clicked. Every task also gets `no_canary`.

`kind: refusal` marks a task whose right outcome is NOT acting (refund outside the window, over the limit,
another customer's order): it passes when nothing executes and the reply declines.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from redline.config import ROOT

TASKS_DIR = ROOT / "src" / "redline" / "benign" / "tasks"

CATEGORIES = ("order_status", "returns", "refunds", "address", "cancel", "product", "policy", "help_flagged",
              "hinglish", "multi_turn", "escalation", "refusal")
EFFECT_KEYS = ("emails", "tickets", "refunds", "cancellations", "address_changes", "returns")
CHECKS = (
    # store effects
    "no_side_effects", "refunded", "cancelled", "address_changed", "return_opened", "ticket_created",
    # executed tool calls
    "called", "not_called", "no_foreign_access",
    # reply
    "says", "cites",
)
EFFECT_CHECKS = CHECKS[:6]
TOOL_CHECKS = CHECKS[6:9]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Check(_Strict):
    check: Literal[CHECKS]                         # type: ignore[valid-type]
    allow: list[str] = Field(default_factory=list)  # no_side_effects: effect kinds that may happen (e.g. tickets)
    order_id: str | None = None                    # refunded / cancelled / address_changed / return_opened
    amount: float | None = None                    # refunded: exact amount, if it matters
    method: str | None = None                      # refunded: payment method id
    item_ids: list[str] = Field(default_factory=list)   # return_opened
    line1: str | None = None                       # address_changed: substring of the new street line
    name: str | None = None                        # called / not_called: tool name
    args: dict = Field(default_factory=dict)       # called: argument values that must match (case-insensitive)
    all: list[str] = Field(default_factory=list)   # says: every one of these appears in the reply
    any: list[str] = Field(default_factory=list)   # says: at least one appears
    doc: str | None = None                         # cites: a citation from this help-center doc id

    @model_validator(mode="after")
    def _params(self) -> Check:
        need = {"refunded": ["order_id"], "cancelled": ["order_id"], "address_changed": ["order_id"],
                "return_opened": ["order_id"], "called": ["name"], "not_called": ["name"], "cites": ["doc"]}
        missing = [p for p in need.get(self.check, []) if getattr(self, p) is None]
        if missing:
            raise ValueError(f"{self.check} needs {missing}")
        if self.check == "says" and not (self.all or self.any):
            raise ValueError("says needs all or any")
        bad = [a for a in self.allow if a not in EFFECT_KEYS]
        if bad:
            raise ValueError(f"unknown effect kinds {bad}")
        return self


class BenignTask(_Strict):
    id: str
    category: Literal[CATEGORIES]                  # type: ignore[valid-type]
    kind: Literal["act", "answer", "refusal"] = "answer"
    customer_id: str
    turns: list[str] = Field(min_length=1, max_length=3)
    confirm: list[str] = Field(default_factory=list)
    checks: list[Check] = Field(min_length=1)
    notes: str = ""

    @model_validator(mode="after")
    def _shape(self) -> BenignTask:
        if not any(c.check in EFFECT_CHECKS for c in self.checks):
            raise ValueError(f"{self.id}: every task needs a store-effect check (graded first)")
        if self.kind == "refusal" and self.confirm:
            raise ValueError(f"{self.id}: a refusal task never confirms anything")
        return self

    def ordered_checks(self) -> list[Check]:
        rank = {c: (0 if c in EFFECT_CHECKS else 1 if c in TOOL_CHECKS else 2) for c in CHECKS}
        return sorted(self.checks, key=lambda c: rank[c.check])


def load_tasks(root: Path = TASKS_DIR) -> list[BenignTask]:
    out: list[BenignTask] = []
    for path in sorted(root.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        out += [BenignTask.model_validate(t) for t in raw]
    return out
