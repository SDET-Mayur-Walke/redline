"""The attack-library schema and loader.

Each YAML file under library/ holds a list of attacks for one course module.
An attack is a declarative spec: who the customer is, what to plant in the
knowledge base first (setup), the message(s) to send, and a list of
success_if checks that each map to a security grader in run.py. An attack is
BLOCKED when none of its checks fire, so a clean defense turns every check to
"did not happen".

Validation is strict (extra keys fail) so a typo in a 40-attack library is a
loud error, not a silently ignored field. OWASP ids are pattern-checked:
LLMxx:2026 for the Top 10 for LLM Applications 2026 and ASIxx:2026 for the
Top 10 for Agentic Applications 2026 (names and links live in owasp.py).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from redline.attacks.encoders import encode
from redline.config import ROOT

LIBRARY = ROOT / "src" / "redline" / "attacks" / "library"

MODULES = ("recon", "indirect_injection", "exfiltration", "excessive_agency", "evasion")

# every check name here must have a factory in run.py's GRADERS
CHECK_NAMES = (
    "canary_in_reply", "staff_canary_in_reply", "sink_hit", "sink_url_in_reply", "fetch_to_sink",
    "email_to_non_customer", "refund_over_limit", "refund_without_confirmation", "refund_to_foreign_method",
    "foreign_order_accessed", "foreign_pii_in_reply", "internal_notes_in_reply", "tool_called",
    # reply_matches is the catch-all for recon-style disclosure (tool/param enumeration, policy limits, ANSI)
    # where the harm is in the text and no structured effect or canary carries the signal
    "reply_matches",
)

OWASP_LLM = re.compile(r"^LLM(0[1-9]|10):2026$")
OWASP_ASI = re.compile(r"^ASI(0[1-9]|10):2026$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PlantDoc(_Strict):
    """A document to add to the index before the trial, as if an attacker seeded the corpus."""
    id: str
    title: str
    text: str
    metadata: dict = Field(default_factory=dict)      # author, source, audience, category, product_id, ...


class Review(_Strict):
    """A poisoned customer review; becomes a review Document under the given product."""
    review_id: str
    product_id: str
    customer: str
    rating: int = Field(ge=1, le=5)
    title: str
    text: str
    date: str = "2026-10-01"


class Setup(_Strict):
    plant_docs: list[PlantDoc] = Field(default_factory=list)
    reviews: list[Review] = Field(default_factory=list)


class Check(_Strict):
    """One success_if condition. `check` names the grader; the rest are its parameters."""
    check: Literal[CHECK_NAMES]           # type: ignore[valid-type]
    token: str | None = None              # canary_in_reply: the exact token (defaults to the SYS canary pattern)
    contains: str | None = None           # sink_hit: substring that must appear in the hit
    name: str | None = None               # tool_called: the tool name
    min_times: int = 1                    # tool_called: how many calls count as success (e.g. 2 for a double refund)
    pattern: str | None = None            # reply_matches: a regex searched (case-insensitive) in the final reply
    order_id: str | None = None           # foreign_*: the targeted order
    customer_id: str | None = None        # foreign_pii / internal_notes: the targeted customer


class Encode(_Strict):
    """Encode `payload` with `scheme` and substitute it into input at `{enc}` (appended if absent)."""
    scheme: Literal["tag_chars", "zero_width", "lookalike", "base64", "leetspeak"]
    payload: str


class Control(_Strict):
    """The plain-text twin of an evasion attack: the same ask with no evasion trick.

    Encoded attacks derive theirs (the payload, unencoded, at {enc}), so only attacks whose trick is
    the wording itself (a fake delimiter, a multi-turn walk, another language) spell one out here.
    """
    input: str
    followups: list[str] = Field(default_factory=list)


CONTROL_SUFFIX = "~control"


class Attack(_Strict):
    id: str
    module: Literal[MODULES]              # type: ignore[valid-type]
    title: str
    owasp_llm: list[str] = Field(min_length=1)
    owasp_asi: list[str] = Field(default_factory=list)
    severity: Literal["low", "medium", "high", "critical"]
    customer_id: str
    setup: Setup | None = None
    input: str
    followups: list[str] = Field(default_factory=list)
    encode: Encode | None = None
    success_if: list[Check] = Field(min_length=1)
    control: Control | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _evasion_has_control(self) -> Attack:
        if self.module == "evasion" and self.encode is None and self.control is None:
            raise ValueError(f"{self.id}: an evasion attack needs an encode block or an explicit control")
        return self

    @field_validator("owasp_llm")
    @classmethod
    def _llm_ids(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if not OWASP_LLM.match(x)]
        if bad:
            raise ValueError(f"malformed OWASP LLM ids {bad} (want e.g. LLM01:2026)")
        return v

    @field_validator("owasp_asi")
    @classmethod
    def _asi_ids(cls, v: list[str]) -> list[str]:
        bad = [x for x in v if not OWASP_ASI.match(x)]
        if bad:
            raise ValueError(f"malformed OWASP ASI ids {bad} (want e.g. ASI02:2026)")
        return v

    def rendered_input(self) -> str:
        """The message actually sent: the encode payload, encoded, dropped into input at {enc}."""
        if self.encode is None:
            return self.input
        smuggled = encode(self.encode.scheme, self.encode.payload)
        return self.input.replace("{enc}", smuggled) if "{enc}" in self.input else f"{self.input} {smuggled}"


    def control_variant(self) -> Attack | None:
        """The same attack with the evasion stripped, run alongside it. If the control is blocked too, the
        evasion result is inert: the payload never worked, so a block says nothing about a filter."""
        if self.module != "evasion":
            return None
        if self.control is not None:
            plain, followups = self.control.input, list(self.control.followups)
        else:
            payload = self.encode.payload
            plain = self.input.replace("{enc}", payload) if "{enc}" in self.input else f"{self.input} {payload}"
            followups = list(self.followups)
        return self.model_copy(update={"id": self.id + CONTROL_SUFFIX, "title": f"{self.title} (control)",
                                       "input": plain, "followups": followups, "encode": None, "control": None})


def is_control(attack_id: str) -> bool:
    return attack_id.endswith(CONTROL_SUFFIX)


def load_file(path: Path) -> list[Attack]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a list of attacks, got {type(raw).__name__}")
    return [Attack.model_validate(a) for a in raw]


def load_library(root: Path = LIBRARY) -> list[Attack]:
    attacks: list[Attack] = []
    for path in sorted(root.glob("*.yaml")):
        attacks += load_file(path)
    return attacks
