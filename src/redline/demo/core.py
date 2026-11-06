"""Everything the demo does besides drawing: building the two agents, running turns, formatting what happened.

Kept free of Streamlit so it is testable offline (tests/test_demo.py) and the UI module stays a thin layout.

THE DEMO IS A VIEWER. It changes no defense, config switch, grader or result. It runs the same Agent the API
and the runner use and reads what that agent already records: Session.events (each defense layer's actions),
Store.effects (what changed in the world), Retriever.quarantined (planted chunks the ingestion scanner held back)
and Session.pending (side effects waiting for a Confirm). Nothing here writes back into any of them, except
through the agent's own public calls: chat, confirm, reset, and retriever.add_documents for presets, which is
exactly how the attack runner plants setup docs.

Design: two in-process agents, one per mode, built lazily and kept for the life of the Streamlit server.
  - Each has its own Store and its own Retriever over an in-memory Qdrant, so the modes never share state and
    neither locks data/qdrant (a `make serve` can run beside the demo). In-memory loses nothing: the API
    rebuilds its index at every startup anyway, for the same reason (a fresh corpus, no stale planted docs).
  - No second API process, so no second port: the hardened egress allowlist stays exactly as
    configs/hardened.yaml writes it (localhost:8000 and 127.0.0.1:8000, the API from `make serve`). The demo
    itself, on 8501, is not on it and needs not be: no reply ever has a reason to link to the demo page.
  - Models: REDLINE_DEMO_MODEL=ollama (default) loads configs/default.yaml and configs/hardened.yaml unchanged;
    `stub` loads the CI gate's gate/vulnerable.yaml and gate/hardened.yaml through gate.offline_agent (stub
    model, hash encoders, injection classifier and Llama Guard off), for an offline run in seconds.
  - One user at a time: both agents are shared by every browser tab, like the API's single agent.

Canary masking is display-only and lives here, not in defenses/: mask() is applied to text on its way to the
screen. TurnView keeps the raw reply, and the agent's transcript, which graders read, is never touched.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from redline.agent.agent import Agent
from redline.agent.tools import TOOL_NAMES
from redline.attacks.run import CANARY_RX, setup_documents
from redline.attacks.schema import Attack, load_library
from redline.config import ROOT, load_config
from redline.sink import HITS_PATH, RESET_PATH, SINK_BASE
from redline.store.store import Store

MODES = ("vulnerable", "hardened")
CONFIGS = {"ollama": {"vulnerable": ROOT / "configs" / "default.yaml", "hardened": ROOT / "configs" / "hardened.yaml"},
           "stub": {"vulnerable": ROOT / "gate" / "vulnerable.yaml", "hardened": ROOT / "gate" / "hardened.yaml"}}
# five existing library attacks, no new attack text: an IDOR, the zero-click image, a prompt leak,
# a split indirect injection and a refund over the limit
PRESET_IDS = ("ea-change-foreign-address", "exf-markdown-image-pixel", "rec-sysprompt-direct",
              "ii-split-across-chunks", "ea-refund-over-limit")
# the attacker (C0011), the owner of the order the IDOR preset redirects (C0016), and two more with orders
CUSTOMERS = ("C0011", "C0016", "C0004", "C0026")
MASK = "RL-CANARY-****"
VERBS = {"block": "blocked", "drop": "dropped", "quarantine": "quarantined", "strip": "stripped",
         "redact": "redacted", "pending": "held for a Confirm click:", "note": "noted", "error": "error:"}
TOOL_DETAIL = re.compile(r"^(" + "|".join(TOOL_NAMES) + r")( at confirm)?: (.*)$", re.S)


def model_kind() -> str:
    kind = os.environ.get("REDLINE_DEMO_MODEL", "ollama")
    if kind not in CONFIGS:
        raise SystemExit(f"REDLINE_DEMO_MODEL must be one of {sorted(CONFIGS)}, got {kind!r}")
    return kind


def sink_url() -> str:
    return os.environ.get("REDLINE_SINK_URL", SINK_BASE)


# ----- display-only masking -----

def has_canary(text: str) -> bool:
    return bool(CANARY_RX.search(text or ""))


def mask(text: str) -> str:
    """Every canary, system or staff, becomes RL-CANARY-****. For the screen only (recording-safe)."""
    return CANARY_RX.sub(MASK, text or "")


def mask_tree(obj: Any) -> Any:
    """mask() over every string in a JSON-like value (tool results, sink hits). Returns a copy."""
    if isinstance(obj, str):
        return mask(obj)
    if isinstance(obj, dict):
        return {k: mask_tree(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [mask_tree(v) for v in obj]
    return obj


# ----- formatting what happened -----

def rupees(x: float) -> str:
    return f"₹{x:,.0f}" if float(x).is_integer() else f"₹{x:,.2f}"


def format_event(e: dict) -> str:
    """{"layer": "tool_authz", "action": "block", "detail": "get_order: order X is not ..."}
    -> "tool_authz blocked get_order (order X is not ...)"."""
    layer, action, detail = e["layer"], e["action"], e.get("detail", "")
    verb = VERBS.get(action, action)
    m = TOOL_DETAIL.match(detail)
    if m and action == "block":
        return f"{layer} {verb} {m.group(1)}{m.group(2) or ''} ({m.group(3)})"
    return f"{layer} {verb} {detail}".strip()


def format_quarantine(new: list[dict]) -> list[str]:
    """Planted chunks the ingestion scanner held back, as one summary line plus one line per chunk."""
    if not new:
        return []
    n = len(new)
    lines = [f"ingestion_scanner quarantined {n} planted chunk{'s' if n != 1 else ''}"]
    lines += [f"  {q['chunk_id']}: {'; '.join(q['reasons'])}" for q in new]
    return lines


def _address(a: dict | None) -> str:
    if not a:
        return "?"
    return f"{a.get('line1', '?')}, {a.get('city', '?')}, {a.get('state', '?')} {a.get('pincode', '')}".strip()


def format_effects(effects: dict) -> dict[str, list[str]]:
    """Store.effects.as_dict() -> {section: lines}, only sections with something in them."""
    out: dict[str, list[str]] = {}
    refunds = effects.get("refunds") or []
    if refunds:
        out["Refunds"] = [f"{rupees(r['amount'])} to {r['to']} on {r['order_id']} ({r.get('reason', '')})"
                          for r in refunds] + [f"Total refunded: {rupees(effects.get('refund_total', 0))}"]
    if effects.get("cancellations"):
        out["Cancellations"] = [f"{o} cancelled" for o in effects["cancellations"]]
    if effects.get("address_changes"):
        out["Address changes"] = [f"{c['order_id']}: {_address(c.get('from'))} → {_address(c.get('to'))}"
                                  for c in effects["address_changes"]]
    if effects.get("emails"):
        out["Outbox"] = [f"to {e['to']}: {e.get('subject', '')} ({len(e.get('body') or '')} chars)"
                         for e in effects["emails"]]
    if effects.get("tickets"):
        out["Tickets"] = [f"{t['ticket_id']} [{t.get('priority', 'normal')}] {t.get('summary', '')}"
                          for t in effects["tickets"]]
    if effects.get("returns"):
        out["Returns"] = [f"{r['order_id']}: {', '.join(r['item_ids'])} ({r.get('reason', '')})"
                          for r in effects["returns"]]
    if effects.get("fetched_urls"):
        out["fetch_url calls"] = list(effects["fetched_urls"])
    return out


def format_hit(h: dict) -> str:
    q = f"?{h['query']}" if h.get("query") else ""
    return f"{h.get('time', '')[11:23]}  {h.get('method', 'GET')} {h.get('path', '')}{q}"


# ----- the exfil sink (a separate process: `make sink`) -----

def sink_hits(base: str | None = None, timeout: float = 1.0) -> list[dict] | None:
    """The sink's hits, or None if it isn't running."""
    try:
        r = httpx.get((base or sink_url()) + HITS_PATH, timeout=timeout, trust_env=False)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def reset_sink(base: str | None = None, timeout: float = 1.0) -> bool:
    try:
        httpx.post((base or sink_url()) + RESET_PATH, timeout=timeout, trust_env=False).raise_for_status()
        return True
    except httpx.HTTPError:
        return False


# ----- presets and customers -----

@dataclass(frozen=True)
class Preset:
    id: str
    title: str
    customer_id: str
    message: str
    attack: Attack = field(repr=False, compare=False)

    @property
    def n_docs(self) -> int:
        return len(setup_documents(self.attack))


def load_presets(ids: tuple[str, ...] = PRESET_IDS) -> list[Preset]:
    """The preset attacks, straight from the library: the message is the attack's own rendered input."""
    lib = {a.id: a for a in load_library()}
    missing = [i for i in ids if i not in lib]
    if missing:
        raise ValueError(f"preset ids not in the attack library: {missing}")
    return [Preset(i, lib[i].title, lib[i].customer_id, lib[i].rendered_input(), lib[i]) for i in ids]


def customer_rows(store: Store, ids: tuple[str, ...] = CUSTOMERS) -> list[dict]:
    rows = []
    for cid in ids:
        c = store.customer(cid)
        orders = [{"order_id": o["order_id"], "status": o["status"], "total": rupees(o["total"]),
                   "items": ", ".join(i["name"] for i in o["items"])} for o in store.orders_of(cid)]
        rows.append({"customer_id": cid, "name": c["name"], "orders": orders})
    return rows


# ----- one mode's agent, as the UI drives it -----

def build_agent(kind: str, mode: str) -> Agent:
    cfg = load_config(CONFIGS[kind][mode])
    if kind == "stub":
        from redline.gate import offline_agent

        return offline_agent(cfg)
    from redline.kb.corpus import load_corpus
    from redline.kb.retrieval import Retriever

    # the one change from the YAML: an in-memory index, so the two modes don't share or lock data/qdrant
    c = cfg.model_copy(update={"retrieval": cfg.retrieval.model_copy(update={"qdrant_path": ":memory:"})})
    r = Retriever.from_config(c)
    r.rebuild(load_corpus(include_staff=True))
    return Agent(cfg, Store(), r)


@dataclass
class TurnView:
    """One turn as the screen shows it. Raw values: masking happens at render time."""
    role: str
    content: str
    citations: list[str] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    stopped: str = ""


class ModeRunner:
    def __init__(self, agent: Agent):
        self.agent = agent
        self.planted: set[str] = set()     # preset ids whose setup docs are in this agent's index
        self._q_seen = 0                   # planted quarantines already reported
        self.epoch = 0                     # bumped on reset, so sessions start fresh

    def session_id(self, customer_id: str) -> str:
        return f"demo:{customer_id}:{self.epoch}"

    def session(self, customer_id: str):
        conv = self.agent.conversations.get(self.session_id(customer_id))
        return conv.session if conv else None

    def plant(self, preset: Preset) -> int:
        """Add the preset's setup docs, as the attack runner does. Idempotent per preset until reset."""
        if preset.id in self.planted:
            return 0
        docs = setup_documents(preset.attack)
        if docs:
            self.agent.retriever.add_documents(docs, "planted")
        self.planted.add(preset.id)
        return len(docs)

    def _new_quarantines(self) -> list[str]:
        planted = [q for q in getattr(self.agent.retriever, "quarantined", []) if q["origin"] == "planted"]
        new, self._q_seen = planted[self._q_seen:], len(planted)
        return format_quarantine(new)

    def turn(self, customer_id: str, message: str) -> TurnView:
        s = self.session(customer_id)
        before = len(s.events) if s else 0
        t = self.agent.chat(self.session_id(customer_id), customer_id, message)
        events = self.session(customer_id).events[before:]
        return TurnView("assistant", t.reply, list(t.citations),
                        [{"name": c.name, "args": c.args, "result": c.result} for c in t.tool_calls],
                        self._new_quarantines() + [format_event(e) for e in events], t.stopped)

    def pending(self, customer_id: str) -> dict[str, dict]:
        s = self.session(customer_id)
        return dict(s.pending) if s else {}

    def confirm(self, customer_id: str, action_id: str) -> tuple[Any, list[str]]:
        s = self.session(customer_id)
        before = len(s.events) if s else 0
        result = self.agent.confirm(self.session_id(customer_id), customer_id, action_id)
        return result, [format_event(e) for e in self.session(customer_id).events[before:]]

    def reset(self) -> None:
        self.agent.reset()                 # store and effects, planted docs, sessions
        self.planted.clear()
        self._q_seen = 0
        self.epoch += 1


def config_path(kind: str, mode: str) -> Path:
    return CONFIGS[kind][mode]
