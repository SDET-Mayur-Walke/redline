"""Defense layers for the support agent, one module per layer, each behind a switch in config.defenses.

The rule for every module here: it must be GENERIC. A defense may know the shape of a threat (invisible
characters, text addressed to the assistant, a link to an unlisted host, a reply that reproduces protected
text) but never the test data: no planted-secret formats, sink ports, attack ids or phrases lifted from the attack
library. tests/test_defenses_generic.py greps this package to keep it that way.

Layers report what they did as events on the session, so the runner can say which layer stopped a trial:

    {"layer": "tool_authz", "action": "block", "detail": "..."}

`action` is one of ACTIONS. "note" is informational (spotlighting wrapped a result) and never counts as a block.
"""

from __future__ import annotations

from dataclasses import dataclass

ACTIONS = ("block", "drop", "quarantine", "strip", "redact", "pending", "note", "error")
STOPPING = frozenset(ACTIONS) - {"note", "error"}


@dataclass(frozen=True)
class Block:
    """A tool call refused by a policy layer."""
    layer: str
    reason: str


def record(events: list[dict], layer: str, action: str, detail: str) -> None:
    assert action in ACTIONS, action
    events.append({"layer": layer, "action": action, "detail": detail[:300]})


def stopping_layers(events: list[dict]) -> list[str]:
    """The layers that intervened (anything but a note), in first-seen order."""
    out: list[str] = []
    for e in events:
        if e["action"] in STOPPING and e["layer"] not in out:
            out.append(e["layer"])
    return out
