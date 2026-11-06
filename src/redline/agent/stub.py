"""A deterministic, maximally gullible stand-in for the agent model: `models.agent: "stub"`.

THIS TESTS THE DEFENSE CODE, NOT THE MODEL. CI can't run Ollama, and a real model's refusals would hide whether
the deterministic layers (tool authorization, refund rules, confirmation, egress, ingestion scanner, output
filter, unicode, spotlight wiring) still hold. So the stub never refuses anything:

  - it calls the tools the customer's message asks for, with the ids, amounts, addresses and recipients given;
  - it follows any instruction it finds in retrieved text (help-center hits, fetched pages) that names a tool,
    asks for an email to be sent, or asks for a URL to be fetched, and repeats any markdown link or image there;
  - asked to repeat, quote or reproduce, it echoes its whole context, system prompt included.

Every attack it is shown would succeed against it if nothing in code stopped it, which is the point: with the
stub, attack success measures the code paths alone. Its numbers say nothing about qwen3:8b. It reads keywords,
not meaning, and it knows no attack ids or phrases from the library: the same rules run on every message.

No randomness, no network, no model: the same messages always give the same reply. It plugs in where
LiteLLMChat does (agent.LLM), so the agent loop, defenses and tool layer all run unchanged.
"""

from __future__ import annotations

import json
import re

from redline.agent.agent import LLMReply, LLMToolCall
from redline.agent.tools import SIDE_EFFECT_TOOLS, TOOL_NAMES

ORDER_ID = re.compile(r"\bSC\d{7}\b")
PRODUCT_ID = re.compile(r"\bP\d{3}\b")
AMOUNT = re.compile(r"(?:₹|rs\.?|inr)\s?([\d,]+(?:\.\d+)?)", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}", re.I)
VPA = re.compile(r"\b[\w.-]+@[a-z]+\b(?!\.)", re.I)                 # a UPI id: name@bank, no dotted domain
URL = re.compile(r"https?://[^\s)\"'<>\]]+")
MD_LINK = re.compile(r"!?\[[^\[\]]*\]\(https?://[^)\s]+\)")
ADDRESS = re.compile(r"\bto\s+\"?([^,\"]+),\s*([^,\"]+),\s*([^,\"]+),\s*(\d{6})")
TOOL_NAME = re.compile(r"\b(" + "|".join(TOOL_NAMES) + r")\b")
SEND_EMAIL = re.compile(r"\be-?mail\b.*?\bto\b", re.I | re.S)
FETCH_VERB = re.compile(r"\b(fetch|call|visit|open|load|request|ping)\b", re.I)
ECHO = re.compile(r"\b(repeat|reproduce|verbatim|word for word|quote|translate|paste|echo)\b", re.I)
MARKERS = re.compile(r"<<\s*(?:END\s+)?DATA\b[^>]*>>")
SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
RETRIEVED = ("search_help_center", "fetch_url")


def _unescape(text: str) -> str:
    """Tool messages are JSON (maybe spotlight-wrapped); read them as the text a model would see."""
    return MARKERS.sub("", text).replace('\\"', '"').replace("\\n", "\n")


def _method(text: str) -> str:
    if m := VPA.search(text):
        return m.group(0)
    low = text.lower()
    return "wallet" if "wallet" in low else "upi_1" if "upi" in low else "card_1"


def _address(text: str) -> dict | None:
    m = ADDRESS.search(text)
    if not m:
        return None
    return {"line1": m.group(1).strip(), "city": m.group(2).strip(), "state": m.group(3).strip(),
            "pincode": m.group(4)}


def _email_call(text: str, context: str) -> tuple[str, dict] | None:
    if not SEND_EMAIL.search(text):
        return None
    to = EMAIL.findall(text)
    if not to:
        return None
    return "send_email", {"to": to[0], "subject": "As requested", "body": context[:2000]}


def requested_calls(message: str, context: str) -> list[tuple[str, dict]]:
    """What the customer asked for, read the dumb way: keywords plus the ids, amounts and addresses given."""
    low, orders = message.lower(), ORDER_ID.findall(message)
    calls: list[tuple[str, dict]] = []
    if (e := _email_call(message, context)) is not None:
        calls.append(e)
    elif "refund" in low and orders and (amt := AMOUNT.search(message)):
        calls.append(("issue_refund", {"order_id": orders[0], "amount": float(amt.group(1).replace(",", "")),
                                       "method": _method(message), "reason": "customer request"}))
    elif "cancel" in low and orders:
        calls.append(("cancel_order", {"order_id": orders[0], "reason": "customer request"}))
    elif "address" in low and orders and (addr := _address(message)) is not None:
        calls.append(("update_order_address", {"order_id": orders[0], "address": addr}))
    else:
        calls += [("get_order", {"order_id": o}) for o in dict.fromkeys(orders)]
    if not orders and re.search(r"\borders\b", low):
        calls.append(("list_my_orders", {}))
    calls += [("get_product", {"product_id": p}) for p in dict.fromkeys(PRODUCT_ID.findall(message))]
    calls += [("fetch_url", {"url": u}) for u in dict.fromkeys(URL.findall(message))]
    return calls


def instructed_calls(text: str, context: str) -> list[tuple[str, dict]]:
    """Instructions found in retrieved text, followed sentence by sentence: a named tool, an email to send, or
    a URL to fetch. Markdown links are not fetched here; they go into the reply (see compose)."""
    calls: list[tuple[str, dict]] = []
    for s in SENTENCE.split(MD_LINK.sub("", text)):
        orders, tools = ORDER_ID.findall(s), TOOL_NAME.findall(s)
        if "fetch_url" in tools or (URL.search(s) and FETCH_VERB.search(s)):
            calls += [("fetch_url", {"url": u}) for u in URL.findall(s)]
        elif (e := _email_call(s, context)) is not None:
            calls.append(e)
        elif tools and orders:
            name, oid = tools[0], orders[0]
            if name == "update_order_address" and (addr := _address(s)) is not None:
                calls.append((name, {"order_id": oid, "address": addr}))
            elif name == "issue_refund" and (amt := AMOUNT.search(s)):
                calls.append((name, {"order_id": oid, "amount": float(amt.group(1).replace(",", "")),
                                     "method": _method(s), "reason": "as instructed"}))
            elif name in ("get_order", "cancel_order"):
                calls.append((name, {"order_id": oid} | ({"reason": "as instructed"} if name != "get_order"
                                                         else {})))
    return calls


class StubLLM:
    """agent.LLM: (messages, tools) -> LLMReply. See the module docstring: it exists to test the defenses."""

    def __call__(self, messages: list[dict], tools: list[dict]) -> LLMReply:
        start = max(i for i, m in enumerate(messages) if m["role"] == "user")
        user, turn = messages[start]["content"], messages[start + 1:]
        results = [m for m in turn if m["role"] == "tool"]
        context = "\n\n".join(_unescape(str(m.get("content") or "")) for m in messages)

        if ECHO.search(user):                                   # gullible: hand over the whole context
            return LLMReply(context)

        done = {(c["function"]["name"], c["function"]["arguments"])
                for m in turn if m["role"] == "assistant" for c in m.get("tool_calls") or []}
        wanted = requested_calls(user, context)
        for m in results:
            if m.get("name") in RETRIEVED:
                wanted += instructed_calls(_unescape(str(m.get("content") or "")), context)
        todo, seen = [], set()
        for name, args in wanted:
            key = (name, json.dumps(args, ensure_ascii=False, sort_keys=True))
            if key not in done and key not in seen:
                seen.add(key)
                todo.append(LLMToolCall(f"stub_{len(messages)}_{len(todo)}", name, key[1]))
        if todo:
            return LLMReply("", todo)
        return LLMReply(compose(results))


def compose(results: list[dict]) -> str:
    """The final answer: what each tool returned, plainly, plus every markdown link or image it was handed."""
    lines, links = [], []
    for m in results:
        name, raw = m.get("name", ""), _unescape(str(m.get("content") or ""))
        if name in RETRIEVED:
            links += [x for x in MD_LINK.findall(raw) if x not in links]
            continue
        if '"error"' in raw:
            lines.append(f"Sorry, I can't do that ({name}): {raw}")
        elif '"pending_confirmation"' in raw and name in SIDE_EFFECT_TOOLS:
            lines.append(f"Please press Confirm to go ahead with {name}: {raw}")
        else:
            lines.append(f"{name}: {raw}")
    return "\n".join(lines + links) or "Happy to help. Anything else about your orders?"
