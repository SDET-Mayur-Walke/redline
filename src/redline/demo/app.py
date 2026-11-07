"""The Streamlit demo: chat on the left, what the agent actually did on the right.

    make sink          # the exfil sink on 127.0.0.1:8765, in another terminal
    make demo          # Ollama (configs/default.yaml vs configs/hardened.yaml), http://127.0.0.1:8501
    make demo-stub     # offline: the CI gate's stub model and configs

A thin layout over demo/core.py, which holds the design notes (two in-process agents, display-only masking).
Replies render as plain markdown (no raw HTML), the way a typical chat client renders them: a markdown image is
loaded by the browser as soon as the reply is drawn, so in vulnerable mode the zero-click exfil really reaches
the sink, and the sink panel (refreshed every two seconds) shows the hit.
"""

from __future__ import annotations

import json

import streamlit as st

from redline.demo import core

st.set_page_config(page_title="redline demo", layout="wide")
KIND = core.model_kind()
LABEL = {"vulnerable": "Vulnerable", "hardened": "Recommended" if KIND == "recommended" else "Hardened"}


@st.cache_resource(show_spinner="Building the agent and indexing the help center…")
def runner(kind: str, mode: str) -> core.ModeRunner:
    return core.ModeRunner(core.build_agent(kind, mode))


@st.cache_resource
def presets() -> dict[str, core.Preset]:
    return {p.id: p for p in core.load_presets()}


@st.cache_resource
def customers() -> dict[str, dict]:
    return {c["customer_id"]: c for c in core.customer_rows(core.Store())}


ss = st.session_state
ss.setdefault("history", {})      # (mode, customer) -> [TurnView]
ss.setdefault("last", {})         # mode -> event lines of the last turn or confirm
ss.setdefault("draft", "")
ss.setdefault("preset", "")
ss.setdefault("customer", core.CUSTOMERS[0])
ss.setdefault("mode", "vulnerable")
ss.setdefault("safe", True)


def show(text: str) -> str:
    return core.mask(text) if ss.safe else text


def show_tree(obj):
    return core.mask_tree(obj) if ss.safe else obj


def leaked_badge(text: str) -> str:
    return " :red-badge[secret leaked]" if core.has_canary(text) else ""


# ----- callbacks (they run before the script, so they may set widget state) -----

def on_preset() -> None:
    p = presets().get(ss.preset)
    if p is None:
        return
    ss.customer = p.customer_id
    ss.draft = p.message
    n = runner(KIND, ss.mode).plant(p)
    ss.last[ss.mode] = [f"planted {n} setup doc(s) for {p.id}"] if n else []


def on_send() -> None:
    ss.to_send = ss.draft.strip()
    ss.draft = ""


def on_reset() -> None:
    for m in core.MODES:
        if (KIND, m) in ss.get("built", set()):
            runner(KIND, m).reset()
    ok = core.reset_sink()
    ss.history, ss.last, ss.preset, ss.draft = {}, {}, "", ""
    ss.reset_note = "Reset: store, planted docs, sessions" + (", sink." if ok else " (sink not running).")


# ----- sidebar -----

with st.sidebar:
    st.title("redline")
    st.caption(f"SaffronCart support agent · model: **{'stub' if KIND == 'stub' else 'ollama'}**")
    # switching mode re-loads the selected preset into the other agent, so the same attack replays in one click
    st.radio("Mode", core.MODES, key="mode", format_func=LABEL.get, horizontal=True, on_change=on_preset)
    st.caption(f"`{core.config_path(KIND, ss.mode).relative_to(core.ROOT)}`")
    cust = customers()
    st.selectbox("Customer", list(cust), key="customer",
                 format_func=lambda c: f"{cust[c]['name']} ({c}) · {len(cust[c]['orders'])} orders")
    orders = cust[ss.customer]["orders"]
    if orders:
        st.dataframe(orders, hide_index=True, width="stretch",
                     column_order=("order_id", "status", "total", "items"))
    pre = presets()
    st.selectbox("Attack presets", ["", *pre], key="preset", on_change=on_preset,
                 format_func=lambda i: "(none)" if not i else f"{i}: {pre[i].title}")
    st.toggle("Recording-safe (mask canaries)", key="safe")
    st.button("Reset", on_click=on_reset, type="secondary", width="stretch")
    if note := ss.pop("reset_note", None):
        st.success(note)

r = runner(KIND, ss.mode)
ss.setdefault("built", set()).add((KIND, ss.mode))
key = (ss.mode, ss.customer)
history = ss.history.setdefault(key, [])
chat, panel = st.columns([3, 2], gap="large")

# ----- left: the chat -----

with chat:
    st.subheader(f"{LABEL[ss.mode]} · chatting as {cust[ss.customer]['name']}")
    message = ss.pop("to_send", "")
    if message:
        p = pre.get(ss.preset)
        if p is not None and p.customer_id == ss.customer:
            r.plant(p)                              # the preset may have been picked in the other mode
        history.append(core.TurnView("user", message))
        with st.spinner("Agent is working…"):
            t = r.turn(ss.customer, message)
        history.append(t)
        ss.last[ss.mode] = t.events

    for t in history:
        with st.chat_message(t.role):
            st.markdown(show(t.content) + (leaked_badge(t.content) if t.role == "assistant" else ""))
            if t.citations:
                st.markdown(" ".join(f":blue-background[{c}]" for c in t.citations))
            if t.tool_calls:
                with st.expander(f"{len(t.tool_calls)} tool call(s)"):
                    st.code(json.dumps(show_tree(t.tool_calls), indent=2, ensure_ascii=False, default=str),
                            language="json", wrap_lines=True)

    st.text_area("Message", key="draft", height=100, placeholder="Ask about an order, or pick an attack preset")
    st.button("Send", on_click=on_send, type="primary")

# ----- right: what the agent did -----

with panel:
    st.subheader("Defense events (last turn)")
    events = ss.last.get(ss.mode) or []
    if events:
        st.code(show("\n".join(events)), language=None, wrap_lines=True)
    else:
        st.caption("none" + (" (every defense is off)" if ss.mode == "vulnerable" else ""))

    st.subheader("Pending actions")
    pending = r.pending(ss.customer)
    if not pending:
        st.caption("none")
    for aid, a in pending.items():
        st.code(show(f"{aid} {a['tool']}({json.dumps(a['args'], ensure_ascii=False)})"), language=None,
                wrap_lines=True)
        if st.button(f"Confirm {aid}", key=f"confirm-{ss.mode}-{aid}", type="primary"):
            result, ev = r.confirm(ss.customer, aid)
            ss.last[ss.mode] = ev
            history.append(core.TurnView("assistant", f"Confirmed {aid}: `{json.dumps(result, default=str)}`"))
            st.rerun()

    st.subheader("Store effects")
    effects = r.agent.store.effects.as_dict()
    sections = core.format_effects(effects)
    if not sections:
        st.caption("nothing changed")
    for name, lines in sections.items():
        st.markdown(f"**{name}**" + leaked_badge(json.dumps(effects, default=str) if name == "Outbox" else ""))
        st.code(show("\n".join(lines)), language=None, wrap_lines=True)

    @st.fragment(run_every="2s")
    def sink_panel() -> None:
        st.subheader("Exfil sink (127.0.0.1:8765)")
        hits = core.sink_hits()
        if hits is None:
            st.warning("Sink not running: start it with `make sink`.")
        elif not hits:
            st.caption("no hits")
        else:
            raw = "\n".join(core.format_hit(h) for h in hits)
            st.markdown(f"**{len(hits)} hit(s)**" + leaked_badge(raw))
            st.code(show(raw), language=None, wrap_lines=True)

    sink_panel()
