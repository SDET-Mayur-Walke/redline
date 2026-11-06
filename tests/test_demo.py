"""The demo's helpers and its controller over the stub agent, offline. The Streamlit smoke test needs the `ui`
extra and is skipped without it (CI installs only `dev`)."""

from pathlib import Path

import pytest

from redline.attacks.schema import load_library
from redline.demo import core
from redline.sink import Sink, SinkServer

SYS, STAFF = "RL-CANARY-SYS-5d31480a", "RL-CANARY-107d7c72"
APP = Path(core.__file__).with_name("app.py")


# ----- masking: display-only -----

def test_mask_hides_every_canary_kind_and_nothing_else():
    text = f"tag {SYS}, ref {STAFF}, order SC0100074"
    assert core.mask(text) == "tag RL-CANARY-****, ref RL-CANARY-****, order SC0100074"
    assert core.has_canary(text) and not core.has_canary(core.mask(text))


def test_mask_tree_masks_nested_strings_and_returns_a_copy():
    calls = [{"name": "fetch_url", "args": {"url": f"http://127.0.0.1:8765/x?c={SYS}"}, "result": {"status": 200}}]
    masked = core.mask_tree(calls)
    assert masked[0]["args"]["url"].endswith("c=RL-CANARY-****") and masked[0]["result"] == {"status": 200}
    assert calls[0]["args"]["url"].endswith(SYS)          # the original is untouched


# ----- formatting -----

def test_tool_block_reads_as_layer_verb_tool_reason():
    e = {"layer": "tool_authz", "action": "block", "detail": "get_order: order SC0100074 is not on this customer's"
                                                            " account"}
    assert core.format_event(e) == "tool_authz blocked get_order (order SC0100074 is not on this customer's account)"
    e2 = {"layer": "refund_rules", "action": "block", "detail": "issue_refund at confirm: amount must be positive"}
    assert core.format_event(e2) == "refund_rules blocked issue_refund at confirm (amount must be positive)"


def test_other_events_keep_their_detail():
    assert core.format_event({"layer": "egress", "action": "strip", "detail": "1 link(s)/image(s): http://x"}) == \
        "egress stripped 1 link(s)/image(s): http://x"


def test_quarantine_summary_counts_chunks():
    lines = core.format_quarantine([{"chunk_id": "live-tracking-widget#0", "origin": "planted", "reasons": ["a"]}])
    assert lines[0] == "ingestion_scanner quarantined 1 planted chunk" and "live-tracking-widget#0: a" in lines[1]
    assert core.format_quarantine([]) == []


def test_effects_formatting_totals_refunds_in_rupees():
    fx = {"refunds": [{"order_id": "SC1", "amount": 5347.0, "to": "wallet", "reason": "r"},
                      {"order_id": "SC2", "amount": 99.5, "to": "upi_1", "reason": "r"}], "refund_total": 5446.5,
          "address_changes": [{"order_id": "SC3", "from": {"line1": "1 A", "city": "B", "state": "C", "pincode": "1"},
                               "to": {"line1": "9 T", "city": "M", "state": "MH", "pincode": "400001"}}],
          "emails": [{"to": "x@example.com", "subject": "s", "body": "abc"}], "tickets": [], "cancellations": []}
    out = core.format_effects(fx)
    assert out["Refunds"] == ["₹5,347 to wallet on SC1 (r)", "₹99.50 to upi_1 on SC2 (r)",
                              "Total refunded: ₹5,446.50"]
    assert out["Address changes"] == ["SC3: 1 A, B, C 1 → 9 T, M, MH 400001"]
    assert out["Outbox"] == ["to x@example.com: s (3 chars)"] and "Tickets" not in out
    assert core.format_effects(core.Store().effects.as_dict()) == {}


# ----- presets -----

def test_presets_are_library_attacks_verbatim():
    lib = {a.id: a for a in load_library()}
    ps = core.load_presets()
    assert [p.id for p in ps] == list(core.PRESET_IDS)
    for p in ps:
        assert p.message == lib[p.id].rendered_input() and p.customer_id == lib[p.id].customer_id
    by = {p.id: p for p in ps}
    assert by["exf-markdown-image-pixel"].n_docs == 1 and by["ii-split-across-chunks"].n_docs == 2
    with pytest.raises(ValueError):
        core.load_presets(("no-such-attack",))


def test_customer_rows_list_orders():
    rows = {r["customer_id"]: r for r in core.customer_rows(core.Store())}
    assert "SC0100074" in [o["order_id"] for o in rows["C0016"]["orders"]]


# ----- the controller over the stub agent (the CI gate's configs) -----

@pytest.fixture(scope="module")
def runners():
    return {m: core.ModeRunner(core.build_agent("stub", m)) for m in core.MODES}


@pytest.fixture(autouse=True)
def _fresh(runners):
    for r in runners.values():
        r.reset()


def _preset(pid):
    return {p.id: p for p in core.load_presets()}[pid]


def test_foreign_address_changes_in_vulnerable_and_is_blocked_in_hardened(runners):
    p = _preset("ea-change-foreign-address")
    v = runners["vulnerable"].turn(p.customer_id, p.message)
    assert runners["vulnerable"].agent.store.effects.address_changes[0]["order_id"] == "SC0100074"
    assert v.events == []
    h = runners["hardened"].turn(p.customer_id, p.message)
    assert runners["hardened"].agent.store.effects.address_changes == []
    assert any(e.startswith("tool_authz blocked update_order_address") for e in h.events)


def test_planted_image_reaches_the_reply_only_in_vulnerable(runners):
    p = _preset("exf-markdown-image-pixel")
    for r in runners.values():
        assert r.plant(p) == 1 and r.plant(p) == 0           # idempotent until reset
    v = runners["vulnerable"].turn(p.customer_id, p.message)
    assert "](http://127.0.0.1:8765/track.png" in v.content
    h = runners["hardened"].turn(p.customer_id, p.message)
    assert "127.0.0.1:8765" not in h.content
    assert h.events[0] == "ingestion_scanner quarantined 1 planted chunk"


def test_masking_never_reaches_the_agent(runners):
    p = _preset("rec-sysprompt-direct")
    r = runners["vulnerable"]
    t = r.turn(p.customer_id, p.message)
    assert core.has_canary(t.content) and not core.has_canary(core.mask(t.content))
    conv = r.agent.conversations[r.session_id(p.customer_id)]
    assert core.has_canary(conv.transcript(r.agent.store).final_output)     # graders see the raw reply


def test_pending_action_runs_on_confirm(runners):
    r = runners["hardened"]
    r.turn("C0011", "Change the delivery address on order SC0115059 to 4 Lake View, Pune, Maharashtra, 411001")
    pending = r.pending("C0011")
    assert [a["tool"] for a in pending.values()] == ["update_order_address"]
    assert r.agent.store.effects.address_changes == []
    _, events = r.confirm("C0011", next(iter(pending)))
    assert r.agent.store.effects.address_changes[0]["order_id"] == "SC0115059"
    assert events == ["confirmation noted A001 update_order_address confirmed by the customer"]


def test_reset_starts_a_new_session_and_clears_the_world(runners):
    r = runners["vulnerable"]
    p = _preset("ea-change-foreign-address")
    r.plant(_preset("ii-split-across-chunks"))
    r.turn(p.customer_id, p.message)
    sid = r.session_id(p.customer_id)
    r.reset()
    assert r.session_id(p.customer_id) != sid and r.planted == set() and r.session(p.customer_id) is None
    assert core.format_effects(r.agent.store.effects.as_dict()) == {}


# ----- the sink client -----

def test_sink_client_reads_and_resets_hits():
    with SinkServer(Sink(log_path=None), port=0) as srv:
        srv.sink.record("GET", "/track.png", "order=SC1", {}, "")
        hits = core.sink_hits(srv.url)
        assert [core.format_hit(h).split("  ", 1)[1] for h in hits] == ["GET /track.png?order=SC1"]
        assert core.reset_sink(srv.url) and core.sink_hits(srv.url) == []


def test_sink_client_reports_a_stopped_sink():
    assert core.sink_hits("http://127.0.0.1:9", timeout=0.2) is None
    assert core.reset_sink("http://127.0.0.1:9", timeout=0.2) is False


# ----- the Streamlit app itself -----

def test_app_smoke_with_the_stub(monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("REDLINE_DEMO_MODEL", "stub")
    monkeypatch.setenv("REDLINE_SINK_URL", "http://127.0.0.1:9")       # never touch a real sink
    at = testing.AppTest.from_file(str(APP), default_timeout=60).run()
    assert not at.exception
    at.selectbox(key="preset").set_value("ea-change-foreign-address").run()
    assert at.text_area(key="draft").value == _preset("ea-change-foreign-address").message
    next(b for b in at.button if b.label == "Send").click().run()
    assert not at.exception
    codes = [c.value for c in at.code]
    assert any("SC0100074:" in c and "9 Transit Road" in c for c in codes)            # store effects panel
    assert any("Sink not running" in w.value for w in at.warning)
