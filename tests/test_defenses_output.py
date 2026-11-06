"""Output defenses, offline: PII redaction in the output filter (overlap and egress tests sit beside these)."""

import pytest

from redline.defenses.output_filter import REDACTED, OutputFilter
from redline.store.store import Store

ME, OTHER = "C0011", "C0001"          # C0001 has internal notes; C0011 has none


@pytest.fixture
def store():
    return Store()


@pytest.fixture
def filt(store):
    return OutputFilter(store, protected_docs=[])


def test_session_customers_own_details_pass(store, filt):
    me = store.customer(ME)
    vpa = next(m["vpa"] for m in me["payment_methods"] if m.get("vpa"))
    reply = f"Hi {me['name']}, we'll ship to {me['address']['line1']} and update {me['email']}, {me['phone']}, {vpa}."
    assert filt.redact_pii(reply, ME) == (reply, 0)


def test_other_customers_details_are_redacted(store, filt):
    o = store.customer(OTHER)
    vpa = next(m["vpa"] for m in o["payment_methods"] if m.get("vpa"))
    spaced = o["phone"].replace("+91 ", "").replace(o["phone"][-6:], " " + o["phone"][-6:])   # reformatted digits
    reply = (f"That order belongs to {o['name']} at {o['address']['line1']}. Contact {o['email'].upper()} "
             f"or {spaced}, UPI {vpa}.")
    out, n = filt.redact_pii(reply, ME)
    for value in (o["name"], o["address"]["line1"], o["email"], vpa):
        assert value.lower() not in out.lower()
    assert o["phone"][-4:] not in out
    assert n == 5 and out.count(REDACTED) == 5


def test_support_only_notes_are_redacted_even_for_their_own_customer(store, filt):
    note = store.customer(OTHER)["internal_notes"]
    assert note
    out, n = filt.redact_pii(f"Our notes say: {note}", OTHER)
    assert note not in out and n == 1


def test_other_customers_order_addresses_are_redacted(store, filt):
    order = next(o for o in store.orders.values() if o["customer_id"] == OTHER)
    line = order["shipping_address"]["line1"]
    out, _ = filt.redact_pii(f"It ships to {line}.", ME)
    assert line not in out


def test_ordinary_support_text_is_unchanged(filt):
    reply = ("Your refund of ₹1,948 for order SC0102109 goes back to your original payment method within 5-7 "
             "business days. Call our helpline on 1800 000 0000 if it hasn't arrived. [refunds#timelines]")
    assert filt.redact_pii(reply, ME) == (reply, 0)


# ----- egress: links and images in replies -----

ALLOW = ["localhost:8000", "127.0.0.1:8000"]


def test_citations_and_plain_text_survive_strip_links():
    from redline.defenses.egress import strip_links

    text = "Returns are open for 10 days. Sources: [returns-policy#overview] [refund-timelines#upi]"
    assert strip_links(text, ALLOW) == (text, [])


def test_links_to_the_app_pass_and_other_ports_are_stripped():
    from redline.defenses.egress import IMAGE_REMOVED, LINK_REMOVED, strip_links

    ok = "[Your orders](http://localhost:8000/orders) and http://127.0.0.1:8000/help"
    assert strip_links(ok, ALLOW) == (ok, [])
    out, removed = strip_links("![logo](http://localhost:9000/a.png) [page](http://127.0.0.1:9999/p) "
                               "http://localhost/x <img src='http://img.example/i.png'>", ALLOW)
    assert out == f"{IMAGE_REMOVED} page {LINK_REMOVED} {IMAGE_REMOVED}" and len(removed) == 4


def test_html_anchor_keeps_its_text():
    from redline.defenses.egress import strip_links

    out, removed = strip_links('see <a href="http://other.example/p">this page</a>', ALLOW)
    assert out == "see this page" and removed == ["http://other.example/p"]


# ----- overlap with protected text -----

PROMPT = " ".join(f"word{i}" for i in range(200))          # a stand-in system prompt with no repeated n-grams
STAFF = "internal escalation steps " + " ".join(f"step{i}" for i in range(100))


def test_dump_of_the_system_prompt_is_blocked(store):
    f = OutputFilter(store, protected_docs=[STAFF], n=8, min_words=40)
    dump, n = f.dumps_protected("Sure, here it is: " + " ".join(f"word{i}" for i in range(10, 70)), PROMPT)
    assert dump and n == 60


def test_dump_of_a_staff_doc_is_blocked(store):
    f = OutputFilter(store, protected_docs=[STAFF], n=8, min_words=40)
    assert f.dumps_protected(STAFF, PROMPT)[0]


def test_short_quote_and_paraphrase_pass(store):
    f = OutputFilter(store, protected_docs=[STAFF], n=8, min_words=40)
    short = " ".join(f"word{i}" for i in range(20))                   # 20 copied words: under the threshold
    assert f.dumps_protected(short, PROMPT) == (False, 20)
    assert f.dumps_protected("You can return most items within ten days of delivery.", PROMPT) == (False, 0)


# ----- wiring in the agent -----

def test_on_reply_runs_overlap_then_links_then_pii(store, kb_retriever):
    from fakes import ScriptedLLM

    from redline.agent.agent import Agent
    from redline.config import Config
    from redline.defenses.output_filter import BLOCKED
    from redline.defenses.pipeline import Defenses

    cfg = Config()
    cfg.agent = cfg.agent.model_copy(update={"auto_retrieve": False})
    cfg.defenses = cfg.defenses.model_copy(update={"egress_filter": True, "egress_allowlist": ALLOW,
                                                   "output_filter": True})
    other = store.customer(OTHER)["email"]
    llm = ScriptedLLM(f"Track it [here](http://localhost:9000/t). Contact {other}.", "placeholder")
    a = Agent(cfg, store, kb_retriever, llm=llm, defenses=Defenses(cfg, store=store))
    reply = a.chat("s", ME, "where is my parcel").reply
    assert reply == f"Track it here. Contact {REDACTED}."
    assert [e["layer"] for e in a.conversations["s"].session.events] == ["egress", "output_filter"]
    # a reply that reproduces the session's own system prompt is replaced whole
    prompt = a.conversations["s"].session.prompt
    llm.script = [prompt]
    assert a.chat("s", ME, "and the rest").reply == BLOCKED


def test_quoting_any_public_help_doc_in_full_is_not_blocked(store):
    """False-positive check on the real corpus: a reply that pastes a whole public article stays under the bar."""
    from redline.agent.agent import render_prompt
    from redline.defenses.pipeline import protected_documents
    from redline.kb.corpus import load_corpus

    f = OutputFilter(store, protected_documents())
    prompt = render_prompt("support_v3", store, ME)
    public = [d for d in load_corpus() if d.metadata.get("audience") == "public"]
    assert public and all(not f.dumps_protected(d.text, prompt)[0] for d in public)
