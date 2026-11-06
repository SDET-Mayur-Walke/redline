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
