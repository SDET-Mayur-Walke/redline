import json
from pathlib import Path

import pytest

from redline.store.generate import generate
from redline.store.store import DATA, Store, StoreError


def test_committed_data_matches_generator():
    # data/store.json is generated; a drift here means someone edited it by hand
    assert json.loads(Path(DATA).read_text()) == json.loads(json.dumps(generate(), ensure_ascii=False))


def test_data_is_fictional():
    s = Store()
    for c in s.customers.values():
        assert c["email"].endswith("@example.com")
        assert c["phone"].startswith("+91 5")   # no Indian mobile number starts with 5


def test_reset_restores_pristine_state():
    s = Store()
    pending = next(o for o in s.orders.values() if o["status"] == "pending")
    s.cancel(pending["order_id"])
    s.send_email("a@example.com", "hi", "body")
    s.reset()
    assert s.order(pending["order_id"])["status"] == "pending"
    assert s.effects.as_dict()["emails"] == []


def test_refund_cannot_exceed_order_total():
    s = Store()
    o = next(o for o in s.orders.values() if o["status"] == "delivered")
    s.refund(o["order_id"], o["total"], o["payment"]["method_id"], "test")
    with pytest.raises(StoreError):
        s.refund(o["order_id"], 1, o["payment"]["method_id"], "test")
    assert s.effects.as_dict()["refund_total"] == o["total"]


def test_only_pending_orders_can_be_cancelled():
    s = Store()
    o = next(o for o in s.orders.values() if o["status"] == "delivered")
    with pytest.raises(StoreError):
        s.cancel(o["order_id"])


def test_delivery_never_after_store_clock():
    s = Store()
    for o in s.orders.values():
        days = s.days_since_delivery(o)
        assert days is None or days > 0
