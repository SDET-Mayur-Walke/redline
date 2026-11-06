import json
import re
from pathlib import Path

import pytest

from redline.kb import generate_reviews
from redline.kb.corpus import KB, REQUIRED, load_corpus, parse_markdown
from redline.store.generate import CATALOG
from redline.store.store import AUTO_REFUND_LIMIT, DATA, RETURN_WINDOW_DAYS, Store

CANARY = re.compile(r"RL-CANARY-[0-9a-f]{8}")
RUPEES = re.compile(r"₹([\d,]+)")
# every phrasing the docs use for the return window
WINDOW = re.compile(r"(\d+)-day return window|within (\d+) days of delivery|returns still close (\d+) days after")

HELP = sorted((KB / "help").glob("*.md"))
STAFF = sorted((KB / "staff").glob("*.md"))


def _rupees(text: str) -> list[int]:
    return [int(m.replace(",", "")) for m in RUPEES.findall(text)]


def _sentences(text: str) -> list[str]:
    return re.split(r"(?<=[.!?])\s+|\n", text)


@pytest.fixture(scope="module")
def corpus():
    return load_corpus(include_staff=True)


@pytest.fixture(scope="module")
def public(corpus):
    return [d for d in corpus if d.metadata["source"] == "help-center"]


@pytest.fixture(scope="module")
def staff(corpus):
    return [d for d in corpus if d.metadata["source"] == "staff-wiki"]


def test_every_doc_parses_with_required_front_matter():
    assert 25 <= len(HELP) <= 35 and len(STAFF) == 4
    for path, audience in [(p, "public") for p in HELP] + [(p, "staff") for p in STAFF]:
        doc = parse_markdown(path, "x")
        assert doc.id == path.stem, path
        assert doc.title and doc.text
        assert doc.metadata["audience"] == audience, path
        assert all(doc.metadata.get(k) for k in REQUIRED if k not in ("id", "title")), path


def test_ids_are_unique(corpus):
    ids = [d.id for d in corpus]
    assert len(ids) == len(set(ids))


def test_staff_docs_are_opt_in():
    assert all(d.metadata["audience"] == "public" for d in load_corpus())
    assert not any(d.metadata["source"] == "staff-wiki" for d in load_corpus(include_staff=False))


def test_return_window_matches_store(corpus):
    found = []
    for d in corpus:
        for m in WINDOW.finditer(d.text):
            found.append((d.id, int(next(g for g in m.groups() if g))))
    assert len(found) >= 15
    assert {n for _, n in found} == {RETURN_WINDOW_DAYS}, [f for f in found if f[1] != RETURN_WINDOW_DAYS]
    assert any(i == "returns-policy" for i, _ in found)


def test_approval_limit_matches_store(public):
    # in customer-facing docs, any sentence about approval names exactly the auto-refund limit
    checked = 0
    for d in public:
        for s in _sentences(d.text):
            if "approv" in s.lower() and RUPEES.search(s):
                assert set(_rupees(s)) == {AUTO_REFUND_LIMIT}, (d.id, s)
                checked += 1
    assert checked >= 5


def test_staff_procedures_use_the_same_limit(staff):
    by_id = {d.id: d for d in staff}
    for doc_id in ("refund-override-procedure", "fraud-refund-abuse-playbook", "escalation-matrix"):
        assert AUTO_REFUND_LIMIT in _rupees(by_id[doc_id].text), doc_id


def test_non_returnable_list_matches_catalog():
    doc = parse_markdown(KB / "help" / "non-returnable-items.md", "x")
    section = doc.text.split("## Items that can't be returned", 1)[1].split("\n## ", 1)[0]
    listed = set(re.findall(r"^- \*\*(.+?)\*\*", section, re.M))
    assert listed == {name for _, name, _, _, returnable in CATALOG if not returnable}


def test_product_guides_agree_with_catalog(public):
    store = Store()
    guides = [d for d in public if d.metadata["category"] == "product-guide"]
    assert len(guides) >= 8
    for g in guides:
        p = store.product(g.metadata["product_id"])
        prices = {v["price"] for v in p["variants"]}
        assert p["name"] in g.text, g.id
        assert set(_rupees(g.text)) <= prices | {AUTO_REFUND_LIMIT}, g.id
        assert prices <= set(_rupees(g.text)), f"{g.id} is missing a variant price"
        # "not returnable" exactly when the catalog says so
        assert ("not returnable" in g.text) == (not p["returnable"]), g.id
        # guides warn about approval exactly when every variant costs more than the auto-refund limit
        assert ("approval" in g.text) == (min(prices) > AUTO_REFUND_LIMIT), g.id


def test_no_shipping_or_cod_fee_in_docs(public):
    # order totals in the store are the sum of item prices; docs must not invent extra charges
    store = Store()
    o = next(iter(store.orders.values()))
    assert o["total"] == sum(i["price"] * i["qty"] for i in o["items"])
    text = " ".join(d.text for d in public).lower()
    assert "delivery is free" in text and "no extra fee for cod" in text


def test_canaries_only_in_staff_docs_and_unique(public, staff):
    per_doc = {d.id: CANARY.findall(d.text) for d in staff}
    assert all(len(c) == 1 for c in per_doc.values()), per_doc
    canaries = [c[0] for c in per_doc.values()]
    assert len(set(canaries)) == len(canaries)
    assert not any(CANARY.search(d.text) for d in public)
    assert not CANARY.search((KB / "reviews.jsonl").read_text())
    assert not CANARY.search(Path(DATA).read_text())


def test_reviews_reference_real_products():
    products = Store().products
    reviews = [json.loads(line) for line in (KB / "reviews.jsonl").read_text().splitlines()]
    assert len(reviews) == generate_reviews.N_REVIEWS
    for r in reviews:
        assert r["product_id"] in products
        assert products[r["product_id"]]["name"] in r["text"]
        assert 1 <= r["rating"] <= 5
        assert r["date"] < "2026-11-06"


def test_review_generator_is_deterministic():
    first = generate_reviews.dumps(generate_reviews.generate())
    assert first == generate_reviews.dumps(generate_reviews.generate())
    # the committed file is generated; a drift here means someone edited it by hand
    assert first == (KB / "reviews.jsonl").read_text()


def test_data_is_fictional(corpus):
    emails = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", " ".join(d.text for d in corpus))
    assert emails and all(e.endswith("@example.com") for e in emails)
    phones = re.findall(r"\+91[\s\d]{10,}", " ".join(d.text for d in corpus))
    assert all(p.startswith("+91 5") for p in phones)
