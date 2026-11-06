"""Guard against real brands creeping into the synthetic data.

Everything an attack might surface (store records, help docs, reviews) has to be
fictional, so a leaked "customer record" can never point at a real company.
"""

import re

from redline.kb.corpus import KB
from redline.store.store import DATA

BRAND_TOKENS = ["Galaxy", "iPhone", "BlueDart", "BLUDART", "Paytm", "oksbi", "okaxis", "okhdfcbank", "okicici", "ybl"]
# letter boundaries, not \b: tracking ids glue digits straight onto the prefix (BLUDART123...)
PATTERN = re.compile(r"(?<![a-z])(" + "|".join(BRAND_TOKENS) + r")(?![a-z])", re.IGNORECASE)


def _files():
    yield DATA
    yield KB / "reviews.jsonl"
    yield from sorted(KB.rglob("*.md"))


def test_no_real_brand_tokens_in_data():
    hits = [(f.name, m.group(0)) for f in _files() for m in PATTERN.finditer(f.read_text(encoding="utf-8"))]
    assert not hits, hits[:10]


def test_pattern_catches_the_old_values():
    # the old generator output, so the guard is known to bite
    for sample in ["rahul.sharma@oksbi", "BLUDART123456789", "Galaxy S25", "x@ybl", "pay via Paytm"]:
        assert PATTERN.search(sample), sample
