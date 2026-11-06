"""Every defense must be generic: it may not know the test.

A defense that only works because it recognises our canary format, the exfil sink's port, an attack id or a
phrase from an attack YAML would score well and protect nothing. This test reads src/redline/defenses/ as
plain text and fails on any of those. Reviewers: this is the check to look at.
"""

import re

import yaml

from redline.attacks.schema import LIBRARY, load_library
from redline.config import ROOT

DEFENSES = ROOT / "src" / "redline" / "defenses"
FORBIDDEN = ["RL-CANARY", "CANARY", "8765", "SYS-", "nip.io"]
SHINGLE = 5          # any run of this many words copied from an attack's text fails the test


def _source() -> str:
    files = sorted(DEFENSES.rglob("*.py"))
    assert files, "no defense modules found"
    return "\n".join(p.read_text(encoding="utf-8") for p in files)


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _attack_texts() -> list[str]:
    """Every human-written string in the attack YAMLs: inputs, followups, planted docs, reviews, payloads."""
    out: list[str] = []

    def walk(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for k, x in v.items():
                if k not in ("notes", "title", "id", "module", "severity", "owasp_llm", "owasp_asi", "check"):
                    walk(x)

    for path in sorted(LIBRARY.glob("*.yaml")):
        walk(yaml.safe_load(path.read_text(encoding="utf-8")))
    return out


def test_no_test_specific_tokens():
    src = _source()
    found = [t for t in FORBIDDEN if t.lower() in src.lower()]
    assert not found, f"defenses mention test-specific tokens: {found}"


def test_no_attack_ids():
    src = _source()
    found = [a.id for a in load_library() if a.id in src]
    assert not found, f"defenses mention attack ids: {found}"


def test_no_order_or_customer_ids_from_the_attacks():
    """Order and customer ids an attack targets (SC0100074, C0016, ...) must not appear in a defense."""
    src = _source()
    ids = set()
    for t in _attack_texts():
        ids |= set(re.findall(r"\b(?:SC\d{7}|C\d{4}|P\d{3}|RINJ-\d+)\b", t))
    found = sorted(i for i in ids if i in src)
    assert not found, f"defenses mention ids from the attack library: {found}"


def copied_phrases(source: str) -> set[str]:
    src_words = f" {' '.join(_words(source))} "
    copied = set()
    for text in _attack_texts():
        w = _words(text)
        for i in range(len(w) - SHINGLE + 1):
            phrase = " ".join(w[i:i + SHINGLE])
            if f" {phrase} " in src_words:
                copied.add(phrase)
    return copied


def test_no_phrases_copied_from_attack_yamls():
    copied = copied_phrases(_source())
    assert not copied, f"defenses contain phrases from attack YAMLs: {sorted(copied)[:10]}"


def test_the_check_itself_works():
    """Guard against a vacuous test: a phrase lifted from an attack, pasted into "source", is caught."""
    text = next(t for t in _attack_texts() if len(_words(t)) >= 2 * SHINGLE)
    planted = "x = re.compile(r'" + " ".join(_words(text)[2:2 + SHINGLE]) + "')"
    assert copied_phrases(planted)
    assert not copied_phrases("def normalize(text): return text")
