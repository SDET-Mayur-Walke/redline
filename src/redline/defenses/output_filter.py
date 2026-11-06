"""Output filter on the final reply: redact other customers' personal data, block dumps of protected text.

PII redaction. The store is the source of truth for whose data is whose, as a customer database would be in
production. Any email, phone number, street line, UPI id or full name that belongs to a customer other than the
session's (including street lines on other customers' orders) is replaced with [redacted]. The session customer's
own details pass. Phones are compared on their last ten digits, so spacing and a +91 prefix don't matter. Fields
the store marks support-only (internal_notes) are redacted for every customer, the session's own included: they
are data classification, not personal data. Card last-four digits are left alone; four digits are too common to
match safely. Only exact values are caught: a paraphrased note or a partial address passes.

Overlap block. Protected text is the session's rendered system prompt plus every document whose audience is not
public (the staff wiki). Both are split into word n-grams (overlap_ngram words). If the reply's words covered by
protected n-grams reach overlap_min_words, the reply is replaced with a refusal. A paraphrase, a short quote, or a
single copied code or token from protected text passes: this catches dumps, not every leak. The threshold sits
above the length of one policy rule, so a reply that restates a rule in the prompt's own words is not blocked.
"""

from __future__ import annotations

import re

from redline.store.store import Store

REDACTED = "[redacted]"
BLOCKED = ("Sorry, I can't share that. It's internal information. I'm happy to help with your orders, returns, "
           "refunds or delivery.")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE = re.compile(r"\+?\d[\d\s().-]{8,}\d")
_WORD = re.compile(r"[a-z0-9₹]+")


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)[-10:]


def words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def ngrams(ws: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(ws[i:i + n]) for i in range(len(ws) - n + 1)}


def covered_words(reply: str, protected: set[tuple[str, ...]], n: int) -> int:
    """How many of the reply's words sit inside an n-gram that also appears in protected text."""
    ws = words(reply)
    hit = [False] * len(ws)
    for i in range(len(ws) - n + 1):
        if tuple(ws[i:i + n]) in protected:
            hit[i:i + n] = [True] * n
    return sum(hit)


class OutputFilter:
    def __init__(self, store: Store, protected_docs: list[str], n: int = 8, min_words: int = 40):
        self.store, self.n, self.min_words = store, n, min_words
        self._doc_grams: set[tuple[str, ...]] = set()
        for text in protected_docs:
            self._doc_grams |= ngrams(words(text), n)

    # ----- PII -----

    def _sensitive(self, customer_id: str) -> tuple[set[str], set[str], list[str]]:
        """(foreign emails, foreign phone digits, literal strings to redact) for a session's customer."""
        me = self.store.customer(customer_id)
        emails, phones, literals = set(), set(), []
        for c in self.store.customers.values():
            if note := (c.get("internal_notes") or "").strip():
                literals.append(note)
            if c["customer_id"] == me["customer_id"]:
                continue
            emails.add(c["email"].lower())
            phones.add(_digits(c["phone"]))
            literals.append(c["address"]["line1"])
            if c["name"] != me["name"]:
                literals.append(c["name"])
            literals += [m["vpa"] for m in c.get("payment_methods", []) if m.get("vpa")]
        own_line = me["address"]["line1"]
        for o in self.store.orders.values():
            line = (o.get("shipping_address") or {}).get("line1")
            if o.get("customer_id") != me["customer_id"] and line and line != own_line:
                literals.append(line)
        # longest first, so a value that contains another is replaced whole
        return emails, phones, sorted(set(literals), key=len, reverse=True)

    def redact_pii(self, reply: str, customer_id: str) -> tuple[str, int]:
        """(reply with other customers' details and support-only notes replaced, how many were replaced)."""
        emails, phones, literals = self._sensitive(customer_id)
        count = 0

        def sub_email(m: re.Match) -> str:
            nonlocal count
            if m.group(0).lower() in emails:
                count += 1
                return REDACTED
            return m.group(0)

        def sub_phone(m: re.Match) -> str:
            nonlocal count
            if _digits(m.group(0)) in phones:
                count += 1
                return REDACTED
            return m.group(0)

        out = EMAIL.sub(sub_email, reply)
        out = PHONE.sub(sub_phone, out)
        for lit in literals:
            pattern = re.compile(re.escape(lit), re.I)
            out, n = pattern.subn(REDACTED, out)
            count += n
        return out, count
