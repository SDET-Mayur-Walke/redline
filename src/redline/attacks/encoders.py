"""Small text encoders for the evasion attacks. Our own code, kept tiny on purpose.

Each scheme hides an instruction from a naive keyword or substring filter while
(we hope) still reaching the model's tokeniser: Unicode tag characters and
zero-width characters are invisible, look-alikes swap Latin letters for
confusable Cyrillic/Greek ones, base64 and leetspeak re-spell the words. The
inverse functions exist so the unit tests prove each transform is real (the
encoded form differs byte-for-byte, yet round-trips) rather than a no-op.

`encode(scheme, text)` is the one entry point the attack loader uses.
"""

from __future__ import annotations

import base64

# ----- Unicode tag characters: U+E0000..U+E007F shadow ASCII and render as nothing -----
TAG_BASE = 0xE0000


def tag_encode(text: str) -> str:
    """Map each printable ASCII char to its Unicode Tag twin (ord + 0xE0000); others pass through."""
    return "".join(chr(TAG_BASE + ord(c)) if 0x20 <= ord(c) <= 0x7E else c for c in text)


def tag_decode(text: str) -> str:
    return "".join(chr(ord(c) - TAG_BASE) if TAG_BASE + 0x20 <= ord(c) <= TAG_BASE + 0x7E else c for c in text)


# ----- zero-width characters wedged between visible ones -----
ZERO_WIDTH = "​‌‍﻿"      # ZWSP, ZWNJ, ZWJ, BOM/ZWNBSP


def zero_width_inject(text: str, filler: str = "​") -> str:
    """Put a zero-width char between every visible character, so "refund" never appears as a literal substring."""
    return filler.join(text)


def zero_width_strip(text: str) -> str:
    return "".join(c for c in text if c not in ZERO_WIDTH)


# ----- look-alike (homoglyph) letters -----
LOOKALIKE = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р",   # Cyrillic а с е о р
    "x": "х", "y": "у", "i": "і", "s": "ѕ", "j": "ј",   # Cyrillic х у і ѕ ј
    "A": "Α", "B": "Β", "E": "Ε", "H": "Η", "O": "Ο",   # Greek capitals
    "P": "Ρ", "T": "Τ", "X": "Χ",
}
_UNLOOK = {v: k for k, v in LOOKALIKE.items()}


def lookalike_encode(text: str) -> str:
    return "".join(LOOKALIKE.get(c, c) for c in text)


def lookalike_decode(text: str) -> str:
    return "".join(_UNLOOK.get(c, c) for c in text)


# ----- base64 -----
def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def b64_decode(text: str) -> str:
    return base64.b64decode(text.encode("ascii")).decode("utf-8")


# ----- leetspeak -----
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9", "l": "1"}
_UNLEET = {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "8": "b", "9": "g"}


def leet_encode(text: str) -> str:
    return "".join(LEET.get(c.lower(), c) for c in text)


def leet_decode(text: str) -> str:
    """Best effort: the digit->letter map is ambiguous (1 could be i or l), enough to read a decoded instruction."""
    return "".join(_UNLEET.get(c, c) for c in text)


ENCODERS = {
    "tag_chars": tag_encode,
    "zero_width": zero_width_inject,
    "lookalike": lookalike_encode,
    "base64": b64_encode,
    "leetspeak": leet_encode,
}


def encode(scheme: str, text: str) -> str:
    try:
        return ENCODERS[scheme](text)
    except KeyError:
        raise ValueError(f"unknown encoder {scheme!r}; have {sorted(ENCODERS)}") from None
