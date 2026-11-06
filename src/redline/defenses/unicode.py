"""Unicode normalisation for untrusted text: user messages, retrieved chunks and tool results.

Text can carry instructions a human reviewer (or a keyword filter) never sees:
  - Unicode tag characters (U+E0000-U+E007F) shadow ASCII and render as nothing
  - zero-width characters split words so a substring match fails
  - bidi controls reorder what is displayed versus what is read
  - look-alike letters from Cyrillic or Greek spell Latin words a filter doesn't recognise

This layer removes the invisible characters outright (there is no legitimate use for them in a support chat),
applies NFKC (fullwidth and compatibility forms become their plain equivalents), and folds look-alike letters
to Latin where the text is Latin script. Folding is scoped on purpose: a token that mixes scripts (Latin with
Cyrillic inside one word) is always folded, and a whole text is folded when most of its letters are Latin. A
message genuinely written in Cyrillic or Greek is left alone, and Devanagari is never touched.

The table below covers the common confusables in the spirit of Unicode TR39, not an exhaustive list.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# invisible or formatting code points: (start, end) inclusive
INVISIBLE_RANGES = (
    (0xE0000, 0xE007F),   # tag characters
    (0x200B, 0x200F),     # zero-width space / non-joiner / joiner, LRM, RLM
    (0x202A, 0x202E),     # bidi embeddings and overrides
    (0x2060, 0x2064),     # word joiner, invisible operators
    (0x2066, 0x2069),     # bidi isolates
    (0xFE00, 0xFE0F),     # variation selectors
    (0xFEFF, 0xFEFF),     # zero-width no-break space / BOM
    (0x00AD, 0x00AD),     # soft hyphen
    (0x034F, 0x034F),     # combining grapheme joiner
    (0x061C, 0x061C),     # Arabic letter mark
    (0x180E, 0x180E),     # Mongolian vowel separator
)

# Cyrillic and Greek letters that render like Latin ones -> the Latin letter
CONFUSABLES = {
    # Cyrillic lowercase
    "а": "a", "в": "b", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    "ү": "y", "ɡ": "g",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "Ѕ": "S", "І": "I", "Ј": "J", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W", "Ү": "Y",
    # Greek lowercase
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}

_WORD = re.compile(r"\w+", re.UNICODE)


def _invisible(ch: str) -> bool:
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in INVISIBLE_RANGES)


def _is_latin(ch: str) -> bool:
    return ch.isascii() and ch.isalpha() or unicodedata.name(ch, "").startswith("LATIN ")


@dataclass(frozen=True)
class Normalized:
    text: str
    removed: int          # invisible characters dropped
    folded: int           # look-alike letters replaced

    @property
    def changed(self) -> bool:
        return bool(self.removed or self.folded)


def normalize(text: str) -> Normalized:
    kept = [c for c in text if not _invisible(c)]
    removed = len(text) - len(kept)
    s = unicodedata.normalize("NFKC", "".join(kept))

    letters = [c for c in s if c.isalpha()]
    latin = sum(_is_latin(c) for c in letters)
    mostly_latin = bool(letters) and latin / len(letters) > 0.5
    folded = 0

    def fold(m: re.Match) -> str:
        nonlocal folded
        w = m.group(0)
        if not any(c in CONFUSABLES for c in w):
            return w
        if mostly_latin or any(_is_latin(c) for c in w):
            out = "".join(CONFUSABLES.get(c, c) for c in w)
            folded += sum(a != b for a, b in zip(w, out, strict=True))
            return out
        return w

    s = _WORD.sub(fold, s)
    return Normalized(s, removed, folded)


def normalize_tree(value):
    """Normalise every string inside a tool result (dicts and lists walked); returns (value, removed, folded)."""
    totals = [0, 0]

    def walk(v):
        if isinstance(v, str):
            n = normalize(v)
            totals[0] += n.removed
            totals[1] += n.folded
            return n.text
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    out = walk(value)
    return out, totals[0], totals[1]
