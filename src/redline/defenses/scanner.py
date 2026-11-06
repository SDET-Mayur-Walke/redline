"""Ingestion scanner: check every chunk at index time and quarantine the suspicious ones, with the reasons.

The rules come from general categories of content that has no business in a help-center article or a
customer review, not from any particular attack:

  hidden          content a reader would not see: HTML comments, invisible or control characters, markup
                  styled to be invisible
  addresses_ai    text that speaks *to* the assistant or names one of its tools as a command. Our own help
                  docs talk *about* "the assistant" in the third person, so a bare mention is not enough
  role_marker     claimed authority inside content: a line that opens as a system/admin/developer message,
                  or a chat-template control token
  unlisted_link   a URL whose host is not on the egress allowlist (noted separately when the query string
                  has a placeholder waiting to be filled in)
  long_metadata   a metadata field that carries a sentence instead of a short value

A quarantined chunk is not indexed, so it can never be retrieved; `Retriever.quarantined` keeps the chunk id,
origin and reasons so a run can show what was held back and why. The rules are deliberately short. They will
miss an instruction written as ordinary prose (that is what spotlighting and the tool rules are for), and they
are checked against the real corpus for false positives (tests/test_defenses_retrieval.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from redline.defenses.egress import url_allowed
from redline.defenses.unicode import _invisible

_AI = r"(?:ai|assistant|chat\s?bot|bot|model|llm|agent|language model)"

HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
HIDDEN_STYLE = re.compile(
    r"style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)"
    r"|<\w+[^>]*\shidden[\s>]", re.I)
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ADDRESSES_AI = [
    # a vocative: "<greeting> assistant" / "assistant, you ..." / "assistant: please ..."
    re.compile(rf"\b(?:dear|hey|hi|hello|attention|note to(?: the)?)\s+{_AI}s?\b", re.I),
    re.compile(rf"\b{_AI}s?\s*[,:]\s*(?:you|please|always|never|do|don't|now|first)\b", re.I),
    # conditional on the reader being a model: "if you are an AI ..."
    re.compile(rf"\bif you(?:'re| are) (?:an? )?{_AI}\b", re.I),
    re.compile(rf"\b{_AI}s? (?:reading|processing|summari[sz]ing|parsing) this\b", re.I),
    # an imperative naming a function-style identifier: help text never names tool functions
    re.compile(r"\b(?:call|invoke|run|execute|use|trigger)\s+(?:the\s+)?`?[a-z]+_[a-z_]+`?(?:\s+(?:tool|function))?",
               re.I),
]

ROLE_MARKER = [
    re.compile(r"^\s*[\[(<{#*]*\s*(?:system|admin(?:istrator)?|developer|operator|root)"
               r"(?:\s+(?:note|message|notice|instruction|update|override|prompt))?\s*[\])>}*]*\s*:", re.I | re.M),
    re.compile(r"\[/?(?:system|admin|developer|inst)\]", re.I),
    re.compile(r"<\|?/?(?:system|im_start|im_end|endoftext)\|?>", re.I),
]

URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
TEMPLATED_QUERY = re.compile(r"[?&][\w.-]+=(?:\{|<|\[|%7B|%3C|\$)", re.I)

METADATA_EXEMPT = ("path",)          # file paths are long on purpose
METADATA_MAX_WORDS = 10
METADATA_MAX_CHARS = 120


@dataclass(frozen=True)
class Verdict:
    reasons: tuple[str, ...]

    @property
    def quarantined(self) -> bool:
        return bool(self.reasons)


class IngestionScanner:
    def __init__(self, allowlist: list[str] | None = None):
        self.allowlist = list(allowlist or [])

    def scan(self, text: str, metadata: dict | None = None) -> Verdict:
        reasons: list[str] = []
        reasons += self._hidden(text)
        reasons += [f"addresses_ai: {m.group(0)[:60]!r}" for m in _first_matches(ADDRESSES_AI, text)]
        reasons += [f"role_marker: {m.group(0).strip()[:60]!r}" for m in _first_matches(ROLE_MARKER, text)]
        reasons += self._links(text)
        reasons += self._metadata(metadata or {})
        return Verdict(tuple(reasons))

    def scan_chunk(self, chunk) -> Verdict:
        """A kb.ingest.Chunk: title, section and text are scanned as text, metadata field by field."""
        return self.scan(f"{chunk.title}\n{chunk.section}\n{chunk.text}", chunk.metadata)

    def _hidden(self, text: str) -> list[str]:
        out = []
        if HTML_COMMENT.search(text):
            out.append("hidden: HTML comment")
        if HIDDEN_STYLE.search(text):
            out.append("hidden: markup styled to be invisible")
        n = sum(_invisible(c) for c in text)
        if n:
            out.append(f"hidden: {n} invisible character(s)")
        if CONTROL.search(text):
            out.append("hidden: control character(s)")
        return out

    def _links(self, text: str) -> list[str]:
        out = []
        for url in dict.fromkeys(URL.findall(text)):
            if url_allowed(url, self.allowlist):
                continue
            templated = " (templated query)" if TEMPLATED_QUERY.search(url) else ""
            out.append(f"unlisted_link{templated}: {url[:80]}")
        return out

    def _metadata(self, metadata: dict) -> list[str]:
        out = []
        for key, value in metadata.items():
            if key in METADATA_EXEMPT or not isinstance(value, str):
                continue
            if len(value.split()) > METADATA_MAX_WORDS or len(value) > METADATA_MAX_CHARS:
                out.append(f"long_metadata: {key} has {len(value.split())} words")
            else:
                out += [f"{r} (in metadata {key})" for r in self._hidden(value) + self._links(value)]
        return out


def _first_matches(patterns: list[re.Pattern], text: str) -> list[re.Match]:
    """At most one match per pattern: the reason list says what kind of thing was found, not every instance."""
    return [m for p in patterns if (m := p.search(text))]
