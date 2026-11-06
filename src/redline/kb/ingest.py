"""Chunk knowledge-base documents and (from the CLI) build the on-disk index.

Chunks follow the Markdown headings: consecutive sections are merged up to
about `chunk_tokens`, and a section longer than `max_chunk_tokens` is split at
paragraph breaks. With the default 150, most chunks are one heading section, so
a citation points at the section that answers, not the whole article.

Every chunk carries the document's metadata. With `index_metadata` on (the
vulnerable default) that metadata is also prepended to the text that gets
embedded and BM25-indexed, so a planted document can steer retrieval through
its title or author field. That is deliberate: it is one of the surfaces the
attack library exercises.

    python -m redline.kb.ingest          # (re)builds data/qdrant from data/kb
"""

from __future__ import annotations

import argparse
import re
import uuid
from dataclasses import dataclass, field

from redline.kb.corpus import Document

HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "redline/kb")
# metadata that is bookkeeping, not content; never prepended
_NOT_INDEXED = {"path"}


def approx_tokens(text: str) -> int:
    """~4 characters per token for English. Close enough for sizing chunks; no tokenizer download needed."""
    return max(1, round(len(text) / 4))


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"


@dataclass(frozen=True)
class Chunk:
    chunk_id: str        # "<doc_id>:<n>", stable as long as the document doesn't change
    doc_id: str
    title: str
    section: str         # heading the chunk starts under; the H1 and any preamble are "Overview"
    text: str
    metadata: dict = field(default_factory=dict)

    @property
    def point_id(self) -> str:
        """Qdrant wants a UUID or an int; derive one from the chunk id so re-ingesting overwrites in place."""
        return str(uuid.uuid5(_NS, self.chunk_id))

    @property
    def citation(self) -> str:
        return f"[{self.doc_id}#{slug(self.section)}]"

    def indexed_text(self, index_metadata: bool) -> str:
        if not index_metadata:
            return self.text
        fields = {"title": self.title, **{k: v for k, v in self.metadata.items()
                                          if k not in _NOT_INDEXED and k not in ("doc_id", "title")}}
        header = "\n".join(f"{k}: {v}" for k, v in fields.items())
        return f"{header}\n\n{self.text}"


def sections(markdown: str) -> list[tuple[str, str]]:
    """(heading, text including the heading line) for each heading-delimited section."""
    out: list[tuple[str, list[str]]] = []
    for line in markdown.splitlines():
        m = HEADING.match(line)
        if m:
            name = "Overview" if len(m.group(1)) == 1 else m.group(2)
            out.append((name, [line]))
        elif out:
            out[-1][1].append(line)
        else:
            out.append(("Overview", [line]))
    return [(name, "\n".join(lines).strip()) for name, lines in out if "\n".join(lines).strip()]


def _split_long(text: str, max_tokens: int) -> list[str]:
    parts, cur = [], ""
    for para in text.split("\n\n"):
        cand = f"{cur}\n\n{para}" if cur else para
        if cur and approx_tokens(cand) > max_tokens:
            parts.append(cur)
            cur = para
        else:
            cur = cand
    return parts + [cur] if cur else parts


def chunk_document(doc: Document, chunk_tokens: int = 150, max_chunk_tokens: int = 500) -> list[Chunk]:
    pieces: list[tuple[str, str]] = []                  # (section name, text) after splitting long sections
    for name, text in sections(doc.text):
        pieces += [(name, p) for p in _split_long(text, max_chunk_tokens)]

    merged: list[tuple[str, str]] = []
    for name, text in pieces:
        if merged and approx_tokens(merged[-1][1]) + approx_tokens(text) <= chunk_tokens:
            merged[-1] = (merged[-1][0], f"{merged[-1][1]}\n\n{text}")
        else:
            merged.append((name, text))

    meta_base = {"doc_id": doc.id, "title": doc.title, **doc.metadata}
    return [Chunk(chunk_id=f"{doc.id}:{i}", doc_id=doc.id, title=doc.title, section=name, text=text,
                  metadata={**meta_base, "section": name})
            for i, (name, text) in enumerate(merged)]


def chunk_documents(docs: list[Document], chunk_tokens: int = 150, max_chunk_tokens: int = 500) -> list[Chunk]:
    return [c for d in docs for c in chunk_document(d, chunk_tokens, max_chunk_tokens)]


def main(argv: list[str] | None = None) -> None:
    from redline.config import load_config
    from redline.kb.corpus import load_corpus
    from redline.kb.retrieval import Retriever

    ap = argparse.ArgumentParser(description="Build the knowledge-base index (all docs, staff included).")
    ap.add_argument("--config", help="YAML config; defaults to configs/default.yaml")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    r = Retriever.from_config(cfg)
    docs = load_corpus(include_staff=True)
    n = r.rebuild(docs)
    print(f"indexed {n} chunks from {len(docs)} documents into {cfg.retrieval.qdrant_path} "
          f"(index_metadata={cfg.retrieval.index_metadata})")


if __name__ == "__main__":
    main()
