"""Load the knowledge base into one list of documents for retrieval.

Three sources, all under data/kb/:
  - help/*.md       public help-center articles (YAML front matter + Markdown)
  - staff/*.md      staff-only docs, each carrying a canary string
  - reviews.jsonl   customer reviews (written by customers, so untrusted text)

Metadata (author, source, audience) is kept on every document on purpose:
retrieval will surface it to the model, which is itself an attack surface.
Staff docs are opt-in, so a hardened setup can leave them out of the index
while the vulnerable baseline puts them in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KB = Path(__file__).resolve().parents[3] / "data" / "kb"
REQUIRED = ("id", "title", "category", "audience", "author", "updated")
SOURCES = {"help": "help-center", "staff": "staff-wiki"}


@dataclass(frozen=True)
class Document:
    id: str
    title: str
    text: str
    metadata: dict = field(default_factory=dict)   # audience, author, source, category, path, ...


def parse_markdown(path: Path, source: str) -> Document:
    """Split YAML front matter from the body. Raises ValueError on a malformed doc."""
    raw = path.read_text(encoding="utf-8")
    if not raw.startswith("---\n"):
        raise ValueError(f"{path}: missing front matter")
    try:
        head, body = raw[4:].split("\n---\n", 1)
    except ValueError:
        raise ValueError(f"{path}: unterminated front matter") from None
    meta = yaml.safe_load(head) or {}
    missing = [k for k in REQUIRED if k not in meta]
    if missing:
        raise ValueError(f"{path}: front matter missing {missing}")
    meta = {k: str(v) for k, v in meta.items()}   # YAML turns dates into date objects; keep everything as text
    meta["source"] = source
    meta["path"] = f"{path.parent.name}/{path.name}"
    return Document(id=meta.pop("id"), title=meta.pop("title"), text=body.strip(), metadata=meta)


def load_reviews(path: Path) -> list[Document]:
    docs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        docs.append(Document(
            id=r["review_id"],
            title=r["title"],
            text=r["text"],
            metadata={"audience": "public", "author": r["customer"], "source": "customer-review",
                      "category": "review", "product_id": r["product_id"], "rating": r["rating"],
                      "date": r["date"], "path": path.name},
        ))
    return docs


def load_corpus(include_staff: bool = False, include_reviews: bool = True, root: Path = KB) -> list[Document]:
    docs = [parse_markdown(p, SOURCES["help"]) for p in sorted((root / "help").glob("*.md"))]
    if include_staff:
        docs += [parse_markdown(p, SOURCES["staff"]) for p in sorted((root / "staff").glob("*.md"))]
    if include_reviews:
        docs += load_reviews(root / "reviews.jsonl")
    return docs
