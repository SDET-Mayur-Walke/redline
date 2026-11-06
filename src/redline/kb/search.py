"""Query the on-disk index from the shell, to eyeball what the agent would retrieve.

    python -m redline.kb.search "how long do UPI refunds take"
    python -m redline.kb.search "refund override" --staff-filter      # what the permission defense hides
"""

from __future__ import annotations

import argparse
import textwrap

from redline.config import load_config
from redline.kb.retrieval import Retriever


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Search the knowledge-base index.")
    ap.add_argument("query")
    ap.add_argument("--config")
    ap.add_argument("-k", type=int, help="number of hits (default: retrieval.top_k)")
    ap.add_argument("--mode", choices=["dense", "sparse", "hybrid"], default="hybrid")
    ap.add_argument("--no-rerank", action="store_true")
    ap.add_argument("--staff-filter", action="store_true", help="only return audience=public docs")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    if args.no_rerank:
        cfg.retrieval.rerank = False
    if args.staff_filter:
        cfg.retrieval.staff_filter = True
    r = Retriever.from_config(cfg)
    for i, h in enumerate(r.search(args.query, top_k=args.k, mode=args.mode), 1):
        tag = "" if h.metadata.get("audience") == "public" else f"  ({h.metadata.get('audience')})"
        print(f"{i}. {h.score:8.4f}  {h.citation}  {h.title}{tag}")
        print(textwrap.indent(textwrap.shorten(h.text, 220), "      "))


if __name__ == "__main__":
    main()
