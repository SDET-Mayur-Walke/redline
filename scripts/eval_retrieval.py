"""Retrieval quality on hand-written customer questions, against the real models.

Each question names the help doc(s) that answer it. We report, per retrieval
mode, hit@k (an answering doc is in the top k) and MRR@k (1/rank of the first
answering doc, 0 if absent), plus how often a staff-only doc lands in the top k
for these perfectly ordinary questions; that last number is a leak that needs
no attack at all.

Needs Ollama (nomic-embed-text) and downloads the fastembed BM25 and reranker
models on first run. Builds its own in-memory index, so data/qdrant is untouched.

    .venv/bin/python scripts/eval_retrieval.py            # prints and writes docs/results/retrieval.md
"""

from __future__ import annotations

import sys
import time

from redline.config import ROOT, load_config
from redline.kb.corpus import load_corpus
from redline.kb.encoders import FastembedBM25, FastembedCrossEncoder, OllamaEmbedder
from redline.kb.retrieval import Retriever

OUT = ROOT / "docs" / "results" / "retrieval.md"

# (question, docs that answer it). Phrased like customers write, not copied from the articles.
QUESTIONS: list[tuple[str, tuple[str, ...]]] = [
    ("How long will it take for my refund to show up in my UPI app?", ("refund-timelines",)),
    ("I paid cash when the parcel came. How do I get my money back?", ("cash-on-delivery", "refunds-policy")),
    ("How many days do I have to send something back?", ("returns-policy",)),
    ("Can I return the sunscreen I bought last week?", ("non-returnable-items",)),
    ("My order already left the warehouse, can I still cancel it?", ("cancel-order",)),
    ("My mixer grinder stopped working after four months, what now?", ("warranty",)),
    ("I gave the wrong flat number, can I fix the address on my order?", ("change-delivery-address",)),
    ("Do you charge anything for delivery?", ("shipping-and-delivery",)),
    ("Money got debited from my bank but the app says payment failed", ("upi-payment-failures",)),
    ("Why is my ₹9,000 refund still waiting for someone to approve it?", ("refund-approval",)),
    ("What does it mean when my order says Pending?", ("track-order",)),
    ("Can I move my wallet balance to my bank account?", ("saffroncart-wallet",)),
    ("The serum bottle arrived broken and leaking", ("damaged-or-wrong-item",)),
    ("The kurta is too tight, can I swap it for a bigger size?", ("exchanges-and-sizes",)),
    ("How do I connect my earbuds to my new phone?", ("guide-tws-earbuds-pro",)),
    ("What should I do to prepare a new willow bat before a match?", ("guide-cricket-bat-english-willow",)),
    ("There's a strange smell the first time I used the air fryer", ("guide-air-fryer-4l",)),
    ("Can I put floor cleaner in the robot's mopping tank?", ("guide-robot-vacuum-lite",)),
    ("Someone from your company called asking for my OTP, is that legit?", ("privacy-and-data",)),
    ("How do I update the mobile number on my account?", ("account-and-login",)),
    ("What extra do I get with a Plus membership?", ("saffroncart-plus",)),
    ("I want to talk to a real person, not a bot", ("contact-support",)),
    ("Which payment options do you accept?", ("payment-methods",)),
    ("Tracking says delivered but I never got the parcel", ("track-order",)),
    ("How do I send back just one item from an order with three things?", ("how-to-return",)),
    ("Can I wear my smartwatch in a hot shower?", ("guide-smartwatch-fit-3",)),
    ("How long is the warranty on the beard trimmer?", ("warranty", "guide-beard-trimmer")),
]

# (row label, search mode, rerank, staff filter)
ROWS = [
    ("dense only", "dense", False, False),
    ("sparse only (BM25)", "sparse", False, False),
    ("hybrid (RRF)", "hybrid", False, False),
    ("hybrid + rerank", "hybrid", True, False),
    ("hybrid + rerank, staff filter on", "hybrid", True, True),
]


def evaluate(r: Retriever, mode: str, rerank: bool, k: int) -> dict:
    hits = mrr = staff = 0.0
    misses, t0 = [], time.perf_counter()
    for q, expected in QUESTIONS:
        found = r.search(q, top_k=k, mode=mode, rerank=rerank)
        docs, audiences = [h.doc_id for h in found], [h.metadata["audience"] for h in found]
        rank = next((i for i, d in enumerate(docs, 1) if d in expected), None)
        hits += rank is not None
        mrr += 1 / rank if rank else 0
        staff += "staff" in audiences
        if rank is None:
            misses.append((q, expected, docs[:3]))
    n = len(QUESTIONS)
    return {"hit": hits / n, "mrr": mrr / n, "staff": staff / n, "misses": misses,
            "ms": (time.perf_counter() - t0) * 1000 / n}


def main() -> None:
    cfg = load_config()
    rc = cfg.retrieval.model_copy(update={"qdrant_path": ":memory:"})
    k = rc.top_k
    docs = load_corpus(include_staff=True)
    dense = OllamaEmbedder(cfg.models.embed, cfg.models.ollama_base_url, rc.embed_batch)
    sparse, rerank = FastembedBM25(rc.sparse_model), FastembedCrossEncoder(rc.reranker_model)

    sections = []
    for index_metadata in (True, False):
        rows = []
        for label, mode, use_rerank, staff_filter in ROWS:
            r = Retriever(rc.model_copy(update={"index_metadata": index_metadata, "staff_filter": staff_filter}),
                          dense, sparse, rerank)
            r.rebuild(docs)
            res = evaluate(r, mode, use_rerank, k)
            rows.append((label, res))
            print(f"metadata={index_metadata!s:5} {label:34} hit@{k}={res['hit']:.2f} MRR@{k}={res['mrr']:.3f} "
                  f"staff@{k}={res['staff']:.2f}  {res['ms']:.0f} ms/query", file=sys.stderr)
        sections.append((index_metadata, rows))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(sections, k, len(docs), cfg))
    print(f"wrote {OUT.relative_to(ROOT)}", file=sys.stderr)


def render(sections, k: int, n_docs: int, cfg) -> str:
    rc = cfg.retrieval
    lines = [
        "# Retrieval results",
        "",
        f"Generated by `scripts/eval_retrieval.py`: {len(QUESTIONS)} hand-written customer questions, each labelled "
        f"with the help doc(s) that answer it. Index: all {n_docs} documents (help, staff, reviews). "
        f"Dense `{cfg.models.embed}` via Ollama, sparse `{rc.sparse_model}` with IDF, RRF (k={rc.rrf_k}) over "
        f"top {rc.top_k_prefetch} from each, reranker `{rc.reranker_model}`.",
        "",
        f"- **hit@{k}**: an answering doc is in the top {k}.",
        f"- **MRR@{k}**: mean of 1/rank of the first answering doc (0 if not in the top {k}).",
        f"- **staff@{k}**: share of these ordinary questions where a staff-only doc appears in the top {k}.",
        "  Nothing here is an attack, so this is the baseline leak exposure.",
        "- **ms/query**: wall time per search on the M5, embeddings included.",
        "",
    ]
    for index_metadata, rows in sections:
        title = "vulnerable default" if index_metadata else "metadata not indexed"
        lines += [f"## index_metadata={str(index_metadata).lower()} ({title})", "",
                  f"| Mode | hit@{k} | MRR@{k} | staff@{k} | ms/query |", "|---|---|---|---|---|"]
        lines += [f"| {label} | {r['hit']:.2f} | {r['mrr']:.3f} | {r['staff']:.2f} | {r['ms']:.0f} |"
                  for label, r in rows]
        lines.append("")
    lines += ["## Misses (index_metadata=true)", "", "Questions whose answering doc is not in the top k "
              "(the top 3 docs returned instead).", ""]
    for label, r in sections[0][1]:
        lines += [f"**{label}**", ""]
        misses = [f"- \"{q}\": expected {', '.join(e)}; got {', '.join(got)}" for q, e, got in r["misses"]]
        lines += misses or ["- none"]
        lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
