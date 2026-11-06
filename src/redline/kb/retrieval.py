"""Hybrid retrieval over the knowledge base: dense + BM25, RRF fusion, optional rerank.

One Qdrant collection holds every chunk, staff docs included. Whether staff
docs can come back is decided at query time by `staff_filter`: off in the
vulnerable baseline, on as the permission defense. Indexing everything and
filtering late is how many real systems leak, which is the point.

Attacks plant content through `add_documents(..., source="planted")`; `reset()`
removes it again so every trial starts from the clean corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from qdrant_client import QdrantClient, models

from redline.config import Config, RetrievalConfig, resolve
from redline.kb.corpus import Document
from redline.kb.encoders import DenseEncoder, Reranker, SparseEncoder
from redline.kb.ingest import Chunk, chunk_documents, slug

DENSE, SPARSE = "dense", "bm25"
BASE_ORIGIN = "kb"     # chunks from data/kb; anything else was added at runtime
Mode = Literal["dense", "sparse", "hybrid"]


@dataclass(frozen=True)
class Hit:
    chunk_id: str
    doc_id: str
    title: str
    section: str
    text: str
    score: float
    metadata: dict = field(default_factory=dict)

    @property
    def citation(self) -> str:
        return f"[{self.doc_id}#{slug(self.section)}]"


class Retriever:
    def __init__(self, cfg: RetrievalConfig, dense: DenseEncoder, sparse: SparseEncoder,
                 reranker: Reranker | None = None, client: QdrantClient | None = None):
        self.cfg, self.dense, self.sparse, self.reranker = cfg, dense, sparse, reranker
        self.client = client or _client(cfg.qdrant_path)

    @classmethod
    def from_config(cls, cfg: Config) -> Retriever:
        """Real models: Ollama embeddings, fastembed BM25 and (if enabled) a fastembed cross-encoder."""
        from redline.kb.encoders import FastembedBM25, FastembedCrossEncoder, OllamaEmbedder

        r = cfg.retrieval
        return cls(r, OllamaEmbedder(cfg.models.embed, cfg.models.ollama_base_url, r.embed_batch),
                   FastembedBM25(r.sparse_model), FastembedCrossEncoder(r.reranker_model) if r.rerank else None)

    # ----- indexing -----

    def rebuild(self, docs: list[Document]) -> int:
        """Drop the collection and index `docs` from scratch. Returns the number of chunks."""
        chunks = chunk_documents(docs, self.cfg.chunk_tokens, self.cfg.max_chunk_tokens)
        dense = self.dense.embed_documents([c.indexed_text(self.cfg.index_metadata) for c in chunks])
        if self.client.collection_exists(self.cfg.collection):
            self.client.delete_collection(self.cfg.collection)
        self.client.create_collection(
            self.cfg.collection,
            vectors_config={DENSE: models.VectorParams(size=len(dense[0]), distance=models.Distance.COSINE)},
            sparse_vectors_config={SPARSE: models.SparseVectorParams(modifier=models.Modifier.IDF)},
        )
        self._upsert(chunks, BASE_ORIGIN, dense)
        return len(chunks)

    def add_documents(self, docs: list[Document], source: str = "planted") -> list[str]:
        """Index extra documents at runtime (attacks use this). `source` is stored as the chunk's origin,
        separately from the doc's own metadata["source"], so a planted doc can still claim to be a help article."""
        if source == BASE_ORIGIN:
            raise ValueError(f"origin {BASE_ORIGIN!r} is reserved for the base corpus")
        chunks = chunk_documents(docs, self.cfg.chunk_tokens, self.cfg.max_chunk_tokens)
        self._upsert(chunks, source)
        return [c.chunk_id for c in chunks]

    def reset(self) -> None:
        """Remove everything added through add_documents; the base corpus stays."""
        self.client.delete(self.cfg.collection, points_selector=models.FilterSelector(filter=models.Filter(
            must_not=[models.FieldCondition(key="origin", match=models.MatchValue(value=BASE_ORIGIN))])))

    def count(self) -> int:
        return self.client.count(self.cfg.collection).count

    def _upsert(self, chunks: list[Chunk], origin: str, dense: list[list[float]] | None = None) -> None:
        texts = [c.indexed_text(self.cfg.index_metadata) for c in chunks]
        dense = dense or self.dense.embed_documents(texts)
        sparse = self.sparse.embed_documents(texts)
        points = [
            models.PointStruct(
                id=c.point_id,
                vector={DENSE: d, SPARSE: s},
                payload={"chunk_id": c.chunk_id, "doc_id": c.doc_id, "title": c.title, "section": c.section,
                         "text": c.text, "indexed_text": t, "origin": origin,
                         # missing audience counts as public: planted content is customer-visible by default
                         "audience": c.metadata.get("audience", "public"), "metadata": c.metadata},
            )
            for c, t, d, s in zip(chunks, texts, dense, sparse, strict=True)
        ]
        self.client.upsert(self.cfg.collection, points=points)

    # ----- search -----

    def _filter(self) -> models.Filter | None:
        if not self.cfg.staff_filter:
            return None
        return models.Filter(must=[models.FieldCondition(key="audience", match=models.MatchValue(value="public"))])

    def search(self, query: str, top_k: int | None = None, mode: Mode = "hybrid",
               rerank: bool | None = None) -> list[Hit]:
        top_k = top_k or self.cfg.top_k
        rerank = (self.reranker is not None) if rerank is None else rerank
        if rerank and self.reranker is None:
            raise ValueError("rerank requested but no reranker configured")
        n = self.cfg.top_k_prefetch if rerank else top_k
        flt = self._filter()

        if mode == "dense":
            res = self.client.query_points(self.cfg.collection, query=self.dense.embed_query(query), using=DENSE,
                                           query_filter=flt, limit=n, with_payload=True)
        elif mode == "sparse":
            res = self.client.query_points(self.cfg.collection, query=self.sparse.embed_query(query), using=SPARSE,
                                           query_filter=flt, limit=n, with_payload=True)
        else:
            k = self.cfg.top_k_prefetch
            res = self.client.query_points(
                self.cfg.collection,
                prefetch=[models.Prefetch(query=self.dense.embed_query(query), using=DENSE, filter=flt, limit=k),
                          models.Prefetch(query=self.sparse.embed_query(query), using=SPARSE, filter=flt, limit=k)],
                query=models.RrfQuery(rrf=models.Rrf(k=self.cfg.rrf_k)),
                limit=n, with_payload=True,
            )
        hits = [(p.payload, p.score) for p in res.points]

        if rerank and hits:
            scores = self.reranker.scores(query, [p["indexed_text"] for p, _ in hits])
            hits = sorted(((p, s) for (p, _), s in zip(hits, scores, strict=True)), key=lambda h: -h[1])
        return [Hit(chunk_id=p["chunk_id"], doc_id=p["doc_id"], title=p["title"], section=p["section"],
                    text=p["text"], score=float(s), metadata={**p["metadata"], "origin": p["origin"]})
                for p, s in hits[:top_k]]


def _client(path: str) -> QdrantClient:
    path = resolve(path)
    return QdrantClient(location=":memory:") if path == ":memory:" else QdrantClient(path=path)
