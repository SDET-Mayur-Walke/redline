"""The three models retrieval depends on, behind small interfaces.

Real backends: Ollama's nomic-embed-text for dense vectors, fastembed's BM25
for sparse vectors, a fastembed cross-encoder for reranking. The hashing
encoders at the bottom are offline stand-ins so tests never need a model or
a download; they are lexical, which is enough to test plumbing, not quality.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Protocol

import httpx
from qdrant_client import models

# nomic-embed-text was trained with task prefixes; leaving them out costs recall
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "


class DenseEncoder(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


class SparseEncoder(Protocol):
    def embed_documents(self, texts: list[str]) -> list[models.SparseVector]: ...
    def embed_query(self, text: str) -> models.SparseVector: ...


class Reranker(Protocol):
    def scores(self, query: str, texts: list[str]) -> list[float]: ...


class OllamaEmbedder:
    def __init__(self, model: str, base_url: str, batch: int = 32, timeout: float = 120.0):
        self.model, self.batch = model, batch
        self._http = httpx.Client(base_url=base_url, timeout=timeout)

    def _embed(self, inputs: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(inputs), self.batch):
            r = self._http.post("/api/embed", json={"model": self.model, "input": inputs[i:i + self.batch]})
            r.raise_for_status()
            out += r.json()["embeddings"]
        return out

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed([DOC_PREFIX + t for t in texts])

    def embed_query(self, text: str) -> list[float]:
        return self._embed([QUERY_PREFIX + text])[0]


class FastembedBM25:
    """BM25 term weights per document; Qdrant applies IDF at query time (Modifier.IDF)."""

    def __init__(self, model: str = "Qdrant/bm25"):
        from fastembed import SparseTextEmbedding  # imported lazily: loading it fetches the model files

        self._m = SparseTextEmbedding(model)

    @staticmethod
    def _sv(e) -> models.SparseVector:
        return models.SparseVector(indices=e.indices.tolist(), values=e.values.tolist())

    def embed_documents(self, texts: list[str]) -> list[models.SparseVector]:
        return [self._sv(e) for e in self._m.embed(texts)]

    def embed_query(self, text: str) -> models.SparseVector:
        return self._sv(next(iter(self._m.query_embed(text))))


class FastembedCrossEncoder:
    def __init__(self, model: str):
        from fastembed.rerank.cross_encoder import TextCrossEncoder

        self._m = TextCrossEncoder(model)

    def scores(self, query: str, texts: list[str]) -> list[float]:
        return [float(s) for s in self._m.rerank(query, texts)]


# ----- offline stand-ins for tests -----

_WORD = re.compile(r"[a-z0-9₹]+")


def _tokens(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def _bucket(token: str, dim: int) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode(), digest_size=4).digest(), "big") % dim


class HashEmbedder:
    """Bag-of-words hashed into a fixed-size, L2-normalised vector. Deterministic across runs."""

    def __init__(self, dim: int = 256):
        self.dim = dim

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        for t in _tokens(text):
            v[_bucket(t, self.dim)] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vec(text)


class HashSparse:
    """Term counts keyed by a hash of the token; with Modifier.IDF this behaves like a crude BM25."""

    def _sv(self, text: str, binary: bool) -> models.SparseVector:
        counts = Counter(_bucket(t, 2**31 - 1) for t in _tokens(text))
        idx = sorted(counts)
        return models.SparseVector(indices=idx, values=[1.0 if binary else float(counts[i]) for i in idx])

    def embed_documents(self, texts: list[str]) -> list[models.SparseVector]:
        return [self._sv(t, binary=False) for t in texts]

    def embed_query(self, text: str) -> models.SparseVector:
        return self._sv(text, binary=True)
