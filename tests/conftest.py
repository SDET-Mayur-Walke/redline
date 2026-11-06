import pytest

from redline.config import RetrievalConfig
from redline.kb.corpus import load_corpus
from redline.kb.encoders import HashEmbedder, HashSparse
from redline.kb.retrieval import Retriever


def offline_retriever(docs=None, **cfg) -> Retriever:
    """In-memory Qdrant with hashing encoders: real plumbing, no models, no downloads."""
    r = Retriever(RetrievalConfig(qdrant_path=":memory:", rerank=False, **cfg), HashEmbedder(), HashSparse())
    r.rebuild(docs if docs is not None else load_corpus(include_staff=True))
    return r


@pytest.fixture(scope="session")
def kb_retriever() -> Retriever:
    return offline_retriever()
