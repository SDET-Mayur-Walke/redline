"""One typed config for the whole app, loaded from configs/*.yaml.

Every switch that changes how exposed the agent is lives here, so an ablation
run is just a different YAML file. The defaults are the *vulnerable* baseline:
metadata is indexed and staff docs are retrievable. Later steps add the
defense switches next to these.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "configs" / "default.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")   # a typo in YAML should fail loudly, not silently use a default


class ModelsConfig(_Strict):
    agent: str = "qwen3:8b"
    judge: str = "qwen2.5:7b"
    embed: str = "nomic-embed-text"
    ollama_base_url: str = "http://localhost:11434"


class RetrievalConfig(_Strict):
    qdrant_path: str = "data/qdrant"          # relative to the repo root; ":memory:" for tests
    collection: str = "kb"
    chunk_tokens: int = Field(400, ge=50)     # greedy target when merging heading sections
    max_chunk_tokens: int = Field(500, ge=50)  # sections longer than this are split at paragraphs
    embed_batch: int = Field(32, ge=1)
    top_k_prefetch: int = Field(20, ge=1)     # candidates from each of dense and sparse before fusion
    top_k: int = Field(5, ge=1)
    rrf_k: int = Field(60, ge=1)
    sparse_model: str = "Qdrant/bm25"
    rerank: bool = True
    reranker_model: str = "Xenova/ms-marco-MiniLM-L-6-v2"
    index_metadata: bool = True               # vulnerable: author/title/source are embedded and searchable
    staff_filter: bool = False                # vulnerable: staff-only docs can be retrieved


class Config(_Strict):
    models: ModelsConfig = ModelsConfig()
    retrieval: RetrievalConfig = RetrievalConfig()


def load_config(path: str | Path | None = None) -> Config:
    p = Path(path) if path else DEFAULT_CONFIG
    return Config.model_validate(yaml.safe_load(p.read_text()) or {})


def resolve(path: str) -> str:
    """Repo-relative paths in the config resolve against the repo root, whatever the cwd."""
    if path == ":memory:" or Path(path).is_absolute():
        return path
    return str(ROOT / path)
