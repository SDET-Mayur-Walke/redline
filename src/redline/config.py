"""One typed config for the whole app, loaded from configs/*.yaml.

Every switch that changes how exposed the agent is lives here, so an ablation
run is just a different YAML file. The defaults are the *vulnerable* baseline:
metadata is indexed, staff docs are retrievable and every `defenses:` switch
is off. configs/hardened.yaml turns them all on.
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
    chunk_tokens: int = Field(150, ge=50)     # greedy target when merging heading sections; ~1 section per chunk
    max_chunk_tokens: int = Field(500, ge=50)  # sections longer than this are split at paragraphs
    embed_batch: int = Field(32, ge=1)
    top_k_prefetch: int = Field(20, ge=1)     # candidates from each of dense and sparse before fusion
    top_k: int = Field(5, ge=1)
    rrf_k: int = Field(60, ge=1)
    sparse_model: str = "Qdrant/bm25"
    rerank: bool = True                       # +~160 ms/query; halves staff-doc leak (staff@5 0.15->0.07),
    #                                           raises MRR@5 0.825->0.880. See docs/results/retrieval.md.
    reranker_model: str = "Xenova/ms-marco-MiniLM-L-6-v2"
    index_metadata: bool = True               # vulnerable: author/title/source are embedded and searchable
    staff_filter: bool = False                # vulnerable: staff-only docs can be retrieved


class AgentConfig(_Strict):
    prompt: str = "support_v3"                # prompts/<name>.md, versioned so results name the prompt they used
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    max_steps: int = Field(8, ge=1)           # model calls per user turn, tool rounds included
    num_ctx: int = Field(16384, ge=2048)      # Ollama's default window silently truncates prompt + tools + hits
    think: bool = False                       # qwen3 reasoning off: faster, and tool calls don't hide in <think>
    # auto_retrieve: search the help center for every user message before the first model call, and feed the
    # hits to the model as if it had searched. qwen3:8b without thinking rarely calls search itself and answers
    # from memory instead, so this is on by default to make RAG real. It also WIDENS THE INJECTION SURFACE:
    # retrieved (and planted) documents now reach the model on every substantive turn, unprompted, even when
    # the user never asked a policy question. Turn it off to require an explicit tool call before any doc is
    # pulled in, shrinking the indirect-injection surface at the cost of recall on qwen3:8b.
    auto_retrieve: bool = True
    timeout: float = 180.0


class DefensesConfig(_Strict):
    """One switch per defense layer (src/redline/defenses/), all off by default so the baseline stays vulnerable.
    retrieval.staff_filter is the eleventh switch; it lives with retrieval because it is a query filter."""
    # --- input: user messages and retrieved text before the model sees them
    unicode_normalize: bool = False           # NFKC, strip tag/zero-width/bidi characters, fold look-alike letters
    injection_classifier: bool = False        # a prompt-injection classifier on user input and retrieved chunks
    injection_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    injection_threshold: float = Field(0.9, ge=0.0, le=1.0)   # P(injection) at or above this is flagged
    guard_llm: bool = False                   # Llama Guard on the user message and on the final reply
    guard_model: str = "llama-guard3:1b"
    # --- retrieval
    ingestion_scanner: bool = False           # quarantine suspicious chunks at index time
    spotlight: bool = False                   # wrap tool results in a random per-turn marker, declared as data
    # --- tools (enforced in the tool layer; store.py stays policy-free)
    tool_authz: bool = False                  # orders and email recipients must belong to the session customer
    refund_rules: bool = False                # limit, return window, amount owed, original method, in code
    confirm_side_effects: bool = False        # side effects wait for an explicit confirm from the API caller
    # --- output
    egress_filter: bool = False               # fetch_url and links/images in replies only to allowlisted hosts
    egress_allowlist: list[str] = Field(default_factory=list)   # hostnames; an entry also allows its subdomains
    output_filter: bool = False               # redact other customers' PII, block dumps of protected text
    overlap_ngram: int = Field(8, ge=3)       # word n-gram length for the protected-text overlap check
    overlap_min_words: int = Field(40, ge=1)  # reply words covered by protected n-grams before the reply is blocked


SWITCHES = ("unicode_normalize", "injection_classifier", "guard_llm", "ingestion_scanner", "spotlight", "tool_authz",
            "refund_rules", "confirm_side_effects", "egress_filter", "output_filter")


class Config(_Strict):
    models: ModelsConfig = ModelsConfig()
    retrieval: RetrievalConfig = RetrievalConfig()
    agent: AgentConfig = AgentConfig()
    defenses: DefensesConfig = DefensesConfig()
    # /dev/rag/* (plant documents, reset, a {"query"} -> {"answer"} shim) for outside scanners such as
    # rag-redteam. Off everywhere except configs/dev_scanners.yaml: an unauthenticated corpus-write API.
    dev_endpoints: bool = False

    def switches(self) -> dict[str, bool]:
        """Every defense switch by name, staff_filter included."""
        return {**{k: getattr(self.defenses, k) for k in SWITCHES}, "staff_filter": self.retrieval.staff_filter}

    @property
    def mode(self) -> str:
        """'vulnerable' with every defense off, 'hardened' with every one on, 'partial' in between (ablation)."""
        on = self.switches().values()
        return "hardened" if all(on) else "partial" if any(on) else "vulnerable"


def load_config(path: str | Path | None = None) -> Config:
    p = Path(path) if path else DEFAULT_CONFIG
    return Config.model_validate(yaml.safe_load(p.read_text()) or {})


def resolve(path: str) -> str:
    """Repo-relative paths in the config resolve against the repo root, whatever the cwd."""
    if path == ":memory:" or Path(path).is_absolute():
        return path
    return str(ROOT / path)
