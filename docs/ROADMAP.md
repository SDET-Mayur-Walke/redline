# Roadmap

Each step ends with tests passing (`make check`), a commit, and a push.

## v0.1: the target
- [x] **1. Store**: synthetic Indian e-commerce data generator and database layer, with side-effect logs (outbox, tickets, refunds).
- [x] **2. Knowledge base**: about 30 help-center docs (returns, refunds, shipping, COD, warranty, product guides), customer reviews and return notes, plus a few staff-only docs with planted canary strings.
- [x] **3. Retrieval**: ingestion (keeps doc metadata on purpose: title, author, source), Qdrant dense + BM25 sparse, RRF fusion, cross-encoder rerank, citations.
- [x] **4. Agent**: tool layer, support policy prompt, agent loop over LiteLLM to Ollama, FastAPI (`/chat`, `/reset`, `/effects`), vulnerable mode by default.

## v0.2: the attacks
- [x] **5. Exfil sink**: a local "attacker" HTTP listener that logs every hit.
- [x] **6. Attack library**: about 40 YAML attacks grouped by course module (recon and prompt leaks, indirect injection via docs, reviews and metadata, zero-click exfiltration, excessive agency, filter evasion), tagged with OWASP Top 10 for LLM Applications 2026 (LLMxx:2026) and Agentic Applications 2026 (ASIxx:2026) ids; see `docs/owasp_mapping.md`.
- [x] **7. Runner**: each attack becomes an agentproof `Task` with security graders (`canary_leaked`, `exfil_hit`, `unauthorized_refund`, `cross_customer_access`, ...), N trials, attack success rate with a 95% Wilson interval.
- [x] **8. Baseline**: run everything in vulnerable mode; also garak and rag-redteam against `/chat`. Results in `docs/results/baseline.md`, `garak.md`, `rag_redteam.md`.

## v0.3: the defenses
Build everything first, measure once at the end. Steps 9 and 10 end with smoke checks only; step 11 is the single
full measurement, run on one commit after steps 12 and 13. Order: 9, 10, 12, 13, 11, 14.

- [x] **9. Defense layers**, each behind a config switch: Unicode normalisation, ingestion scanner, spotlighting with a random per-request marker, injection classifier, guard LLM, tool-level authorization (session-scoped orders), refund limits in code, human confirmation for side effects, egress and markdown-image filter, output PII filter. Ends with a smoke check (`docs/results/hardened_smoke.md`), not a measurement.
- [x] **10. Benign suite**: about 40 legitimate support tasks, graded on the final store state, to measure what each defense costs. Ends with a smoke check only.

## v0.4: the showcase
- [x] **12. CI gate**: deterministic canary probes against a stub model; fail the build if attack success regresses.
- [x] **13. Demo**: Streamlit chat with citations, a vulnerable/hardened switch, and a live exfil-sink and outbox panel. See `docs/demo.md`.
- [x] **11. Full measurement** (after 12 and 13, on one commit): the hardened attack run, the benign suite on both configs, and a per-defense ablation (each defense on its own, then all together): attack success, task success, latency. Plan in `docs/results/ablation_plan.md`, results in `docs/results/ablation.md`, rule output in `configs/recommended.yaml`.
- [ ] Follow-up: confirm recommended.yaml on a fresh, independent 3-trial run
- [ ] **14. Write-up**: README results table, threat model, OWASP mapping, "what broke".

## Phase 2 (during the LLMOps bootcamp)
Docker + Trivy, docker compose, Langfuse tracing, MLflow run tracking, Prometheus + Grafana security dashboard,
Helm chart on kind, vLLM / LiteLLM serving, a fine-tuned injection classifier (PEFT), Terraform, Jenkins.
