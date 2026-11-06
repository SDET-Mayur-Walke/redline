# redline: notes for Claude Code

A customer-support agent for a fictional Indian e-commerce store (SaffronCart), red-teamed, hardened and
evaluated by what it does. The plan is in `docs/ROADMAP.md`; work through it one step at a time.

## Rules
- **Our own code only.** Don't copy code from other repositories. Libraries go in `pyproject.toml` as dependencies.
- **Data is synthetic.** Emails `@example.com`, phones `+91 5…`, fictional names. Never real people or brands.
- **Local models only** via Ollama: `qwen3:8b` (agent), `qwen2.5:7b` (judge), `nomic-embed-text`, `llama-guard3:1b`.
  Machine is an M5 with 16 GB RAM: load one big model at a time, keep concurrency at 1.
- **Evals use agentproof** (`from agentproof import ...`): Task, Transcript, ToolCall, graders, run_suite.
  Grade what the agent *did* (tool calls, `Store.effects`) before what it said. LLM judges are non-gating.
- `store.py` enforces no support policy on purpose. Policy lives in the tool layer and in `defenses/`,
  so each defense can be switched off for the vulnerable baseline.
- Attacks only ever target this local app and its mock tools. The exfil sink listens on localhost.

## Workflow
- After each roadmap step: `make check` passes, tick the box in `docs/ROADMAP.md`, commit, push.
- Commit messages: imperative, one line plus a short body if needed.
- Tests stay offline and fast (no Ollama in `pytest`); anything needing a model goes behind a marker or a script.
- Python 3.12, `uv`, `ruff` (line length 120). Match the existing style: short modules, docstrings that explain why.

## Commands
- `make setup`: venv and install
- `make data`: regenerate `data/store.json` and `data/kb/reviews.jsonl` (deterministic; tests check they match)
- `make check`: lint and tests (same as CI)
