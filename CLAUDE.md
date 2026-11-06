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
- Commits are authored by Mayur Walke (repo git config). Do not add `Co-Authored-By` or any other attribution
  trailer or "Generated with" line to commits or pull requests.
- Never override git identity (`-c user.name`, `-c user.email`, `--author`): the repo config uses the GitHub
  noreply email on purpose, so no personal email lands in the history.
- Before every commit run `make check` and read its real exit code; never pipe it through `tail` or `head`.
- Tests stay offline and fast (no Ollama in `pytest`); anything needing a model goes behind a marker or a script.
- Python 3.12, `uv`, `ruff` (line length 120). Match the existing style: short modules, docstrings that explain why.

## Commands
- `make setup`: venv and install
- `make data`: regenerate `data/store.json` and `data/kb/reviews.jsonl` (deterministic; tests check they match)
- `make check`: lint and tests (same as CI)
