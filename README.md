# redline

**A customer-support AI agent for an Indian e-commerce store, attacked, hardened, and evaluated by what it *does*.**

SaffronCart is a fictional online store (₹ prices, UPI / card / COD / wallet, Indian addresses). Its support agent
answers from a help-center knowledge base (RAG) and acts through tools: look up orders, issue refunds, cancel
orders, change addresses, email customers, open tickets.

That makes it a realistic target. A poisoned product review, a hidden instruction in a return note, or a
Unicode-smuggled prompt can push the agent to refund the wrong person, leak another customer's address, or
send data to an attacker. redline measures how often that happens, adds defenses one at a time, and proves
each one with repeated, graded trials, gated in CI.

> Status: **work in progress.** See [the roadmap](docs/ROADMAP.md).

## Quickstart

```bash
make setup     # uv venv (Python 3.12) + install
make data      # regenerate the synthetic store (deterministic)
make check     # lint + tests
```

Models run locally through [Ollama](https://ollama.com): `qwen3:8b` (agent), `qwen2.5:7b` (judge),
`nomic-embed-text` (embeddings), `llama-guard3:1b` (guard).

## Layout

```
src/redline/
  store/       synthetic store data (generate.py) and the database layer (store.py)
  kb/          help-center documents, reviews, ingestion and hybrid retrieval
  agent/       the support agent: tools, policy prompt, agent loop
  defenses/    defense layers, each one switchable for the ablation
  attacks/     attack library (YAML) and the red-team runner
data/          store.json and the knowledge base
tests/
```

## Data

All data is synthetic and fictional: emails use `example.com`, phone numbers start with `+91 5` (no Indian mobile
number does), and names and addresses are random combinations.

## License

MIT
