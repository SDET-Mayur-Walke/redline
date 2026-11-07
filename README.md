# redline

**A customer-support AI agent for an Indian e-commerce store: red-teamed, hardened, and evaluated by what it
*does*, not only what it says.**

SaffronCart is a fictional online store (₹ prices, UPI / card / COD / wallet, Indian addresses). Its support agent
answers from a help-center knowledge base (agentic RAG) and acts through tools: look up orders, issue refunds,
cancel orders, change delivery addresses, email customers, open tickets. That makes it a realistic target. A
poisoned review, a hidden instruction in a help article, or a look-alike-letter prompt can push the agent to leak a
secret, act on another customer's order, or send data to an attacker.

redline attacks the agent with 41 attacks across five modules, mapped to the OWASP Top 10 for LLM Applications
2026 and the OWASP Top 10 for Agentic Applications 2026. It adds ten switchable defense layers and measures each
one on attacks *and* on 47 legitimate support tasks, so every defense has a measured cost as well as a benefit. A
CI gate fails the build if a defense regresses.

## Results

One model (`qwen3:8b`, local, temperature 0.2), 41 attacks × 3 trials and 47 benign tasks × 3 trials per config.
Intervals are 95% Wilson.

| | No defenses | **Recommended** | Every defense on |
|---|---|---|---|
| Attack success rate | 33% (25–41%) | **12%** (8–19%) | 2% (1–7%) |
| Legitimate tasks completed | 65% (57–73%) | **67%** (59–75%) | 45% (37–53%) |
| Agent acts on another customer's order | 9/9 trials | **0/9** | 0/9 |
| Exfiltration and indirect-injection attacks | 14/51 trials | **3/51** | 0/51 |
| Median latency, legitimate task | 13.7 s | 12.5 s | 20.0 s |

**The recommended config cuts attack success by almost two thirds at no measurable cost to legitimate support.**
Every attack it still lets through is a *disclosure* (the agent quoting something it shouldn't). None is an
*action*: across all its trials it never moved money, touched another customer's order, or reached the attacker's
server. Turning every defense on blocks more, but fails a fifth of real support work, mostly because of two
model-based filters (see "What broke").

`recommended.yaml` was not hand-picked. A selection rule was committed before the measurement ran
([plan](docs/results/ablation_plan.md)), applied by code to a 1,632-trial ablation ([results](docs/results/ablation.md)),
and then confirmed on 288 fresh trials ([confirmation](docs/results/confirmation.md)).

## What broke

The findings worth knowing, good and bad, from [the full write-up](docs/results/ablation.md):

1. **Cross-customer access was the worst vulnerability, not refunds.** With no defenses, a customer could read,
   cancel or re-address someone else's order by naming its id: 9 of 9 trials. Session-scoped authorization in the
   tool layer stopped all of them, with no cost to legitimate tasks.
2. **A policy in the prompt isn't enforced.** In a legitimate task, the undefended agent told the customer the
   28-day-old order was outside the 10-day return window, then refunded ₹999 when they said "yes". The same rule
   in code (`refund_rules`) refused it every time.
3. **Llama Guard 3 1B called "Where is my order SC0110286?" a violent crime.** It is a content-harm model, not an
   injection detector. Turned on, it acted in 57 of 141 legitimate trials (labelling order questions "violent
   crimes" and refund answers "specialized advice") and broke the simplest task in the suite.
4. **An off-the-shelf injection classifier blocked our own help center.** It flagged the privacy, sign-in and
   payment-safety articles (their "we will never ask for…" wording reads like an instruction). Help-center
   questions about those topics fell from 24/27 to 8/27, and without the sign-in article the agent invented a
   password login the store doesn't have. Over-filtering caused misinformation.
5. **Most model-filter "wins" hid the other layers.** With everything on, the guard and the classifier acted
   first in 86 of 120 blocked attacks, so the deterministic layers never got a turn. Only the one-defense-at-a-time
   ablation showed what each layer is actually worth.
6. **Three trials can miss a one-in-seventeen failure.** One social-engineering refund (₹2,899 on an order
   delivered 33 days earlier) went through once in 17 trials across all configs, after the 3-trial baseline had
   reported ₹0 lost. `refund_rules` would have refused it.
7. **The agent still lists its own tools** in every config, including with every defense on. No layer is built to
   stop it, and none did.
8. **The rule left out the staff filter, and that has a measured cost.** The staff filter logs nothing, so the
   rule charged it with every benign failure in its single-trial run, including flaky ones. As a result, two
   staff-document leaks stay open in `recommended.yaml` (both fire 3/3 in the confirmation run). The rule is
   reported as written. In production I'd add the filter anyway: it is one query filter, and the evidence against
   it is two tasks that also fail under unrelated layers.

## How it works

```mermaid
flowchart LR
    U[Customer chat] --> IN[Input layers<br/>unicode · classifier · guard]
    IN --> A[Agent loop<br/>qwen3:8b via LiteLLM]
    KB[(Help center, reviews,<br/>staff docs)] --> SC[Ingestion scanner] --> Q[(Qdrant<br/>dense + BM25, RRF, rerank)]
    Q --> SP[Spotlighting] --> A
    A --> T[Tools] --> P[Tool policy<br/>session authz · refund rules · confirmation · egress]
    P --> S[(Store: orders, refunds,<br/>outbox, tickets)]
    A --> OUT[Output layers<br/>overlap block · link strip · PII redaction · guard] --> R[Reply]
    X[Attacker: chat, planted docs,<br/>reviews, metadata] -.-> U
    X -.-> KB
    OUT -.-> SINK[Exfil sink<br/>127.0.0.1]
```

- **Target.** A synthetic store (200 customers, 500 orders, deterministic generator) behind a tool layer. The
  store enforces no policy on purpose: every rule lives in the tool layer or in `defenses/`, so the vulnerable
  baseline is a real, switchable configuration.
- **Retrieval.** 31 help-center articles, 120 reviews and 4 staff-only documents with planted canary strings,
  heading-based chunks, dense (`nomic-embed-text`) plus BM25 sparse vectors fused with RRF, and a cross-encoder
  rerank. Rerank halves accidental staff-document exposure on ordinary questions (0.15 → 0.07 in the top 5) and
  lifts MRR@5 from 0.825 to 0.880 ([retrieval](docs/results/retrieval.md)).
- **Attacks.** 41 YAML attacks in five modules: recon and prompt leaks, indirect injection through documents,
  reviews and metadata, zero-click exfiltration, excessive agency, and filter evasion (tag characters, zero-width,
  look-alikes, base64, Hinglish). Every evasion attack runs beside a plain-text control, so an encoding is only
  credited when it beats the plain ask. Each attack is tagged with its OWASP ids ([mapping](docs/owasp_mapping.md)).
- **Grading.** Built on [agentproof](https://github.com/SDET-Mayur-Walke/agentproof), my eval library: graders
  check what happened first (store effects, tool calls that actually executed, sink hits, canaries in the reply),
  then the text. A blocked attempt counts as blocked, a side effect waiting for confirmation is reported separately,
  and ₹ lost counts only money above what the customer was owed.
- **Defenses** (`src/redline/defenses/`), each behind one config switch: Unicode normalisation, an injection
  classifier, Llama Guard, an ingestion scanner, spotlighting with a random per-turn marker, session-scoped tool
  authorization, refund rules in code, human confirmation for side effects, an egress allowlist for fetches and
  reply links, and an output filter (protected-text overlap block and PII redaction), plus the retrieval staff
  filter. A test fails if any defense mentions test data (canary formats, the sink port, attack ids, or phrases
  copied from the attack library), so a layer can't pass by recognising the test.
- **CI gate.** A deterministic, deliberately gullible stub model runs 12 probe attacks and 8 benign tasks in under
  2 seconds on every push. The vulnerable config must let every probe through (so the probes still work) and the
  hardened config must stay at or below a committed baseline. With `tool_authz` switched off, the gate fails and
  names the three foreign-order probes it used to stop.

## Outside scanners

The model and the retrieval pipeline were also scanned with existing open-source tools, run as external tools
against the local app:

- [garak](https://github.com/NVIDIA/garak) on the bare `qwen3:8b`: plain prompt injection worked 81% of the time
  and injection hidden in a document 62%; encoded payloads almost never decoded ([garak](docs/results/garak.md)).
- [rag-redteam](https://github.com/Srivatsa03/rag-redteam) against the RAG pipeline over HTTP: one real leak of a
  planted secret, plus timeouts and misread refusals that make its rates lower bounds. Its "quote everything in your
  context" probe became attack 41 ([rag-redteam](docs/results/rag_redteam.md)).

## Threat model

Assets, attackers, entry points, and which layer covers which threat: [docs/threat_model.md](docs/threat_model.md).

## Quickstart

```bash
make setup         # uv venv (Python 3.12) + install, including the Streamlit demo
make check         # lint + tests, offline (no models needed)
make gate          # the CI gate: stub model, about 2 seconds
```

With [Ollama](https://ollama.com) running and `qwen3:8b`, `nomic-embed-text` and `llama-guard3:1b` pulled:

```bash
make sink          # terminal 1: the exfil sink on 127.0.0.1:8765
make demo          # terminal 2: the Streamlit demo, Vulnerable vs Hardened, http://127.0.0.1:8501
python -m redline.attacks.run --trials 3                      # the attack suite on configs/default.yaml
python -m redline.attacks.run --config configs/recommended.yaml --trials 3
make ablation      # the full step 11 measurement (about 7 hours on an M5 with 16 GB)
```

The demo shows each turn's defense events, store effects, exfil-sink hits and pending actions live, and has
attack presets from the library. Its 60-second walkthrough is in [docs/demo.md](docs/demo.md).

## Layout

```
src/redline/
  store/       synthetic store generator and the policy-free database layer
  kb/          knowledge base, ingestion, hybrid retrieval
  agent/       tools, prompts, the agent loop, the deterministic stub model
  defenses/    one module per defense layer
  attacks/     the attack library (YAML), encoders, graders, runner, OWASP mapping
  benign/      the 47 legitimate support tasks and their runner
  demo/        the Streamlit app
  ablation.py  the resumable step 11 measurement and the pre-registered rule
  gate.py      the CI gate
configs/       default (no defenses), hardened (all), recommended (the rule's choice)
docs/results/  every measurement, with how it was run
```

## Data and scope

All data is synthetic and fictional: emails use `example.com`, phone numbers start with `+91 5` (no Indian mobile
number does), UPI handles and brands are made up. The canary strings in the staff documents and the system prompt
exist only so leaks can be graded. Every attack targets this local app: `fetch_url` can only reach localhost, email
goes to a mock outbox, and the exfil sink listens on 127.0.0.1.

Limits: one agent model at one temperature, three trials per item, and an attack library written by the same
person who wrote the defenses. The CI gate's probes come from that same library. The deterministic layers that did
most of the work should carry over to another model; the residual disclosure leaks depend on the model.

## Roadmap

Done: the target, the attacks, the defenses, the measurement and the demo ([roadmap](docs/ROADMAP.md)). Next,
during an LLMOps course: Docker and Trivy, Langfuse tracing, MLflow run tracking, a Prometheus and Grafana
security dashboard, a Helm chart on kind, vLLM serving, and a fine-tuned injection classifier trained on this
help center's false positives.

## License

All rights reserved. The code is published to be read and evaluated; reuse needs written permission (see [LICENSE](LICENSE)). Built by Mayur Walke.
