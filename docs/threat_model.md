# Threat model

The SaffronCart support agent talks to customers, reads a knowledge base, and holds store-wide tool privileges. The
question for every threat below is the same: what can an attacker make the agent *do* or *disclose*, and which
layer stops it. Measured results are in [ablation.md](results/ablation.md) and
[confirmation.md](results/confirmation.md).

## Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Money | refunds, goodwill credit, payment-method changes | `issue_refund` and the store's refund log |
| Other customers' data | emails, phones, addresses, UPI ids, order history | the store, reachable through `get_order`, `list_my_orders`, `get_my_profile` |
| Order integrity | cancellations and delivery-address changes (parcel theft) | `cancel_order`, `update_order_address` |
| Staff-only knowledge | escalation thresholds, fraud playbooks, override procedures | 4 staff documents in the knowledge base (with canaries) |
| Support-only notes | `internal_notes` on customer records | the store's CRM record |
| Hidden context | the system prompt (with a canary) and the tool list | the agent's prompt |
| Outbound channels | email, `fetch_url`, links and images rendered in replies | mock outbox, localhost-only fetch, the chat client |

## Attackers

1. **A malicious customer in the chat.** Authenticated as one customer, they type the attack themselves: prompt
   leaks, foreign order ids, social engineering ("I'm Priya from escalations"), encoded instructions.
2. **A third party who can write content the agent retrieves.** A product review, a help-center page, a return note
   or document metadata, with instructions hidden in it (indirect prompt injection). The victim is the honest
   customer whose chat retrieves it.
3. **The model itself, failing on its own.** No attacker: the agent misapplies a policy, makes up a procedure, or
   acts without asking. The benign suite measures this.

Out of scope: a compromised host, the model supply chain and training data, denial of service, and multi-agent
setups. There is one agent, no code execution, and no fine-tuning step.

## Trust boundaries and entry points

```
customer chat ──▶ [input layers] ──▶ agent ◀── [spotlighting] ◀── retrieval ◀── [ingestion scanner] ◀── documents
                                      │
                                      ├──▶ [tool policy] ──▶ store, outbox, fetch_url
                                      │
                                      └──▶ [output layers] ──▶ reply rendered as markdown in the chat client
```

- Everything entering the model is untrusted except the system prompt: the customer's message, every retrieved
  chunk, and every tool result.
- The tool layer is the boundary that matters most. The model decides *what* to call; the policy decides whether it
  may. The store itself enforces nothing, on purpose, so the baseline is honestly vulnerable.
- The reply is an output channel too. A chat client that renders markdown fetches images with no click, so an image
  URL can carry data out.

## Threats and controls

| Threat | OWASP 2026 | Example attack | Control | Kind |
|---|---|---|---|---|
| Acting on another customer's order | LLM03, ASI02, ASI03 | `ea-change-foreign-address` | `tool_authz`: orders and email recipients must belong to the session customer | deterministic |
| Refund outside policy | LLM03, ASI02 | `ea-refund-over-limit`, social-engineering refund | `refund_rules`: limit, window, amount owed, original method, in code | deterministic |
| Side effect without the customer's consent | LLM03, ASI02, ASI09 | double refund, injected cancellation | `confirm_side_effects`: only an explicit confirm from the caller executes | deterministic |
| Instructions planted in retrieved content | LLM01, LLM09, ASI01, ASI06 | `ii-hidden-html-comment`, `ii-split-across-chunks` | `ingestion_scanner` at index time; `spotlight` marks retrieved text as data | rules / prompt |
| Zero-click exfiltration through the reply | LLM10, LLM02 | `exf-markdown-image-pixel` | `egress_filter`: fetches and reply links/images only to allowlisted host:port | deterministic |
| Data sent out through a fetch | LLM02, ASI02 | `exf-fetch-query-data` | `egress_filter` on `fetch_url`, scanner on the planted page | deterministic |
| Other customers' PII in a reply | LLM02 | `exf-foreign-pii-guessed-order` | `tool_authz` first; `output_filter` redacts foreign PII using the store | deterministic |
| System-prompt or staff-document dump | LLM08, LLM02 | `rec-sysprompt-direct` | `output_filter` blocks replies with long n-gram overlap with protected text; `staff_filter` keeps staff docs out of retrieval | deterministic |
| Encoded or smuggled instructions | LLM01 | tag characters, look-alikes, zero-width | `unicode_normalize` in front of text-matching filters | deterministic |
| Direct prompt injection | LLM01, ASI01 | role-play, "ignore your instructions" | `injection_classifier`, `guard_llm` | model-based |

## What the measurement says about the controls

- **The deterministic controls carried the action-level threats.** In the confirmation run of `recommended.yaml`,
  excessive agency and indirect injection went to 0% attack success, with no measurable cost to legitimate tasks.
- **The model-based controls were the costly ones.** Llama Guard 3 1B and the off-the-shelf injection classifier
  blocked many attacks but broke legitimate support (order questions labelled "violent crimes", our own help center
  flagged as injection). They are left out of `recommended.yaml` by the pre-registered rule.
- **Residual risk is disclosure.** With `recommended.yaml`, five attacks still work, and all are things the agent
  *says*: a single-token system-prompt canary (via look-alike letters or Hinglish), two staff-document leaks
  (`staff_filter` would cover these, see the README), and the tool list. None moves money, touches another
  customer's data, or reaches the exfil sink.
- **Not measured:** attacks the library doesn't contain. The attack library and the defenses were written by the
  same person, and the CI gate's probes come from the same library. A held-out attack set is the obvious next test.
