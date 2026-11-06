"""Where each defense layer plugs into one agent turn. The agent calls four hooks:

    on_user_message  the customer's text, before the model:      unicode -> guard (input) -> classifier
    on_tool_result   every tool result, before the model:        unicode -> classifier (retrieved text only)
    render_tool      the tool message the model reads:           spotlight wrapping (else plain JSON)
    on_reply         the final reply, before the customer:       overlap block -> egress strip -> PII -> guard

Tool-call *authorization* is not here: it runs in the tool layer through ToolPolicy (defenses/policy.py), and
the ingestion scanner runs at index time inside the retriever. A layer whose switch is off is None and its
step is skipped, so the vulnerable config runs exactly the baseline code path.
"""

from __future__ import annotations

from redline.agent.tools import to_json
from redline.config import Config
from redline.defenses import record, spotlight
from redline.defenses.classifier import InjectionClassifier
from redline.defenses.egress import strip_links
from redline.defenses.guard import LlamaGuard
from redline.defenses.output_filter import BLOCKED, OutputFilter
from redline.defenses.unicode import normalize, normalize_tree

REFUSAL = ("Sorry, I can't help with that request. I'm happy to help with your orders, returns, refunds or "
           "delivery.")
RETRIEVED_TOOLS = ("search_help_center", "fetch_url")   # text that came from documents or the web


def protected_documents() -> list[str]:
    """Texts the output filter guards besides the system prompt: every document whose audience isn't public."""
    from redline.kb.corpus import load_corpus

    return [d.text for d in load_corpus(include_staff=True, include_reviews=False)
            if d.metadata.get("audience") != "public"]


class Defenses:
    def __init__(self, cfg: Config, classifier: InjectionClassifier | None = None, guard: LlamaGuard | None = None,
                 store=None, output_filter: OutputFilter | None = None):
        d = cfg.defenses
        self.egress = list(d.egress_allowlist) if d.egress_filter else None
        self.output = output_filter
        if self.output is None and d.output_filter:
            if store is None:
                raise ValueError("output_filter needs the store (whose PII is whose)")
            self.output = OutputFilter(store, protected_documents(), d.overlap_ngram, d.overlap_min_words)
        self.unicode = d.unicode_normalize
        self.classifier = (classifier or InjectionClassifier(d.injection_model, d.injection_threshold)
                           if d.injection_classifier else None)
        self.guard = (guard or LlamaGuard(d.guard_model, cfg.models.ollama_base_url)) if d.guard_llm else None
        self.spotlight = d.spotlight
        self.marker: str | None = None

    def begin_turn(self, base_prompt: str) -> str:
        """The system prompt for this turn. With spotlighting on, a fresh marker and the note that declares it."""
        if not self.spotlight:
            return base_prompt
        self.marker = spotlight.new_marker()
        return base_prompt + spotlight.system_note(self.marker)

    # ----- input -----

    def on_user_message(self, message: str, events: list[dict]) -> tuple[str, str | None]:
        """(text for the model, refusal or None). A refusal ends the turn before the agent model runs."""
        text = message
        if self.unicode:
            n = normalize(message)
            if n.changed:
                record(events, "unicode", "strip", f"user message: {n.removed} invisible, {n.folded} look-alike")
            text = n.text
        if self.guard:
            v = self.guard.check_input(text)
            if v.error:
                record(events, "guard_llm", "error", v.describe())
            elif not v.safe:
                record(events, "guard_llm", "block", f"user message {v.describe()}")
                return text, REFUSAL
        if self.classifier:
            hit, p = self.classifier.flagged(text)
            if hit:
                record(events, "injection_classifier", "block", f"user message P(injection)={p:.2f}")
                return text, REFUSAL
        return text, None

    def on_tool_result(self, name: str, result, events: list[dict]):
        if self.unicode:
            result, removed, folded = normalize_tree(result)
            if removed or folded:
                record(events, "unicode", "strip", f"{name} result: {removed} invisible, {folded} look-alike")
        if self.classifier and name in RETRIEVED_TOOLS:
            result = self._classify_retrieved(name, result, events)
        return result

    def _classify_retrieved(self, name: str, result, events: list[dict]):
        if name == "search_help_center" and isinstance(result, list):
            texts = [" ".join(str(r.get(k) or "") for k in ("title", "author", "text")) for r in result]
            keep = []
            for r, p in zip(result, self.classifier.scores(texts), strict=True):
                if p >= self.classifier.threshold:
                    record(events, "injection_classifier", "drop", f"chunk {r.get('citation')} P={p:.2f}")
                else:
                    keep.append(r)
            return keep
        if name == "fetch_url" and isinstance(result, dict) and result.get("text"):
            hit, p = self.classifier.flagged(result["text"])
            if hit:
                record(events, "injection_classifier", "drop", f"fetched page P={p:.2f}")
                return {**result, "text": "[page text removed: flagged as a prompt injection]"}
        return result

    def render_tool(self, name: str, result) -> str:
        if self.spotlight and self.marker:
            return spotlight.render(name, result, self.marker)
        return to_json(result)

    # ----- output -----

    def on_reply(self, reply: str, message: str, session) -> str:
        """overlap block -> strip unlisted links/images -> redact PII -> guard. `session` gives the customer,
        the rendered system prompt and the event log."""
        events = session.events
        if self.output:
            dump, n = self.output.dumps_protected(reply, session.prompt)
            if dump:
                record(events, "output_filter", "block", f"reply reproduces {n} words of protected text")
                return BLOCKED
        if self.egress is not None:
            reply, removed = strip_links(reply, self.egress)
            if removed:
                record(events, "egress", "strip", f"{len(removed)} link(s)/image(s): {', '.join(removed)[:200]}")
        if self.output:
            reply, n = self.output.redact_pii(reply, session.customer_id)
            if n:
                record(events, "output_filter", "redact", f"{n} value(s) of other customers or support-only")
        if self.guard:
            v = self.guard.check_output(message, reply)
            if v.error:
                record(events, "guard_llm", "error", v.describe())
            elif not v.safe:
                record(events, "guard_llm", "block", f"reply {v.describe()}")
                return REFUSAL
        return reply
