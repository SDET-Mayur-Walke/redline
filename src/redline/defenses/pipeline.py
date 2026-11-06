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
from redline.defenses import record
from redline.defenses.classifier import InjectionClassifier
from redline.defenses.guard import LlamaGuard
from redline.defenses.unicode import normalize, normalize_tree

REFUSAL = ("Sorry, I can't help with that request. I'm happy to help with your orders, returns, refunds or "
           "delivery.")
RETRIEVED_TOOLS = ("search_help_center", "fetch_url")   # text that came from documents or the web


class Defenses:
    def __init__(self, cfg: Config, classifier: InjectionClassifier | None = None, guard: LlamaGuard | None = None):
        d = cfg.defenses
        self.unicode = d.unicode_normalize
        self.classifier = (classifier or InjectionClassifier(d.injection_model, d.injection_threshold)
                           if d.injection_classifier else None)
        self.guard = (guard or LlamaGuard(d.guard_model, cfg.models.ollama_base_url)) if d.guard_llm else None

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
        return to_json(result)

    # ----- output -----

    def on_reply(self, reply: str, message: str, events: list[dict]) -> str:
        if self.guard:
            v = self.guard.check_output(message, reply)
            if v.error:
                record(events, "guard_llm", "error", v.describe())
            elif not v.safe:
                record(events, "guard_llm", "block", f"reply {v.describe()}")
                return REFUSAL
        return reply
