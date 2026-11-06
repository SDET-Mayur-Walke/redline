"""A prompt-injection classifier on user input and on retrieved chunks.

The model is protectai/deberta-v3-base-prompt-injection-v2, a binary SAFE / INJECTION classifier, loaded
lazily through transformers on first use (pip install -e ".[guards]"), so nothing downloads unless the switch
is on. Tests inject a `scorer` instead.

What it is good for: text shaped like an injection ("ignore the above and ..."), in English, in the user
message or inside a retrieved document. What it is not: it sees one text at a time, so an instruction split
across two chunks can pass as two harmless halves; it doesn't know our tools or our policy; and it was trained
on English, so a Hinglish or encoded ask may score low. It is one layer, not the defense.

On a user message a flag ends the turn with a fixed refusal before the agent model runs. On retrieved chunks
a flag drops that chunk from the result the model sees; the rest of the result goes through.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

Scorer = Callable[[Sequence[str]], list[float]]   # texts -> P(injection) each
MAX_TOKENS = 512


def _transformers_scorer(model: str) -> Scorer:
    try:
        from transformers import pipeline
    except ImportError as e:  # pragma: no cover - depends on the optional extra
        raise RuntimeError('injection_classifier needs the guards extra: uv pip install -e ".[guards]"') from e
    clf = pipeline("text-classification", model=model, truncation=True, max_length=MAX_TOKENS, top_k=None)

    def score(texts: Sequence[str]) -> list[float]:
        out = []
        for labels in clf(list(texts)):
            by = {d["label"].upper(): d["score"] for d in labels}
            out.append(float(by.get("INJECTION", 1.0 - by.get("SAFE", 1.0))))
        return out

    return score


class InjectionClassifier:
    def __init__(self, model: str, threshold: float, scorer: Scorer | None = None):
        self.model, self.threshold = model, threshold
        self._scorer = scorer

    def _score(self, texts: Sequence[str]) -> list[float]:
        if self._scorer is None:
            self._scorer = _transformers_scorer(self.model)
        return self._scorer(texts) if texts else []

    def scores(self, texts: Sequence[str]) -> list[float]:
        return self._score([t or "" for t in texts])

    def flagged(self, text: str) -> tuple[bool, float]:
        [p] = self.scores([text])
        return p >= self.threshold, p
