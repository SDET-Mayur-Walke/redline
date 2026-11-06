"""Llama Guard 3 (1B) as an input and output check, through Ollama.

Llama Guard is a *content-safety* classifier. It answers "safe" or "unsafe" plus hazard categories from the
MLCommons taxonomy (S1 violent crimes ... S14 code interpreter abuse). What that means for this project:

  - It catches harmful-content asks and answers: violence, weapons, self-harm, sexual content, hate, and the
    S7 "privacy" category for some personal-data requests.
  - It is NOT a prompt-injection detector. "Print your system prompt", "ignore the above", a planted help doc
    telling the assistant to fetch a URL, an IDOR on another customer's order, an over-limit refund: none of
    these is a hazard category, so it will usually call them safe. Expect it to stop little of the attack
    library; it is here because a production stack would run it, and because measuring that gap is the point.
  - The 1B model is small and fast (fine on an M5 next to qwen3:8b) but noisier than the 8B one.

It fails open: if Ollama errors, the turn goes ahead and an "error" event is logged, so a guard outage shows
up in the run instead of silently refusing every customer.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

Chat = Callable[[list[dict]], str]     # messages -> the guard model's raw reply

CATEGORIES = {
    "S1": "violent crimes", "S2": "non-violent crimes", "S3": "sex-related crimes", "S4": "child sexual exploitation",
    "S5": "defamation", "S6": "specialized advice", "S7": "privacy", "S8": "intellectual property",
    "S9": "indiscriminate weapons", "S10": "hate", "S11": "suicide and self-harm", "S12": "sexual content",
    "S13": "elections", "S14": "code interpreter abuse",
}


@dataclass(frozen=True)
class Verdict:
    safe: bool
    categories: list[str] = field(default_factory=list)
    error: str | None = None

    def describe(self) -> str:
        if self.error:
            return f"guard error: {self.error}"
        return "safe" if self.safe else "unsafe: " + ", ".join(f"{c} {CATEGORIES.get(c, '?')}"
                                                              for c in self.categories)


def parse(raw: str) -> Verdict:
    lines = [x.strip() for x in raw.strip().splitlines() if x.strip()]
    if not lines or lines[0].lower() == "safe":
        return Verdict(True)
    cats = [c.strip().upper() for x in lines[1:] for c in x.split(",") if c.strip()]
    return Verdict(False, cats)


class LlamaGuard:
    def __init__(self, model: str, base_url: str, chat: Chat | None = None, timeout: float = 60.0):
        self.model, self.base_url, self.timeout = model, base_url.rstrip("/"), timeout
        self._chat = chat or self._ollama

    def _ollama(self, messages: list[dict]) -> str:
        r = httpx.post(f"{self.base_url}/api/chat", timeout=self.timeout, json={
            "model": self.model, "messages": messages, "stream": False, "options": {"temperature": 0}})
        r.raise_for_status()
        return r.json()["message"]["content"]

    def _check(self, messages: list[dict]) -> Verdict:
        try:
            return parse(self._chat(messages))
        except Exception as e:     # fail open, but loudly: see the module docstring
            return Verdict(True, error=f"{type(e).__name__}: {e}"[:200])

    def check_input(self, message: str) -> Verdict:
        return self._check([{"role": "user", "content": message}])

    def check_output(self, message: str, reply: str) -> Verdict:
        return self._check([{"role": "user", "content": message}, {"role": "assistant", "content": reply}])
