"""Privacy chokepoint in front of every LLM call.

Tools already redact what they produce, but this wrapper is the single place
all outbound prompts pass through, so a tool that forgets to redact (or a
future tool) still cannot ship an email address or phone number to a
third-party model. It records what it removed so the agent loop can audit it.
"""

from __future__ import annotations

from typing import Any

from app.llm.base import LLMClient, LLMResponse
from app.security import pii


class PrivacyGuardLLM:
    def __init__(self, inner: LLMClient) -> None:
        self.inner = inner
        self.name = inner.name
        self.supports_generation = inner.supports_generation
        self.redactions: dict[str, int] = {}

    def _scrub(self, text: str) -> str:
        result = pii.redact(text)
        for label, n in result.counts.items():
            self.redactions[label] = self.redactions.get(label, 0) + n
        return result.text

    def pop_redactions(self) -> dict[str, int]:
        out, self.redactions = self.redactions, {}
        return out

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        scrubbed = [
            {**m, "content": self._scrub(m["content"])} if isinstance(m.get("content"), str) else m
            for m in messages
        ]
        return self.inner.chat(scrubbed, tools)

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        return self.inner.complete_json(self._scrub(system), self._scrub(user))
