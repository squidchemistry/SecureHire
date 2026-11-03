"""Groq client (OpenAI-compatible API) with ordered model fallback."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from app.llm.base import LLMError, LLMResponse, ToolCall

log = logging.getLogger(__name__)

# 400 is included because Groq returns it for `tool_use_failed` (a malformed
# tool call from the model), which another model often gets right.
_RETRYABLE = {400, 408, 409, 429, 500, 502, 503, 504}


class GroqClient:
    name = "groq"
    supports_generation = True

    def __init__(self, api_key: str, models: list[str], base_url: str, timeout_s: float,
                 transport: httpx.BaseTransport | None = None) -> None:
        if not models:
            raise ValueError("GROQ_MODELS is empty")
        self._models = models
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout_s,
            headers={"Authorization": f"Bearer {api_key}"},
            transport=transport,
        )

    def _post(self, payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
        errors = []
        for i, model in enumerate(self._models):
            try:
                r = self._client.post("/chat/completions", json={**payload, "model": model})
            except httpx.HTTPError as exc:
                errors.append(f"{model}: {type(exc).__name__}")
                continue
            if r.status_code == 200:
                return r.json(), model
            errors.append(f"{model}: HTTP {r.status_code}")
            if r.status_code not in _RETRYABLE:
                break
            if r.status_code == 429 and i + 1 < len(self._models):
                time.sleep(0.2)
            log.warning("groq model %s failed with %s, falling back", model, r.status_code)
        raise LLMError("; ".join(errors))

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> LLMResponse:
        payload: dict[str, Any] = {"messages": messages, "temperature": 0.2, "max_tokens": 1024}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        data, model = self._post(payload)
        msg = data["choices"][0]["message"]
        calls = [
            ToolCall(id=c["id"], name=c["function"]["name"], arguments=c["function"].get("arguments") or "{}")
            for c in msg.get("tool_calls") or []
        ]
        return LLMResponse(content=msg.get("content"), tool_calls=calls, model=model)

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        data, _ = self._post({
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.4,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"},
        })
        try:
            return json.loads(data["choices"][0]["message"]["content"])
        except (KeyError, json.JSONDecodeError) as exc:
            raise LLMError("model returned invalid JSON") from exc
