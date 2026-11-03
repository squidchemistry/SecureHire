from __future__ import annotations

from app.config import Settings, get_settings
from app.llm.base import LLMClient


def build_llm(settings: Settings | None = None) -> LLMClient:
    s = settings or get_settings()
    if s.resolved_llm_provider == "groq":
        if not s.groq_api_key:
            raise RuntimeError("LLM_PROVIDER=groq but GROQ_API_KEY is not set")
        from app.llm.groq import GroqClient

        return GroqClient(s.groq_api_key, s.groq_model_list, s.groq_base_url, s.llm_timeout_s)
    from app.llm.mock import MockLLM

    return MockLLM()
