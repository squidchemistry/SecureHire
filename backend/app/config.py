"""Environment-based configuration.

Every knob is read from environment variables (or a local `.env` file) so the
same image runs locally, in CI and on Render. Secrets have dev-only defaults
that are rejected when ENV=production.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SECRETS = {"dev-only-change-me", "dev-only-audit-key", "dev-only-identity-key"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    # --- Database -----------------------------------------------------------
    database_url: str = "sqlite:///./securehire.db"
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_timeout_s: int = 10

    # --- Auth / crypto ------------------------------------------------------
    jwt_secret: str = "dev-only-change-me"  # noqa: S105 - rejected in production
    jwt_ttl_minutes: int = 60
    jwt_issuer: str = "securehire"
    # HMAC key for pseudonymous identifiers in the audit log.
    audit_hmac_key: str = "dev-only-audit-key"
    # HMAC key for the email lookup digest (we never store plaintext emails).
    identity_hmac_key: str = "dev-only-identity-key"

    # --- HTTP ---------------------------------------------------------------
    # Comma-separated list of exact origins, plus an optional regex (e.g. for
    # Vercel preview deployments).
    allowed_origins: str = "http://localhost:5173,http://localhost:8080"
    allowed_origin_regex: str | None = None

    # --- LLM ----------------------------------------------------------------
    # auto = Groq when GROQ_API_KEY is set, otherwise the deterministic mock.
    llm_provider: Literal["auto", "groq", "mock"] = "auto"
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"
    # Tried in order; the next model is used on rate limits / errors.
    groq_models: str = "llama-3.3-70b-versatile,openai/gpt-oss-20b,llama-3.1-8b-instant"
    llm_timeout_s: float = 30.0

    # --- Agent --------------------------------------------------------------
    agent_max_steps: int = 10
    agent_max_calls_per_step: int = 3
    agent_tool_timeout_s: float = 20.0
    agent_max_retries: int = 2
    agent_retry_base_delay_s: float = 0.5
    agent_max_consecutive_errors: int = 3
    # flag   = keep suspicious text (clearly delimited) and record a security event
    # redact = additionally replace suspected instructions before the LLM sees them
    injection_action: Literal["flag", "redact"] = "flag"

    # --- Worker / queue -----------------------------------------------------
    embedded_worker: bool = False
    worker_poll_interval_s: float = 1.0
    worker_lease_s: int = 120
    worker_max_attempts: int = 3

    # --- Limits -------------------------------------------------------------
    max_upload_bytes: int = 2_000_000
    max_jd_chars: int = 20_000
    max_active_runs_per_user: int = 3

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def groq_model_list(self) -> list[str]:
        return [m.strip() for m in self.groq_models.split(",") if m.strip()]

    @property
    def sqlalchemy_url(self) -> str:
        """Normalise provider URLs (Render hands out postgres://...) to psycopg 3."""
        url = self.database_url
        for prefix in ("postgres://", "postgresql://"):
            if url.startswith(prefix):
                return "postgresql+psycopg://" + url[len(prefix):]
        return url

    @property
    def resolved_llm_provider(self) -> str:
        if self.llm_provider == "auto":
            return "groq" if self.groq_api_key else "mock"
        return self.llm_provider

    @model_validator(mode="after")
    def _reject_dev_secrets_in_prod(self) -> Settings:
        if self.env == "production":
            bad = [
                name
                for name in ("jwt_secret", "audit_hmac_key", "identity_hmac_key")
                if getattr(self, name) in _DEV_SECRETS or len(getattr(self, name)) < 32
            ]
            if bad:
                raise ValueError(f"Insecure secrets for production: {', '.join(bad)}")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
