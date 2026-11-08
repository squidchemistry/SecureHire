from __future__ import annotations

import os

os.environ.update({
    "ENV": "test",
    "LLM_PROVIDER": "mock",
    "EMBEDDED_WORKER": "false",
    "AGENT_RETRY_BASE_DELAY_S": "0",
    "GROQ_API_KEY": "",
})

import json  # noqa: E402
import uuid  # noqa: E402
from collections.abc import Callable, Iterator  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.agent.loop import AgentRunner  # noqa: E402
from app.agent.tools import build_registry  # noqa: E402
from app.api.deps import auth_limiter, run_limiter  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import get_engine, get_sessionmaker, init_db, session_scope  # noqa: E402
from app.llm.base import LLMResponse, ToolCall  # noqa: E402
from app.llm.mock import MockLLM  # noqa: E402
from app.models import AgentRun, Analysis, User  # noqa: E402
from app.samples import JD_TEXT, sample_resume  # noqa: E402
from app.security.auth import hash_password  # noqa: E402
from app.security.hashing import email_digest  # noqa: E402
from app.worker import claim_next  # noqa: E402


def _reset_caches() -> None:
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


@pytest.fixture(autouse=True)
def database(tmp_path, monkeypatch) -> Iterator[None]:
    """Fresh database per test: a temp SQLite file, or a wiped Postgres when TEST_DATABASE_URL is set."""
    pg_url = os.environ.get("TEST_DATABASE_URL")
    monkeypatch.setenv("DATABASE_URL", pg_url or f"sqlite:///{tmp_path.as_posix()}/test.db")
    _reset_caches()
    if pg_url:
        from sqlalchemy import text

        with get_engine().begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    init_db()
    auth_limiter.reset()
    run_limiter.reset()
    yield
    get_engine().dispose()
    _reset_caches()


@pytest.fixture
def settings_override(monkeypatch) -> Callable[..., None]:
    def apply(**values: Any) -> None:
        for k, v in values.items():
            monkeypatch.setenv(k.upper(), str(v))
        get_settings.cache_clear()

    return apply


@pytest.fixture
def client() -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def register(client: TestClient, email: str = "alice@example.com", password: str = "correct-horse") -> dict:
    r = client.post("/api/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_user(email: str) -> int:
    with session_scope() as s:
        u = User(email_digest=email_digest(email), password_hash=hash_password("irrelevant-pw"))
        s.add(u)
        s.flush()
        return u.id


def make_run(user_id: int, *, resume: bytes | None = None, jd: str = JD_TEXT, scenario: str = "clean",
             options: dict | None = None) -> str:
    from app.models import Document

    with session_scope() as s:
        rd = Document(user_id=user_id, kind="resume", media_type="application/pdf",
                      content=resume or sample_resume(scenario))
        jd_doc = Document(user_id=user_id, kind="jd", media_type="text/plain", content=jd.encode())
        s.add_all([rd, jd_doc])
        s.flush()
        run = AgentRun(user_id=user_id, options=options or {"target_role": "Backend Engineer"},
                       resume_document_id=rd.id, jd_document_id=jd_doc.id)
        s.add(run)
        s.flush()
        return run.id


def add_analysis(user_id: int, role: str, missing: list[str]) -> None:
    with session_scope() as s:
        s.add(Analysis(user_id=user_id, run_id=str(uuid.uuid4()), target_role=role,
                       match_score=10.0, matched_skills=[], missing_skills=missing, prep_plan=[], questions=[],
                       summary="secret"))


class RecordingLLM:
    """Wraps another client and records everything it is sent."""

    def __init__(self, inner: Any | None = None) -> None:
        self.inner = inner or MockLLM()
        self.name = "recording"
        self.supports_generation = getattr(self.inner, "supports_generation", False)
        self.sent: list[str] = []

    def chat(self, messages, tools=None) -> LLMResponse:
        self.sent.append(json.dumps(messages))
        return self.inner.chat(messages, tools)

    def complete_json(self, system, user):
        self.sent.append(system + user)
        return self.inner.complete_json(system, user)


class ScriptedLLM:
    """Plays back a fixed list of responses (tool calls as (name, args) tuples), then follows the mock."""

    name = "scripted"
    supports_generation = False

    def __init__(self, script: list[list[tuple[str, Any]] | str | Exception]) -> None:
        self.script = list(script)
        self.fallback = MockLLM()
        self.n = 0

    def chat(self, messages, tools=None) -> LLMResponse:
        if not self.script:
            return self.fallback.chat(messages, tools)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, str):
            return LLMResponse(item, [], self.name)
        calls = []
        for name, args in item:
            self.n += 1
            raw = args if isinstance(args, str) else json.dumps(args)
            calls.append(ToolCall(f"call_{self.n}", name, raw))
        return LLMResponse(None, calls, self.name)

    def complete_json(self, system, user):  # pragma: no cover
        raise NotImplementedError


def run_agent(run_id: str, llm: Any | None = None, registry=None, worker_id: str = "test-worker") -> str:
    settings = get_settings()
    assert claim_next(settings, worker_id) == run_id
    runner = AgentRunner(settings, llm or MockLLM(), registry or build_registry(), worker_id=worker_id)
    return runner.process(run_id)


def steps_of(run_id: str) -> list[dict]:
    from sqlalchemy import select

    from app.models import RunStep

    with session_scope() as s:
        return [
            {"kind": r.kind, "tool": r.tool, "status": r.status, "detail": r.detail}
            for r in s.execute(select(RunStep).where(RunStep.run_id == run_id).order_by(RunStep.seq)).scalars()
        ]


def get_run(run_id: str) -> AgentRun:
    with session_scope() as s:
        return s.get(AgentRun, run_id)


def analysis_for(run_id: str) -> Analysis | None:
    from sqlalchemy import select

    with session_scope() as s:
        return s.execute(select(Analysis).where(Analysis.run_id == run_id)).scalar_one_or_none()
