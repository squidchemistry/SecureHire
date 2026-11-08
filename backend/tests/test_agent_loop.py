"""Agent loop: step limits, retries, timeouts, checkpoint/resume, leases."""

from __future__ import annotations

import dataclasses
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update

from app.agent.loop import AgentRunner, LeaseLost
from app.agent.registry import TransientToolError
from app.agent.tools import build_registry
from app.config import get_settings
from app.db import session_scope
from app.llm.base import LLMError
from app.llm.mock import MockLLM
from app.models import AgentRun, Document
from app.worker import Worker, claim_next, reap_exhausted
from tests.conftest import ScriptedLLM, analysis_for, get_run, make_run, make_user, run_agent, steps_of


def _patched_registry(tool_name: str, fn):
    reg = build_registry()
    reg._tools[tool_name] = dataclasses.replace(reg.get(tool_name), fn=fn)
    return reg


def _documents_left(user_id: int) -> int:
    with session_scope() as s:
        return len(s.execute(select(Document.id).where(Document.user_id == user_id)).all())


def test_happy_path_produces_an_analysis_and_purges_documents():
    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id) == "succeeded"
    run = get_run(run_id)
    assert run.status == "succeeded" and run.phase == "done" and run.state == {}
    assert run.lease_owner is None and run.finished_at is not None
    a = analysis_for(run_id)
    assert 0 < a.match_score < 100 and a.missing_skills and len(a.prep_plan) == 7 and len(a.questions) == 8
    assert _documents_left(user) == 0


def test_step_limit_ends_the_run(settings_override):
    settings_override(agent_max_steps=3)
    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id) == "failed"
    assert "Step limit reached (3)" in get_run(run_id).error
    assert get_run(run_id).step_count == 3
    assert _documents_left(user) == 0  # purged on failure too


def test_model_that_never_calls_tools_fails_closed():
    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id, ScriptedLLM(["I'm done.", "Really done.", "Done!"])) == "failed"
    assert "consecutive errors" in get_run(run_id).error
    assert [s["status"] for s in steps_of(run_id) if s["kind"] == "llm" and s["status"] != "thinking"] == [
        "no_tool_call"] * 3


def test_llm_errors_are_retried_with_backoff():
    user = make_user("u@example.com")
    run_id = make_run(user)
    llm = ScriptedLLM([LLMError("429"), LLMError("503")])  # then succeeds via the mock
    assert run_agent(run_id, llm) == "succeeded"
    retries = [s for s in steps_of(run_id) if s["status"] == "retrying"]
    assert [r["detail"]["attempt"] for r in retries] == [1, 2]


def test_llm_outage_fails_the_run_after_retries():
    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id, ScriptedLLM([LLMError("down")] * 3)) == "failed"
    assert get_run(run_id).error.startswith("LLM unavailable")


def test_transient_tool_errors_are_retried():
    from app.agent.tools import parse_resume

    attempts = {"n": 0}

    def flaky(args, ctx):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise TransientToolError("upstream hiccup")
        return parse_resume(args, ctx)

    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id, registry=_patched_registry("parse_resume", flaky)) == "succeeded"
    assert attempts["n"] == 3


def test_tool_timeout(settings_override):
    settings_override(agent_tool_timeout_s=0.05, agent_max_retries=1)

    def slow(args, ctx):
        time.sleep(0.3)

    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id, registry=_patched_registry("parse_resume", slow)) == "failed"
    errors = [s for s in steps_of(run_id) if s["status"] == "error"]
    assert errors and "timed out" in errors[0]["detail"]["error"]


def test_unexpected_tool_crash_is_contained():
    def boom(args, ctx):
        raise RuntimeError("secret internal detail")

    user = make_user("u@example.com")
    run_id = make_run(user)
    assert run_agent(run_id, registry=_patched_registry("parse_resume", boom)) == "failed"
    err = [s for s in steps_of(run_id) if s["status"] == "error"][0]["detail"]["error"]
    assert "secret internal detail" not in err


class CrashAfter(MockLLM):
    def __init__(self, n: int) -> None:
        super().__init__()
        self.left = n

    def chat(self, messages, tools=None):
        if self.left == 0:
            raise RuntimeError("worker killed")
        self.left -= 1
        return super().chat(messages, tools)


def test_crashed_run_resumes_from_its_checkpoint():
    user = make_user("u@example.com")
    run_id = make_run(user)
    with pytest.raises(RuntimeError):
        run_agent(run_id, CrashAfter(3), worker_id="worker-a")
    run = get_run(run_id)
    assert run.status == "running" and run.step_count == 3 and "comparison" in run.state["artifacts"]

    with session_scope() as s:  # the lease expires
        s.execute(update(AgentRun).values(lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    assert run_agent(run_id, worker_id="worker-b") == "succeeded"
    tool_ok = [s["tool"] for s in steps_of(run_id) if s["kind"] == "tool" and s["status"] == "ok"]
    assert tool_ok.count("parse_resume") == 1  # not redone
    assert any(s["status"] == "resumed" for s in steps_of(run_id))
    assert get_run(run_id).attempts == 2


def test_a_worker_that_lost_its_lease_cannot_write():
    user = make_user("u@example.com")
    run_id = make_run(user)
    settings = get_settings()
    assert claim_next(settings, "worker-a") == run_id
    with session_scope() as s:
        s.execute(update(AgentRun).values(lease_owner="worker-b"))
    with pytest.raises(LeaseLost):
        AgentRunner(settings, MockLLM(), build_registry(), worker_id="worker-a").process(run_id)


def test_only_one_worker_can_claim_a_run():
    user = make_user("u@example.com")
    run_id = make_run(user)
    settings = get_settings()
    assert claim_next(settings, "a") == run_id
    assert claim_next(settings, "b") is None


def test_runs_that_keep_crashing_are_reaped(settings_override):
    settings_override(worker_max_attempts=1)
    user = make_user("u@example.com")
    run_id = make_run(user)
    with pytest.raises(RuntimeError):
        run_agent(run_id, CrashAfter(0))
    with session_scope() as s:
        s.execute(update(AgentRun).values(lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    assert reap_exhausted(get_settings()) == 1
    run = get_run(run_id)
    assert run.status == "failed" and "Gave up" in run.error
    assert _documents_left(user) == 0


def test_worker_processes_the_queue_in_order():
    user = make_user("u@example.com")
    first, second = make_run(user), make_run(user)
    w = Worker(get_settings(), worker_id="w")
    assert w.run_once() == first
    assert w.run_once() == second
    assert w.run_once() is None
    assert get_run(first).status == get_run(second).status == "succeeded"
