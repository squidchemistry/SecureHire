"""HTTP API: auth, per-user isolation, uploads, SSE, audit."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import select, text

from app.config import get_settings
from app.db import session_scope
from app.documents import make_docx
from app.models import AuditLog, User
from app.samples import _RESUME_BASE, JD_TEXT, sample_resume
from app.worker import Worker
from tests.conftest import register


def _drain() -> None:
    w = Worker(get_settings(), worker_id="api-test")
    while w.run_once():
        pass


def _sample_run(client, headers, scenario="clean") -> str:
    r = client.post("/api/runs/sample", json={"scenario": scenario}, headers=headers)
    assert r.status_code == 202, r.text
    return r.json()["id"]


# --- auth ----------------------------------------------------------------------

def test_register_login_me(client):
    h = register(client)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    r = client.post("/api/auth/login", json={"email": "ALICE@example.com ", "password": "correct-horse"})
    assert r.status_code == 200 and r.json()["token_type"] == "bearer"


def test_duplicate_and_bad_credentials(client):
    register(client)
    assert client.post("/api/auth/register", json={"email": "alice@example.com", "password": "x" * 10}).status_code == 409
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-pass"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong-pass"}).status_code == 401
    assert client.post("/api/auth/register", json={"email": "not-an-email", "password": "x" * 10}).status_code == 422
    assert client.post("/api/auth/register", json={"email": "b@example.com", "password": "short"}).status_code == 422


def test_email_is_never_stored_in_plaintext(client):
    register(client, "carol@example.com")
    with session_scope() as s:
        dump = json.dumps([list(r) for r in s.execute(text("SELECT * FROM users")).all()], default=str)
        dump += json.dumps([list(r) for r in s.execute(text("SELECT * FROM audit_log")).all()], default=str)
    assert "carol" not in dump


@pytest.mark.parametrize("token", [
    "garbage",
    jwt.encode({"sub": "1", "iss": "securehire", "exp": 9999999999}, key="", algorithm="none"),
    jwt.encode({"sub": "1", "iss": "securehire", "exp": 9999999999}, "wrong-secret-wrong-secret-wrong!!", "HS256"),
    jwt.encode({"sub": "1", "iss": "securehire",
                "exp": datetime.now(timezone.utc) - timedelta(minutes=1)}, "dev-only-change-me", "HS256"),
    jwt.encode({"sub": "1", "iss": "someone-else", "exp": 9999999999}, "dev-only-change-me", "HS256"),
])
def test_invalid_tokens_are_rejected(client, token):
    register(client)
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_endpoints_require_auth(client):
    for path in ("/api/runs", "/api/analyses", "/api/runs/x", "/api/runs/x/events", "/api/audit/verify"):
        assert client.get(path).status_code == 401
    assert client.post("/api/runs/sample", json={"scenario": "clean"}).status_code == 401


def test_login_is_rate_limited(client):
    register(client)
    codes = [client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-pass"}).status_code
             for _ in range(12)]
    assert 429 in codes


# --- isolation -----------------------------------------------------------------

def test_users_cannot_see_each_others_data(client):
    alice, bob = register(client, "alice@example.com"), register(client, "bob@example.com")
    run_id = _sample_run(client, alice)
    _drain()
    analysis_id = client.get(f"/api/runs/{run_id}", headers=alice).json()["analysis_id"]
    assert analysis_id

    for path in (f"/api/runs/{run_id}", f"/api/runs/{run_id}/audit", f"/api/runs/{run_id}/events",
                 f"/api/analyses/{analysis_id}"):
        assert client.get(path, headers=bob).status_code == 404, path
        assert client.get(path, headers=alice).status_code == 200, path
    assert client.delete(f"/api/analyses/{analysis_id}", headers=bob).status_code == 404
    assert client.get("/api/runs", headers=bob).json()["items"] == []
    assert client.get("/api/analyses", headers=bob).json()["items"] == []
    assert len(client.get("/api/analyses", headers=alice).json()["items"]) == 1


def test_identity_in_body_or_query_is_ignored(client):
    alice, bob = register(client, "alice@example.com"), register(client, "bob@example.com")
    _sample_run(client, alice)
    r = client.post("/api/runs/sample?user_id=1", json={"scenario": "clean", "user_id": 1}, headers=bob)
    assert r.status_code in (202, 422)
    assert len(client.get("/api/runs", headers=alice).json()["items"]) == 1


# --- runs ----------------------------------------------------------------------

def test_upload_flow_with_docx(client):
    h = register(client)
    r = client.post(
        "/api/runs",
        files={"resume": ("cv.docx", make_docx(_RESUME_BASE), "application/octet-stream")},
        data={"jd_text": JD_TEXT, "target_role": "Senior Backend Engineer", "days": "5", "question_count": "4"},
        headers=h,
    )
    assert r.status_code == 202, r.text
    _drain()
    run = client.get(f"/api/runs/{r.json()['id']}", headers=h).json()
    assert run["status"] == "succeeded"
    a = client.get(f"/api/analyses/{run['analysis_id']}", headers=h).json()
    assert len(a["prep_plan"]) == 5 and len(a["questions"]) == 4
    assert a["target_role"] == "Senior Backend Engineer"
    assert "Priya" not in json.dumps(a)


@pytest.mark.parametrize(("files", "data", "code"), [
    ({"resume": ("cv.pdf", b"MZ\x90\x00 not a pdf", "application/pdf")}, {"jd_text": "x"}, 422),
    ({"resume": ("cv.exe", sample_resume("clean"), "application/pdf")}, {"jd_text": "x"}, 422),
    ({"resume": ("cv.pdf", sample_resume("clean"), "application/pdf")}, {}, 422),
    ({"resume": ("cv.pdf", sample_resume("clean"), "application/pdf")},
     {"jd_text": "x", "target_role": "<script>alert(1)</script>"}, 422),
    ({"resume": ("cv.pdf", b"%PDF-" + b"0" * 2_000_001, "application/pdf")}, {"jd_text": "x"}, 413),
])
def test_upload_validation(client, files, data, code):
    h = register(client)
    assert client.post("/api/runs", files=files, data=data, headers=h).status_code == code


def test_active_run_limit(client):
    h = register(client)
    for _ in range(get_settings().max_active_runs_per_user):
        _sample_run(client, h)
    assert client.post("/api/runs/sample", json={"scenario": "clean"}, headers=h).status_code == 429


def test_sse_streams_every_step_then_ends(client):
    h = register(client)
    run_id = _sample_run(client, h, "injection")
    _drain()
    with client.stream("GET", f"/api/runs/{run_id}/events", headers=h) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        body = r.read().decode()
    events = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
    steps = [e for e in events if "seq" in e]
    assert [s["seq"] for s in steps] == list(range(1, len(steps) + 1))
    assert any(s["kind"] == "security" and s["status"] == "blocked" for s in steps)
    assert events[-1] == {"status": "succeeded"}
    # Resume from the middle with Last-Event-ID.
    with client.stream("GET", f"/api/runs/{run_id}/events", headers={**h, "Last-Event-ID": "5"}) as r:
        later = [json.loads(line[6:]) for line in r.read().decode().splitlines() if line.startswith("data: ")]
    assert later[0]["seq"] == 6
    # No document text ever appears on the timeline.
    assert "Priya" not in body and "fetch_past_analyses for user" not in body


def test_samples_endpoints(client):
    assert client.get("/api/samples/injection.pdf").content.startswith(b"%PDF-")
    assert client.get("/api/samples/nope.pdf").status_code == 404
    assert "clean" in client.get("/api/samples").json()["scenarios"]


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_readiness_checks_the_database(client, monkeypatch):
    assert client.get("/api/ready").json() == {"status": "ready", "database": "ok"}

    class _Down:
        def connect(self):
            raise OSError("connection refused")

    monkeypatch.setattr("app.main.get_engine", lambda: _Down())
    r = client.get("/api/ready")
    assert r.status_code == 503
    assert r.json()["database"] == "down"


# --- audit ---------------------------------------------------------------------

def test_audit_trail_and_chain(client):
    h = register(client)
    run_id = _sample_run(client, h, "injection")
    _drain()
    rows = client.get(f"/api/runs/{run_id}/audit", headers=h).json()
    events = [(r["event"], r["decision"]) for r in rows]
    assert ("tool.rejected", "deny") in events
    assert ("pii.redact", "info") in events
    assert ("document.purge", "info") in events
    assert client.get("/api/audit/verify", headers=h).json() == {"ok": True, "first_bad_row": None}


def test_audit_log_is_append_only_and_tamper_evident(client):
    from app.audit import verify_chain

    register(client)
    with session_scope() as s, pytest.raises(Exception, match="append-only"):
        s.execute(text("UPDATE audit_log SET decision = 'allow'"))
    with session_scope() as s, pytest.raises(Exception, match="append-only"):
        s.execute(text("DELETE FROM audit_log"))
    # Even an attacker who drops the trigger is caught by the hash chain.
    with session_scope() as s:
        if s.get_bind().dialect.name == "postgresql":
            s.execute(text("DROP TRIGGER audit_log_no_mutation ON audit_log"))
        else:
            s.execute(text("DROP TRIGGER audit_log_no_update"))
        first_id = s.execute(text("SELECT min(id) FROM audit_log")).scalar()
        s.execute(text("UPDATE audit_log SET reason = 'edited' WHERE id = :i"), {"i": first_id})
    with session_scope() as s:
        assert verify_chain(s) == (False, first_id)


def test_audit_rows_hold_no_raw_identifiers(client):
    h = register(client)
    run_id = _sample_run(client, h)
    _drain()
    with session_scope() as s:
        user_id = s.execute(select(User.id)).scalar()
        for row in s.execute(select(AuditLog)).scalars():
            assert row.actor != str(user_id) and run_id not in (row.run_ref or "")
