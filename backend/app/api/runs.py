"""Agent runs: create (upload), list, detail, live events (SSE) and per-run audit trail."""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, documents, repositories, samples
from app.api.deps import current_user, limit, run_limiter
from app.config import get_settings
from app.db import get_db, session_scope
from app.models import AgentRun, AuditLog, Document, RunStep, User
from app.security.hashing import audit_ref

router = APIRouter(prefix="/api", tags=["runs"])

_ROLE = re.compile(r"^[A-Za-z0-9 +#./&(),-]{2,80}$")
TERMINAL = {"succeeded", "failed"}


class StepOut(BaseModel):
    seq: int
    kind: str
    tool: str | None
    status: str
    detail: dict[str, Any]
    created_at: datetime


class RunOut(BaseModel):
    id: str
    status: str
    phase: str
    step_count: int
    attempts: int
    target_role: str
    error: str | None
    created_at: datetime
    finished_at: datetime | None
    analysis_id: str | None = None


class RunDetailOut(RunOut):
    steps: list[StepOut]


class RunPage(BaseModel):
    items: list[RunOut]
    next_cursor: str | None


class CreatedOut(BaseModel):
    id: str
    status: str


class SampleIn(BaseModel):
    scenario: Literal["clean", "injection"]
    target_role: str = "Senior Backend Engineer"


def _run_out(db: Session, run: AgentRun, user_id: int) -> dict[str, Any]:
    analysis = repositories.get_analysis_for_run(db, user_id=user_id, run_id=run.id)
    return {
        "id": run.id, "status": run.status, "phase": run.phase, "step_count": run.step_count,
        "attempts": run.attempts, "target_role": (run.options or {}).get("target_role", ""),
        "error": run.error, "created_at": run.created_at, "finished_at": run.finished_at,
        "analysis_id": analysis.id if analysis else None,
    }


def _validate_role(role: str) -> str:
    role = " ".join(role.split())
    if not _ROLE.match(role):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "Target role: 2-80 letters, digits, spaces and + # . / & ( ) , -")
    return role


async def _read_limited(upload: UploadFile, max_bytes: int) -> bytes:
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"File larger than {max_bytes} bytes")
    return data


def _create_run(db: Session, user: User, *, resume: bytes, resume_type: str, jd: bytes, jd_type: str,
                options: dict[str, Any], source: str) -> AgentRun:
    s = get_settings()
    if repositories.count_active_runs(db, user_id=user.id) >= s.max_active_runs_per_user:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"You already have {s.max_active_runs_per_user} analyses in progress")
    resume_doc = Document(user_id=user.id, kind="resume", media_type=resume_type, content=resume)
    jd_doc = Document(user_id=user.id, kind="jd", media_type=jd_type, content=jd)
    db.add_all([resume_doc, jd_doc])
    db.flush()
    run = AgentRun(user_id=user.id, options=options, state={},
                   resume_document_id=resume_doc.id, jd_document_id=jd_doc.id)
    db.add(run)
    db.flush()
    db.add(RunStep(run_id=run.id, seq=1, kind="run", status="queued", detail={"source": source}))
    audit.record(db, event="run.create", user_id=user.id, run_id=run.id, decision="allow", reason=source)
    db.commit()
    return run


@router.post("/runs", response_model=CreatedOut, status_code=status.HTTP_202_ACCEPTED)
async def create_run(
    resume: UploadFile = File(...),
    jd_text: str | None = Form(None),
    jd_file: UploadFile | None = File(None),
    target_role: str = Form("Software Engineer"),
    days: int = Form(7, ge=1, le=30),
    question_count: int = Form(8, ge=1, le=15),
    difficulty: Literal["junior", "mid", "senior", "mixed"] = Form("mixed"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> CreatedOut:
    s = get_settings()
    limit(run_limiter, f"runs:{user.id}")
    role = _validate_role(target_role)

    data = await _read_limited(resume, s.max_upload_bytes)
    try:
        media_type = documents.sniff_media_type(data, resume.filename or "")
        await run_in_threadpool(documents.extract_text, data, media_type)  # fail fast on unreadable files
    except documents.DocumentError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None

    if jd_file is not None and jd_file.filename:
        jd_bytes = await _read_limited(jd_file, s.max_upload_bytes)
        try:
            jd_type = documents.sniff_media_type(jd_bytes, jd_file.filename)
            jd_plain = await run_in_threadpool(documents.extract_text, jd_bytes, jd_type)
        except documents.DocumentError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Job description: {exc}") from None
    elif jd_text and jd_text.strip():
        jd_plain = jd_text.strip()
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Provide a job description (text or file)")
    if len(jd_plain) > s.max_jd_chars:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Job description over {s.max_jd_chars} chars")

    run = _create_run(
        db, user, resume=data, resume_type=media_type, jd=jd_plain.encode(), jd_type="text/plain",
        options={"target_role": role, "days": days, "question_count": question_count, "difficulty": difficulty},
        source="upload",
    )
    return CreatedOut(id=run.id, status=run.status)


@router.post("/runs/sample", response_model=CreatedOut, status_code=status.HTTP_202_ACCEPTED)
def create_sample_run(body: SampleIn, user: User = Depends(current_user), db: Session = Depends(get_db)) -> CreatedOut:
    limit(run_limiter, f"runs:{user.id}")
    run = _create_run(
        db, user, resume=samples.sample_resume(body.scenario), resume_type=documents.PDF,
        jd=samples.JD_TEXT.encode(), jd_type="text/plain",
        options={"target_role": _validate_role(body.target_role), "days": 7, "question_count": 8,
                 "difficulty": "mixed"},
        source=f"sample:{body.scenario}",
    )
    return CreatedOut(id=run.id, status=run.status)


@router.get("/samples/{scenario}.pdf", include_in_schema=False)
def sample_pdf(scenario: str) -> Response:
    if scenario not in samples.SCENARIOS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown sample")
    return Response(samples.sample_resume(scenario), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="sample-{scenario}.pdf"'})


@router.get("/samples")
def list_samples() -> dict[str, Any]:
    return {"scenarios": samples.SCENARIOS, "job_description": samples.JD_TEXT}


@router.get("/runs", response_model=RunPage)
def list_runs(limit_: int = Query(20, alias="limit", ge=1, le=50), cursor: str | None = None,
              user: User = Depends(current_user), db: Session = Depends(get_db)) -> RunPage:
    try:
        rows, nxt = repositories.list_runs(db, user_id=user.id, limit=limit_, cursor=cursor)
    except repositories.BadCursor:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor") from None
    return RunPage(items=[RunOut(**_run_out(db, r, user.id)) for r in rows], next_cursor=nxt)


@router.get("/runs/{run_id}", response_model=RunDetailOut)
def get_run(run_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> RunDetailOut:
    run = repositories.get_run(db, user_id=user.id, run_id=run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
    steps = repositories.steps_after(db, user_id=user.id, run_id=run_id, after_seq=0)
    return RunDetailOut(**_run_out(db, run, user.id), steps=[StepOut.model_validate(st, from_attributes=True)
                                                             for st in steps])


def _poll(user_id: int, run_id: str, after: int) -> tuple[list[dict[str, Any]], str | None]:
    with session_scope() as s:
        run = repositories.get_run(s, user_id=user_id, run_id=run_id)
        if run is None:
            return [], None
        steps = repositories.steps_after(s, user_id=user_id, run_id=run_id, after_seq=after)
        return [StepOut.model_validate(st, from_attributes=True).model_dump(mode="json") for st in steps], run.status


@router.get("/runs/{run_id}/events")
async def run_events(
    run_id: str,
    request: Request,
    after: int = Query(0, ge=0),
    last_event_id: str | None = Header(None),
    user: User = Depends(current_user),
) -> StreamingResponse:
    """Server-Sent Events: one `step` event per timeline entry, then `end`.

    Authenticated with the normal Bearer header (the frontend uses fetch
    streaming, not EventSource), so tokens never appear in URLs or logs.
    Resumable with `Last-Event-ID` / `?after=`.
    """
    user_id = user.id
    if last_event_id and last_event_id.isdigit():
        after = max(after, int(last_event_id))
    first, run_status = await run_in_threadpool(_poll, user_id, run_id, after)
    if run_status is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")

    async def stream():
        nonlocal after, run_status
        steps, deadline, last_beat = first, time.monotonic() + 600, time.monotonic()
        yield "retry: 2000\n\n"
        while True:
            for st in steps:
                after = st["seq"]
                yield f"id: {st['seq']}\nevent: step\ndata: {json.dumps(st)}\n\n"
            if run_status in TERMINAL and not steps:
                yield f"event: end\ndata: {json.dumps({'status': run_status})}\n\n"
                return
            if time.monotonic() > deadline or await request.is_disconnected():
                return
            if time.monotonic() - last_beat > 15:
                last_beat = time.monotonic()
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.4)
            steps, run_status = await run_in_threadpool(_poll, user_id, run_id, after)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


class AuditOut(BaseModel):
    id: int
    ts: datetime
    event: str
    tool: str | None
    decision: str
    reason: str | None
    latency_ms: int | None
    entry_hash: str


@router.get("/runs/{run_id}/audit", response_model=list[AuditOut])
def run_audit(run_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> list[AuditOut]:
    if repositories.get_run(db, user_id=user.id, run_id=run_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
    rows = db.execute(
        select(AuditLog)
        .where(AuditLog.run_ref == audit_ref("run", run_id), AuditLog.actor == audit_ref("user", user.id))
        .order_by(AuditLog.id)
        .limit(500)
    ).scalars()
    return [AuditOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/audit/verify")
def verify_audit(user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    ok, bad = audit.verify_chain(db)
    return {"ok": ok, "first_bad_row": bad}
