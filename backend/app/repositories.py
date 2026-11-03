"""User-scoped data access.

Every function takes `user_id` as a required keyword argument and filters on
it, so a query without an owner cannot be written by accident. A row owned by
someone else is indistinguishable from a missing row (callers return 404).
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import TypeVar

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from app.models import AgentRun, Analysis, Document, RunStep

T = TypeVar("T", Analysis, AgentRun)

MAX_PAGE = 50


class BadCursor(ValueError):
    pass


def encode_cursor(created_at: datetime, row_id: str) -> str:
    return base64.urlsafe_b64encode(f"{created_at.isoformat()}|{row_id}".encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        ts, row_id = base64.urlsafe_b64decode(cursor.encode()).decode().split("|", 1)
        return datetime.fromisoformat(ts), row_id
    except Exception as exc:
        raise BadCursor("invalid cursor") from exc


def _page(session: Session, model: type[T], *, user_id: int, limit: int, cursor: str | None) -> tuple[list[T], str | None]:
    """Keyset pagination on (created_at DESC, id DESC): stable under inserts, no OFFSET scans."""
    limit = max(1, min(limit, MAX_PAGE))
    stmt = select(model).where(model.user_id == user_id)
    if cursor:
        ts, row_id = decode_cursor(cursor)
        if ts.tzinfo is not None and session.get_bind().dialect.name == "sqlite":
            ts = ts.replace(tzinfo=None)
        stmt = stmt.where(or_(model.created_at < ts, and_(model.created_at == ts, model.id < row_id)))
    rows = list(session.execute(stmt.order_by(model.created_at.desc(), model.id.desc()).limit(limit + 1)).scalars())
    next_cursor = encode_cursor(rows[limit - 1].created_at, rows[limit - 1].id) if len(rows) > limit else None
    return rows[:limit], next_cursor


# --- documents --------------------------------------------------------------

def get_document(session: Session, *, user_id: int, document_id: str) -> Document | None:
    return session.execute(
        select(Document).where(Document.id == document_id, Document.user_id == user_id)
    ).scalar_one_or_none()


def purge_documents(session: Session, *, user_id: int, document_ids: list[str]) -> None:
    session.execute(delete(Document).where(Document.user_id == user_id, Document.id.in_(document_ids)))


# --- runs -------------------------------------------------------------------

def get_run(session: Session, *, user_id: int, run_id: str) -> AgentRun | None:
    return session.execute(
        select(AgentRun).where(AgentRun.id == run_id, AgentRun.user_id == user_id)
    ).scalar_one_or_none()


def list_runs(session: Session, *, user_id: int, limit: int, cursor: str | None = None):
    return _page(session, AgentRun, user_id=user_id, limit=limit, cursor=cursor)


def count_active_runs(session: Session, *, user_id: int) -> int:
    return len(session.execute(
        select(AgentRun.id).where(AgentRun.user_id == user_id, AgentRun.status.in_(("queued", "running")))
    ).all())


def steps_after(session: Session, *, user_id: int, run_id: str, after_seq: int) -> list[RunStep]:
    return list(session.execute(
        select(RunStep)
        .join(AgentRun, AgentRun.id == RunStep.run_id)
        .where(RunStep.run_id == run_id, AgentRun.user_id == user_id, RunStep.seq > after_seq)
        .order_by(RunStep.seq)
    ).scalars())


# --- analyses ---------------------------------------------------------------

def list_analyses(session: Session, *, user_id: int, limit: int, cursor: str | None = None):
    return _page(session, Analysis, user_id=user_id, limit=limit, cursor=cursor)


def get_analysis(session: Session, *, user_id: int, analysis_id: str) -> Analysis | None:
    return session.execute(
        select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == user_id)
    ).scalar_one_or_none()


def get_analysis_for_run(session: Session, *, user_id: int, run_id: str) -> Analysis | None:
    return session.execute(
        select(Analysis).where(Analysis.run_id == run_id, Analysis.user_id == user_id)
    ).scalar_one_or_none()
