"""Append-only, hash-chained audit log.

Every row stores `entry_hash = sha256(prev_hash || canonical(row))`, so any
edit or deletion that slipped past the database triggers breaks the chain and
is caught by `verify_chain()`. Identifiers are HMAC references, never raw ids.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.security.hashing import audit_ref

GENESIS = "0" * 64


def _entry_hash(prev_hash: str, fields: dict) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _hashed_fields(row: AuditLog) -> dict:
    # SQLite returns naive datetimes, Postgres aware ones in the session zone.
    ts = row.ts if row.ts.tzinfo else row.ts.replace(tzinfo=timezone.utc)
    return {
        "ts": ts.astimezone(timezone.utc).isoformat(),
        "event": row.event,
        "actor": row.actor,
        "run_ref": row.run_ref,
        "tool": row.tool,
        "decision": row.decision,
        "reason": row.reason,
        "args_digest": row.args_digest,
        "latency_ms": row.latency_ms,
    }


def record(
    session: Session,
    *,
    event: str,
    user_id: int,
    decision: str,
    run_id: str | None = None,
    tool: str | None = None,
    reason: str | None = None,
    args_digest: str | None = None,
    latency_ms: int | None = None,
) -> AuditLog:
    """Append one audit row inside the caller's transaction."""
    if session.get_bind().dialect.name == "postgresql":
        # Serialise appends so the chain stays linear across workers.
        session.execute(text("SELECT pg_advisory_xact_lock(727275)"))
    prev = session.execute(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
    row = AuditLog(
        ts=datetime.now(timezone.utc).replace(microsecond=0),
        event=event,
        actor=audit_ref("user", user_id),
        run_ref=audit_ref("run", run_id) if run_id else None,
        tool=tool,
        decision=decision,
        reason=(reason or None) and reason[:120],
        args_digest=args_digest,
        latency_ms=latency_ms,
        prev_hash=prev or GENESIS,
    )
    row.entry_hash = _entry_hash(row.prev_hash, _hashed_fields(row))
    session.add(row)
    session.flush()
    return row


def verify_chain(session: Session) -> tuple[bool, int | None]:
    """Return (ok, id_of_first_bad_row)."""
    prev = GENESIS
    for row in session.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        if row.prev_hash != prev or row.entry_hash != _entry_hash(prev, _hashed_fields(row)):
            return False, row.id
        prev = row.entry_hash
    return True, None


if __name__ == "__main__":  # python -m app.audit
    from app.db import session_scope

    with session_scope() as s:
        ok, bad = verify_chain(s)
        print("audit chain OK" if ok else f"audit chain BROKEN at row {bad}")
        raise SystemExit(0 if ok else 1)
