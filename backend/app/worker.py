"""Background worker: a Postgres/SQLite-backed job queue with leases.

Claiming is a single conditional UPDATE (`... WHERE id = ? AND claimable`),
so two workers can never own the same run: exactly one UPDATE matches. A
worker that dies stops renewing its lease; once the lease expires another
worker re-claims the run and resumes from the last checkpoint. Runs that
exhaust `worker_max_attempts` are failed and their documents purged.

Run standalone with `python -m app.worker`, or set EMBEDDED_WORKER=true to
run it as a thread inside the API process.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_, select, update

from app import audit, repositories
from app.agent.loop import AgentRunner, LeaseLost
from app.agent.tools import build_registry
from app.config import Settings, get_settings
from app.db import init_db, session_scope
from app.llm import build_llm
from app.models import AgentRun, RunStep

log = logging.getLogger("securehire.worker")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _claimable(now: datetime):
    return or_(
        AgentRun.status == "queued",
        and_(AgentRun.status == "running", AgentRun.lease_expires_at < now),
    )


def reap_exhausted(settings: Settings) -> int:
    """Fail runs whose lease expired after the last allowed attempt."""
    now = _now()
    reaped = 0
    with session_scope() as s:
        rows = s.execute(
            select(AgentRun).where(
                AgentRun.status == "running",
                AgentRun.lease_expires_at < now,
                AgentRun.attempts >= settings.worker_max_attempts,
            ).limit(20)
        ).scalars().all()
        for run in rows:
            run.status, run.phase, run.state = "failed", "done", {}
            run.error = f"Gave up after {run.attempts} attempts"
            run.lease_owner, run.lease_expires_at, run.finished_at = None, None, now
            ids = [d for d in (run.resume_document_id, run.jd_document_id) if d]
            repositories.purge_documents(s, user_id=run.user_id, document_ids=ids)
            seq = s.execute(select(func.max(RunStep.seq)).where(RunStep.run_id == run.id)).scalar() or 0
            s.add(RunStep(run_id=run.id, seq=seq + 1, kind="run", status="failed", detail={"error": run.error}))
            audit.record(s, event="run.fail", user_id=run.user_id, run_id=run.id, decision="error",
                         reason="max attempts")
            reaped += 1
    return reaped


def claim_next(settings: Settings, worker_id: str) -> str | None:
    now = _now()
    with session_scope() as s:
        candidates = s.execute(
            select(AgentRun.id)
            .where(_claimable(now), AgentRun.attempts < settings.worker_max_attempts)
            .order_by(AgentRun.created_at)
            .limit(5)
        ).scalars().all()
        for run_id in candidates:
            res = s.execute(
                update(AgentRun)
                .where(AgentRun.id == run_id, _claimable(now), AgentRun.attempts < settings.worker_max_attempts)
                .values(status="running", lease_owner=worker_id, attempts=AgentRun.attempts + 1,
                        lease_expires_at=now + timedelta(seconds=settings.worker_lease_s), updated_at=now)
            )
            if res.rowcount == 1:
                return run_id
    return None


class Worker:
    def __init__(self, settings: Settings | None = None, worker_id: str | None = None) -> None:
        self.settings = settings or get_settings()
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.runner = AgentRunner(self.settings, build_llm(self.settings), build_registry(), worker_id=self.worker_id)

    def run_once(self) -> str | None:
        """Claim and process one run. Returns its id, or None if the queue was empty."""
        reap_exhausted(self.settings)
        run_id = claim_next(self.settings, self.worker_id)
        if run_id is None:
            return None
        log.info("processing run %s", run_id)
        try:
            status = self.runner.process(run_id)
            log.info("run %s %s", run_id, status)
        except LeaseLost:
            log.warning("lease lost for run %s; another worker owns it", run_id)
        except Exception:
            # Leave the lease to expire: the run is retried up to worker_max_attempts.
            log.exception("run %s crashed; it will be retried after its lease expires", run_id)
        return run_id

    def run_forever(self, stop: threading.Event) -> None:
        log.info("worker %s started (llm=%s)", self.worker_id, self.runner.llm.name)
        while not stop.is_set():
            try:
                if self.run_once() is None:
                    stop.wait(self.settings.worker_poll_interval_s)
            except Exception:
                log.exception("worker loop error")
                stop.wait(5)
        log.info("worker %s stopped", self.worker_id)


def start_embedded(settings: Settings) -> tuple[threading.Thread, threading.Event]:
    stop = threading.Event()
    worker = Worker(settings)
    thread = threading.Thread(target=worker.run_forever, args=(stop,), name="embedded-worker", daemon=True)
    thread.start()
    return thread, stop


def main() -> None:  # pragma: no cover - process entry point
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    init_db()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    Worker(settings).run_forever(stop)


if __name__ == "__main__":  # pragma: no cover
    main()
