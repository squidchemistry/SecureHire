"""Request dependencies: authentication and simple rate limiting."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.security.auth import InvalidToken, decode_access_token

_bearer = HTTPBearer(auto_error=False)


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the caller from a Bearer JWT. Identity never comes from the request body or query."""
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"}
    )
    if creds is None or creds.scheme.lower() != "bearer":
        raise unauthorized
    try:
        user_id = decode_access_token(creds.credentials)
    except InvalidToken:
        raise unauthorized from None
    user = db.get(User, user_id)
    if user is None:
        raise unauthorized
    return user


class RateLimiter:
    """In-process sliding-window limiter.

    Good enough for a single API instance; behind several replicas, move the
    counters to Redis or the database.
    """

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit, self.window_s = limit, window_s
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window_s:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 10_000:  # bound memory under key-spraying
                for k in [k for k, v in self._hits.items() if not v][:5_000]:
                    del self._hits[k]
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


auth_limiter = RateLimiter(limit=10, window_s=60)
run_limiter = RateLimiter(limit=20, window_s=60)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def limit(limiter: RateLimiter, key: str) -> None:
    if not limiter.hit(key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests, slow down",
                            headers={"Retry-After": str(int(limiter.window_s))})
