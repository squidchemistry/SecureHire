"""Keyed hashing helpers for pseudonymous identifiers."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from app.config import get_settings


def _hmac(key: str, value: str) -> str:
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def email_digest(email: str) -> str:
    """Lookup key for login. The plaintext email is never stored."""
    return _hmac(get_settings().identity_hmac_key, email.strip().lower())


def audit_ref(kind: str, value: object) -> str:
    """Pseudonymous reference for the audit log (stable, not reversible without the key)."""
    return _hmac(get_settings().audit_hmac_key, f"{kind}:{value}")[:32]


def digest_json(data: Any) -> str:
    """Content digest of tool arguments, so the audit log never stores raw arguments."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()
