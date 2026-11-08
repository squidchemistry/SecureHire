"""Registration and login. Emails are stored only as an HMAC digest."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import auth_limiter, client_ip, current_user, limit
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.security.auth import create_access_token, hash_password, verify_password
from app.security.hashing import email_digest

router = APIRouter(prefix="/api/auth", tags=["auth"])

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")
# Precomputed so a login for an unknown email costs the same as a real one.
_DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")


class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL.match(v):
            raise ValueError("invalid email address")
        return v


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - not a secret
    expires_in: int


class MeOut(BaseModel):
    id: int
    created_at: str


def _token(user_id: int) -> TokenOut:
    return TokenOut(access_token=create_access_token(user_id), expires_in=get_settings().jwt_ttl_minutes * 60)


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: Credentials, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    limit(auth_limiter, f"register:{client_ip(request)}")
    user = User(email_digest=email_digest(body.email), password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists") from None
    audit.record(db, event="auth.register", user_id=user.id, decision="allow")
    db.commit()
    return _token(user.id)


@router.post("/login", response_model=TokenOut)
def login(body: Credentials, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    digest = email_digest(body.email)
    limit(auth_limiter, f"login:{client_ip(request)}")
    limit(auth_limiter, f"login-account:{digest}")
    user = db.execute(select(User).where(User.email_digest == digest)).scalar_one_or_none()
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        if user:
            audit.record(db, event="auth.login", user_id=user.id, decision="deny", reason="bad password")
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    audit.record(db, event="auth.login", user_id=user.id, decision="allow")
    db.commit()
    return _token(user.id)


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(current_user)) -> MeOut:
    return MeOut(id=user.id, created_at=user.created_at.isoformat())
