"""FastAPI dependencies: database session, current principal, RBAC checks."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar import security
from soar.db import get_db
from soar.domain import Perm, has_perm
from soar.models import RevokedToken, User

COOKIE_NAME = "soar_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "x-requested-with"


@dataclass
class Principal:
    id: str
    username: str
    role: str
    jti: str = ""

    def can(self, perm: Perm) -> bool:
        return has_perm(self.role, perm)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _extract_token(request: Request) -> tuple[str | None, bool]:
    """Return (token, from_cookie). Bearer header wins over the session cookie."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip(), False
    cookie = request.cookies.get(COOKIE_NAME)
    return (cookie, True) if cookie else (None, False)


def current_user(request: Request, db: Session = Depends(get_db)) -> Principal:
    token, from_cookie = _extract_token(request)
    if not token:
        raise HTTPException(401, "Authentication required")
    # Cookie sessions are ambient credentials, so state-changing calls must carry a header
    # that a cross-site form/request cannot set (defends against CSRF).
    if from_cookie and request.method not in SAFE_METHODS and CSRF_HEADER not in request.headers:
        raise HTTPException(403, "Missing X-Requested-With header")
    try:
        claims = security.decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired session") from None
    if db.get(RevokedToken, claims["jti"]):
        raise HTTPException(401, "Session has been revoked")
    user = db.get(User, claims["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or disabled")
    # Role comes from the database, not the token, so demotions take effect immediately.
    return Principal(id=user.id, username=user.username, role=user.role, jti=claims["jti"])


def require(perm: Perm):
    def dep(user: Principal = Depends(current_user)) -> Principal:
        if not user.can(perm):
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dep


def purge_revoked(db: Session) -> None:
    now = datetime.now(UTC)
    for row in db.scalars(select(RevokedToken).where(RevokedToken.expires_at < now)):
        db.delete(row)
