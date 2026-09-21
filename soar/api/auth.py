"""Authentication, session and user administration endpoints."""
from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soar import audit, security
from soar.api.deps import COOKIE_NAME, Principal, client_ip, current_user, require
from soar.config import get_settings
from soar.db import get_db
from soar.domain import Perm, Role
from soar.models import AuditLog, RevokedToken, User, utcnow

router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
# Compared against when the username does not exist, so timing does not reveal valid names.
_DUMMY_HASH = security.hash_password("dummy-password-for-timing")


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class ProfileBody(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class NewUserBody(BaseModel):
    username: str
    password: str = Field(max_length=256)
    role: Role = Role.VIEWER


class UpdateUserBody(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=256)


def user_json(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active,
            "created_at": u.created_at, "last_login": u.last_login}


def _login_retry_after(db: Session, ip: str, username: str, limit: int, window: int) -> int:
    """Seconds until this ip+username may try again, or 0 when not throttled.

    Derived from the audit log, so every worker and container sharing the database sees the same
    failures (no per-process state). A successful login by the same ip+username resets the count.
    Concurrent requests can overshoot `limit` by a few attempts; that is acceptable for throttling.
    """
    who = (AuditLog.action == "login", func.lower(AuditLog.actor) == username.lower(),
           AuditLog.ip_address == ip)
    since = utcnow() - timedelta(seconds=window)
    last_ok = db.scalar(select(func.max(AuditLog.timestamp)).where(*who, AuditLog.result == "success"))
    if last_ok and last_ok > since:
        since = last_ok
    failures = db.scalars(select(AuditLog.timestamp).where(
        *who, AuditLog.result == "failure", AuditLog.timestamp > since).order_by(AuditLog.timestamp)).all()
    if len(failures) < limit:
        return 0
    # Blocked until enough of the oldest failures leave the window to drop below the limit.
    unblock_at = failures[len(failures) - limit] + timedelta(seconds=window)
    return max(1, math.ceil((unblock_at - utcnow()).total_seconds()))


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response, db: Session = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request) or "unknown"
    retry_after = _login_retry_after(db, ip, body.username, s.login_max_attempts, s.login_window_seconds)
    if retry_after:
        audit.record(db, actor=body.username, action="login", result="rate_limited", ip=ip)
        db.commit()
        raise HTTPException(429, "Too many failed attempts. Try again later.",
                            headers={"Retry-After": str(retry_after)})

    user = db.scalar(select(User).where(User.username == body.username))
    ok = security.verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not (user and ok and user.is_active):
        audit.record(db, actor=body.username, action="login", result="failure", ip=ip)
        db.commit()
        raise HTTPException(401, "Invalid credentials")

    user.last_login = datetime.now(UTC)
    token, _, exp = security.create_token(user.id, user.role)
    audit.record(db, actor=user.username, actor_role=user.role, action="login",
                 target_type="user", target_id=user.id, ip=ip)
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict",
                        secure=s.cookie_secure, max_age=s.jwt_expire_minutes * 60, path="/")
    return {"user": user_json(user), "token": token, "expires_at": exp}


@router.post("/logout")
def logout(request: Request, response: Response, user: Principal = Depends(current_user),
           db: Session = Depends(get_db)):
    claims = security.decode_token(_raw_token(request))
    db.merge(RevokedToken(jti=user.jti,
                          expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC)))
    audit.record(db, actor=user.username, actor_role=user.role, action="logout",
                 target_type="user", target_id=user.id, ip=client_ip(request))
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


def _raw_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else request.cookies[COOKIE_NAME]


@router.get("/me")
def me(user: Principal = Depends(current_user), db: Session = Depends(get_db)):
    return {"user": user_json(db.get(User, user.id)), "permissions": _perms(user)}


def _perms(user: Principal) -> list[str]:
    return sorted(p.value for p in Perm if user.can(p))


@router.put("/profile")
def change_password(body: ProfileBody, request: Request, user: Principal = Depends(current_user),
                    db: Session = Depends(get_db)):
    row = db.get(User, user.id)
    if not security.verify_password(body.current_password, row.password_hash):
        audit.record(db, actor=user.username, actor_role=user.role, action="password_change",
                     target_type="user", target_id=user.id, result="failure",
                     ip=client_ip(request))
        db.commit()
        raise HTTPException(400, "Current password is incorrect")
    try:
        row.password_hash = security.hash_password(body.new_password)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    audit.record(db, actor=user.username, actor_role=user.role, action="password_change",
                 target_type="user", target_id=user.id, ip=client_ip(request))
    return {"ok": True}


# ─── User administration (ADMIN) ───
@users_router.get("")
def list_users(_: Principal = Depends(require(Perm.USER_ADMIN)), db: Session = Depends(get_db)):
    return {"users": [user_json(u) for u in db.scalars(select(User).order_by(User.username))]}


@users_router.post("", status_code=201)
def create_user(body: NewUserBody, request: Request,
                admin: Principal = Depends(require(Perm.USER_ADMIN)),
                db: Session = Depends(get_db)):
    if not USERNAME_RE.match(body.username):
        raise HTTPException(422, "Username must be 3-64 chars: letters, digits, . _ -")
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(409, "Username already exists")
    try:
        pw_hash = security.hash_password(body.password)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    user = User(username=body.username, password_hash=pw_hash, role=body.role.value)
    db.add(user)
    db.flush()
    audit.record(db, actor=admin.username, actor_role=admin.role, action="user_create",
                 target_type="user", target_id=user.id, ip=client_ip(request),
                 data={"username": user.username, "role": user.role})
    return user_json(user)


@users_router.patch("/{user_id}")
def update_user(user_id: str, body: UpdateUserBody, request: Request,
                admin: Principal = Depends(require(Perm.USER_ADMIN)),
                db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    changes: dict = {}
    demoting = (body.role is not None and body.role.value != Role.ADMIN.value) or \
               body.is_active is False
    if user.role == Role.ADMIN.value and user.is_active and demoting:
        admins = db.scalar(select(func.count()).select_from(User).where(
            User.role == Role.ADMIN.value, User.is_active.is_(True)))
        if admins <= 1:
            raise HTTPException(409, "Cannot demote or disable the last active admin")
    if body.role is not None and body.role.value != user.role:
        changes["role"] = {"from": user.role, "to": body.role.value}
        user.role = body.role.value
    if body.is_active is not None and body.is_active != user.is_active:
        changes["is_active"] = body.is_active
        user.is_active = body.is_active
    if body.password:
        try:
            user.password_hash = security.hash_password(body.password)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        changes["password"] = "reset"
    audit.record(db, actor=admin.username, actor_role=admin.role, action="user_update",
                 target_type="user", target_id=user.id, ip=client_ip(request), data=changes)
    return user_json(user)
