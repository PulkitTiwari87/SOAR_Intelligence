"""Password hashing, JWT session tokens and a small login rate limiter."""
from __future__ import annotations

import hmac
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, UTC

import bcrypt
import jwt

from soar.config import get_settings

ALGORITHM = "HS256"
MIN_PASSWORD_LENGTH = 10


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    # bcrypt only uses the first 72 bytes; reject rather than silently truncate.
    if len(password.encode()) > 72:
        raise ValueError("Password must be at most 72 bytes")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], password_hash.encode())
    except ValueError:
        return False


def create_token(user_id: str, role: str) -> tuple[str, str, datetime]:
    """Return (token, jti, expires_at)."""
    s = get_settings()
    jti = uuid.uuid4().hex
    exp = datetime.now(UTC) + timedelta(minutes=s.jwt_expire_minutes)
    token = jwt.encode({"sub": user_id, "role": role, "jti": jti, "exp": exp},
                       s.jwt_secret, algorithm=ALGORITHM)
    return token, jti, exp


def decode_token(token: str) -> dict:
    """Raises jwt.PyJWTError on any problem (bad signature, expired, malformed)."""
    return jwt.decode(token, get_settings().jwt_secret, algorithms=[ALGORITHM],
                      options={"require": ["exp", "sub", "jti"]})


def api_key_matches(provided: str | None) -> bool:
    configured = get_settings().ingest_api_key
    if not configured or not provided:
        return False
    return hmac.compare_digest(provided.encode(), configured.encode())


class RateLimiter:
    """Sliding-window limiter, per process. Enough for a single-worker deployment."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, window: float) -> deque[float]:
        q = self._hits[key]
        cutoff = time.monotonic() - window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, key: str, limit: int, window: float) -> bool:
        return len(self._prune(key, window)) >= limit

    def hit(self, key: str, window: float) -> None:
        self._prune(key, window).append(time.monotonic())

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)


login_limiter = RateLimiter()
