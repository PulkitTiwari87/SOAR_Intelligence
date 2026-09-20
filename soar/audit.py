"""Audit logging for security-sensitive actions.

`record` never raises into the caller's business logic path except for DB errors that
would already roll the transaction back; it adds a row to the caller's session so the
audit entry commits atomically with the change it describes.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from soar.models import AuditLog

log = logging.getLogger("soar.audit")

_SENSITIVE = ("password", "secret", "token", "api_key", "apikey", "authorization")


def _scrub(data: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (data or {}).items():
        out[k] = "[redacted]" if any(s in k.lower() for s in _SENSITIVE) else v
    return out


def record(db: Session, *, actor: str, action: str, target_type: str | None = None,
           target_id: str | None = None, result: str = "success", actor_role: str | None = None,
           ip: str | None = None, data: dict[str, Any] | None = None) -> AuditLog:
    entry = AuditLog(actor=actor, actor_role=actor_role, action=action, target_type=target_type,
                     target_id=target_id, result=result, ip_address=ip, data=_scrub(data))
    db.add(entry)
    log.info("audit actor=%s action=%s target=%s/%s result=%s", actor, action, target_type,
             target_id, result)
    return entry
