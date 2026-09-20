"""Incident timeline helper: one place that writes timestamped timeline entries."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from soar.models import Incident, TimelineEntry


def add(db: Session, incident: Incident | str, kind: str, title: str, detail: str = "",
        actor: str = "system", data: dict[str, Any] | None = None,
        ts: datetime | None = None) -> TimelineEntry:
    incident_id = incident if isinstance(incident, str) else incident.id
    entry = TimelineEntry(incident_id=incident_id, kind=kind, title=title[:300], detail=detail,
                          actor=actor, data=data or {})
    if ts is not None:
        entry.timestamp = ts
    db.add(entry)
    return entry
