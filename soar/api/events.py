"""Event ingestion endpoints. Sources authenticate with a user token or the shared X-API-Key."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar import audit, security
from soar.api.deps import Principal, client_ip, current_user, require
from soar.config import get_settings
from soar.db import get_db, session_scope
from soar.domain import Perm
from soar.models import Event, Incident
from soar.pipeline.ingest import ingest
from soar.pipeline.normalizer import NormalizationError

router = APIRouter(prefix="/events", tags=["events"])
log = logging.getLogger("soar.events")
MAX_BATCH = 200


class IngestBody(BaseModel):
    source: str = Field(max_length=32)
    payload: dict[str, Any] | str | None = None
    payloads: list[dict[str, Any] | str] | None = Field(default=None, max_length=MAX_BATCH)


def ingest_principal(request: Request, x_api_key: str | None = Header(default=None),
                     db: Session = Depends(get_db)) -> str:
    """Machine sources use X-API-Key; people use a normal session with incident:write."""
    if x_api_key is not None:
        if security.api_key_matches(x_api_key):
            return "ingest-key"
        raise HTTPException(401, "Invalid API key")
    user = current_user(request, db)
    if not user.can(Perm.INCIDENT_WRITE):
        raise HTTPException(403, "Insufficient permissions")
    return user.username


def _llm_background(incident_id: str) -> None:
    from ai.llm_commander import commander
    try:
        with session_scope() as db:
            inc = db.get(Incident, incident_id)
            if inc:
                commander.analyze(db, inc)
    except Exception:  # noqa: BLE001
        log.exception("background LLM analysis failed for %s", incident_id)


@router.post("")
def ingest_events(body: IngestBody, request: Request, background: BackgroundTasks,
                  actor: str = Depends(ingest_principal), db: Session = Depends(get_db)):
    items = body.payloads if body.payloads is not None else ([body.payload] if body.payload is not None else [])
    if not items:
        raise HTTPException(422, "Provide 'payload' or 'payloads'")
    results, created = [], []
    for item in items:
        try:
            r = ingest(db, body.source, item)
        except NormalizationError as e:
            results.append({"error": str(e)})
            continue
        results.append({"event_id": r.event.event_id, "duplicate": r.duplicate,
                        "incident_id": r.incident.id if r.incident else None,
                        "incident_number": r.incident.number if r.incident else None,
                        "created_incident": r.created_incident, "correlated_because": r.reasons,
                        "analyzed": r.analyzed})
        if r.created_incident:
            created.append(r.incident.id)
    audit.record(db, actor=actor, action="events_ingest", target_type="events", ip=client_ip(request),
                 data={"source": body.source, "count": len(items), "errors": sum("error" in x for x in results),
                       "incidents_created": len(created)})
    db.commit()
    s = get_settings()
    if s.llm_auto_analyze and s.llm_provider != "none":
        for iid in created:
            background.add_task(_llm_background, iid)
    return {"results": results}


@router.get("")
def list_events(incident_id: str | None = None, source: str | None = None, limit: int = 50,
                _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(Event).order_by(Event.timestamp.desc()).limit(max(1, min(limit, 500)))
    if incident_id:
        q = q.where(Event.incident_id == incident_id)
    if source:
        q = q.where(Event.source == source)
    return {"events": [{"id": e.id, "event_id": e.event_id, "timestamp": e.timestamp, "source": e.source,
                        "event_type": e.event_type, "severity": e.severity, "title": e.title,
                        "source_ip": e.source_ip, "destination_ip": e.destination_ip, "host": e.source_host,
                        "username": e.username, "incident_id": e.incident_id} for e in db.scalars(q)]}
