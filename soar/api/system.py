"""System status. Everything reported here is measured, never hardcoded."""
from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ai.anomaly import isolation_forest_detector as anomaly
from ai.llm_commander import providers
from ai.phishing import nlp_phishing_parser as phishing
from ai.triage import ml_triage_analyzer as triage
from soar.api.deps import Principal, require
from soar.config import get_settings
from soar.db import get_db
from soar.domain import Perm
from soar.models import AuditLog, Event, Incident, PlaybookExecution
from soar.observability import metrics

router = APIRouter(prefix="/system", tags=["system"])
STARTED = time.time()


def _probe(name: str, url: str, verify: bool, path: str = "", headers: dict | None = None) -> dict[str, Any]:
    if not url:
        return {"name": name, "configured": False, "status": "not_configured"}
    t0 = time.perf_counter()
    try:
        r = httpx.get(url.rstrip("/") + path, verify=verify, timeout=4, headers=headers or {})
        return {"name": name, "configured": True, "status": "reachable" if r.status_code < 500 else "error",
                "http_status": r.status_code, "latency_ms": round((time.perf_counter() - t0) * 1000)}
    except httpx.HTTPError as e:
        return {"name": name, "configured": True, "status": "unreachable", "error": type(e).__name__}


@router.get("/integrations")
def integrations(_: Principal = Depends(require(Perm.VIEW))):
    s = get_settings()
    return {"integrations": [
        _probe("wazuh_api", s.wazuh_api_url, s.wazuh_verify_tls),
        _probe("wazuh_indexer", s.wazuh_indexer_url, s.wazuh_verify_tls),
        _probe("thehive", s.thehive_url, True, "/api/status"),
        _probe("cortex", s.cortex_url, True, "/api/status"),
        _probe("misp", s.misp_url, s.misp_verify_tls, "/servers/getVersion.json",
               {"Authorization": s.misp_api_key, "Accept": "application/json"} if s.misp_api_key else None),
        {"name": "llm", **(lambda st: {**st, "status": "configured" if st["configured"] else "not_configured"})(providers.status())}]}


@router.get("/health")
def health(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    db_ok, err = True, None
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:  # noqa: BLE001
        db_ok, err = False, type(e).__name__
    try:
        rev = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001
        rev = None
    models = {"triage": triage.model_info(), "anomaly": anomaly.model_info(), "phishing": phishing.model_info()}
    return {"status": "healthy" if db_ok else "degraded", "uptime_seconds": round(time.time() - STARTED),
            "database": {"ok": db_ok, "error": err, "migration": rev, "dialect": db.bind.dialect.name},
            "models": {k: {"loaded": "version" in v, "version": v.get("version"), "trained_on": (v.get("training_data") or {}).get("source"),
                           "trained_at": v.get("trained_at")} for k, v in models.items()},
            "llm": providers.status(), "environment": get_settings().env}


@router.get("/metrics")
def system_metrics(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return {**metrics.snapshot(),
            "database_counts": {"incidents": db.scalar(select(func.count()).select_from(Incident)),
                                "events": db.scalar(select(func.count()).select_from(Event)),
                                "playbook_executions": db.scalar(select(func.count()).select_from(PlaybookExecution))}}


@router.get("/audit")
def audit_log(page: int = 1, limit: int = 50, action: str | None = None, actor: str | None = None,
              _: Principal = Depends(require(Perm.AUDIT_VIEW)), db: Session = Depends(get_db)):
    limit, page = max(1, min(limit, 200)), max(1, page)
    cond = [c for c in (AuditLog.action == action if action else None, AuditLog.actor == actor if actor else None) if c is not None]
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*cond))
    rows = db.scalars(select(AuditLog).where(*cond).order_by(AuditLog.timestamp.desc()).offset((page - 1) * limit).limit(limit))
    return {"logs": [{"id": a.id, "timestamp": a.timestamp, "actor": a.actor, "actor_role": a.actor_role,
                      "action": a.action, "target_type": a.target_type, "target_id": a.target_id,
                      "result": a.result, "ip_address": a.ip_address, "data": a.data} for a in rows],
            "pagination": {"page": page, "limit": limit, "total": total, "pages": max(1, -(-total // limit))}}
