"""Incident endpoints: list/filter, detail, stats (real KPIs), analyst actions, analysis, reports."""
from __future__ import annotations

from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from soar import audit
from soar.api.deps import Principal, client_ip, require
from soar.config import get_settings
from soar.db import get_db
from soar.domain import (INCIDENT_TRANSITIONS, OPEN_STATUSES, SEVERITY_LABELS, IncidentStatus, InvalidTransition, Perm,
                         TimelineKind, check_transition)
from soar.models import (Approval, ExecutionStep, Incident, MitreMapping, PlaybookExecution, ThreatIntel, AnalystAction, utcnow, Event)
from soar.pipeline import analysis, timeline
from soar.playbooks import engine

router = APIRouter(prefix="/incidents", tags=["incidents"])

# Analyst decisions -> resulting status. Response actions (block/isolate) are separate: see /response.
ACTION_STATUS = {"investigate": IncidentStatus.INVESTIGATING, "monitor": IncidentStatus.MONITORING,
                 "false_positive": IncidentStatus.FALSE_POSITIVE, "resolve": IncidentStatus.RESOLVED,
                 "close": IncidentStatus.CLOSED, "reopen": IncidentStatus.INVESTIGATING}


def find_incident(db: Session, ident: str) -> Incident:
    inc = db.get(Incident, ident) or db.scalar(select(Incident).where(Incident.number == ident))
    if inc is None:
        raise HTTPException(404, "Incident not found")
    return inc


def summary_json(i: Incident) -> dict[str, Any]:
    return {"id": i.id, "number": i.number, "title": i.title, "status": i.status, "severity": i.severity,
            "severity_label": SEVERITY_LABELS.get(i.severity), "risk_score": i.risk_score, "source": i.source,
            "category": i.category, "primary_source_ip": i.primary_source_ip, "primary_host": i.primary_host,
            "primary_user": i.primary_user, "event_count": i.event_count, "first_event_at": i.first_event_at,
            "last_event_at": i.last_event_at, "detected_at": i.detected_at, "resolved_at": i.resolved_at,
            "auto_handled": i.auto_handled, "has_report": bool(i.report_file),
            "mitre": sorted({m.technique_id for m in i.mitre})}


@router.get("")
def list_incidents(severity: int | None = None, status: str | None = None, source: str | None = None,
                   mitre: str | None = None, asset: str | None = None, q: str | None = None,
                   date_from: datetime | None = None, date_to: datetime | None = None,
                   page: int = 1, limit: int = 20, _: Principal = Depends(require(Perm.VIEW)),
                   db: Session = Depends(get_db)):
    limit, page = max(1, min(limit, 200)), max(1, page)
    cond = []
    if severity:
        cond.append(Incident.severity == severity)
    if status:
        cond.append(Incident.status == status)
    if source:
        cond.append(Incident.source == source)
    if mitre:
        cond.append(Incident.id.in_(select(MitreMapping.incident_id).where(MitreMapping.technique_id == mitre.upper())))
    if asset:
        like = f"%{asset.lower()}%"
        cond.append(or_(func.lower(Incident.primary_host).like(like), Incident.primary_source_ip.like(f"%{asset}%")))
    if q:
        cond.append(or_(Incident.title.ilike(f"%{q}%"), Incident.number.ilike(f"%{q}%")))
    if date_from:
        cond.append(Incident.detected_at >= date_from)
    if date_to:
        cond.append(Incident.detected_at <= date_to)
    total = db.scalar(select(func.count()).select_from(Incident).where(*cond))
    rows = db.scalars(select(Incident).where(*cond).order_by(Incident.detected_at.desc())
                      .offset((page - 1) * limit).limit(limit)).all()
    return {"incidents": [summary_json(i) for i in rows],
            "pagination": {"page": page, "limit": limit, "total": total, "pages": max(1, -(-total // limit))}}


@router.get("/stats")
def stats(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    """Every figure is computed from stored data; where there is nothing to average it is null."""
    open_states = [s.value for s in OPEN_STATUSES]
    today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    count = lambda *c: db.scalar(select(func.count()).select_from(Incident).where(*c))  # noqa: E731
    resolved = db.scalars(select(Incident).where(Incident.resolved_at.is_not(None))).all()
    mttr = (sum((i.resolved_at - i.detected_at).total_seconds() for i in resolved) / len(resolved)) if resolved else None
    with_first = db.scalars(select(Incident).where(Incident.first_event_at.is_not(None)).limit(1000)).all()
    mttd = (sum(max(0.0, (i.detected_at - i.first_event_at).total_seconds()) for i in with_first) / len(with_first)
            if with_first else None)
    auto = db.scalar(select(func.count()).select_from(ExecutionStep).join(PlaybookExecution).where(
        ExecutionStep.status == "succeeded", ExecutionStep.approval_mode != "approved",
        PlaybookExecution.requested_by == "system"))
    return {
        "total": count(), "active": count(Incident.status.in_(open_states)),
        "critical": count(Incident.severity == 4, Incident.status.in_(open_states)),
        "by_status": {s: c for s, c in db.execute(select(Incident.status, func.count()).group_by(Incident.status))},
        "by_severity": {SEVERITY_LABELS[s]: c for s, c in db.execute(select(Incident.severity, func.count()).group_by(Incident.severity))},
        "alerts_today": db.scalar(select(func.count()).select_from(Event).where(Event.timestamp >= today, Event.severity >= 2)),
        "automated_responses": auto,
        "pending_approvals": db.scalar(select(func.count()).select_from(Approval).where(Approval.status == "pending")),
        "mttd_seconds": mttd, "mttr_seconds": mttr,
        "mttd_definition": "mean time from an incident's first event to incident creation",
        "mttr_definition": "mean time from incident creation to resolution (resolved incidents only)",
        "categories": [{"category": c, "count": n} for c, n in db.execute(
            select(Incident.category, func.count()).group_by(Incident.category).order_by(func.count().desc()).limit(10))],
        "top_mitre": [{"id": t, "name": nme, "count": n} for t, nme, n in db.execute(
            select(MitreMapping.technique_id, MitreMapping.technique_name, func.count()).group_by(
                MitreMapping.technique_id, MitreMapping.technique_name).order_by(func.count().desc()).limit(8))],
    }


def detail_json(db: Session, inc: Incident) -> dict[str, Any]:
    latest: dict[str, Any] = {}
    for p in inc.predictions:
        latest[p.kind] = {"id": p.id, "model": p.model_name, "version": p.model_version, "prediction": p.prediction,
                          "confidence": p.confidence, "result": p.result, "created_at": p.created_at}
    iocs = []
    for ioc in inc.iocs:
        rows = db.scalars(select(ThreatIntel).where(ThreatIntel.ioc_id == ioc.id).order_by(ThreatIntel.fetched_at.desc())).all()
        iocs.append({"id": ioc.id, "type": ioc.type, "value": ioc.value,
                     "intel": [{"provider": r.provider, "verdict": r.verdict, "score": r.score,
                                "confidence": r.confidence, "tags": r.tags, "context": r.context,
                                "fetched_at": r.fetched_at} for r in rows]})
    execs = db.scalars(select(PlaybookExecution).where(PlaybookExecution.incident_id == inc.id)
                       .order_by(PlaybookExecution.created_at)).all()
    return {
        **summary_json(inc), "summary": inc.summary, "confidence": inc.confidence, "risk_breakdown": inc.risk_breakdown,
        "entities": inc.entities, "auto_handled": inc.auto_handled,
        "events": [{"id": e.id, "timestamp": e.timestamp, "source": e.source, "event_type": e.event_type,
                    "severity": e.severity, "title": e.title, "rule_id": e.rule_id, "source_ip": e.source_ip,
                    "destination_ip": e.destination_ip, "host": e.source_host, "username": e.username,
                    "command": e.command, "raw_event": e.raw_event}
                   for e in sorted(inc.events, key=lambda e: e.timestamp)[:100]],
        "iocs": iocs,
        "mitre": [{"technique_id": m.technique_id, "technique": m.technique_name, "subtechnique": m.subtechnique,
                   "tactic": m.tactic, "source": m.source, "inferred": m.source == "llm_inferred",
                   "confidence": m.confidence, "evidence": m.evidence} for m in inc.mitre],
        "analysis": {k: v for k, v in latest.items() if k != "llm_commander"},
        "llm": latest.get("llm_commander"),
        "timeline": [{"id": t.id, "timestamp": t.timestamp, "kind": t.kind, "title": t.title, "detail": t.detail,
                      "actor": t.actor} for t in inc.timeline],
        "executions": [{"id": x.id, "playbook": x.playbook_name, "status": x.status, "requested_by": x.requested_by,
                        "created_at": x.created_at, "finished_at": x.finished_at, "error": x.error,
                        "steps": [{"id": s.id, "key": s.step_key, "action": s.action, "params": s.params,
                                   "status": s.status, "approval_mode": s.approval_mode, "result": s.result,
                                   "verified": s.verified, "verification": s.verification, "rollback": s.rollback}
                                  for s in x.steps]} for x in execs],
        "approvals": [{"id": a.id, "action": a.action, "risk": a.risk_level, "reason": a.reason, "status": a.status,
                       "requested_at": a.requested_at, "decided_by": a.decided_by, "decided_at": a.decided_at,
                       "decision_note": a.decision_note, "params": a.params}
                      for a in db.scalars(select(Approval).where(Approval.incident_id == inc.id).order_by(Approval.requested_at))],
        "analyst_actions": [{"username": a.username, "action": a.action, "notes": a.notes, "created_at": a.created_at}
                            for a in db.scalars(select(AnalystAction).where(AnalystAction.incident_id == inc.id).order_by(AnalystAction.created_at))],
    }


@router.get("/reports/all")
def list_reports(_: Principal = Depends(require(Perm.VIEW))):
    d = get_settings().reports_dir
    files = sorted(d.glob("*.pdf"), key=lambda p: p.stat().st_mtime, reverse=True) if d.is_dir() else []
    return {"reports": [{"filename": f.name, "size": f.stat().st_size,
                         "created_at": datetime.fromtimestamp(f.stat().st_mtime, tz=UTC)} for f in files]}


@router.get("/reports/download/{filename}")
def download_report(filename: str, _: Principal = Depends(require(Perm.VIEW))):
    root = get_settings().reports_dir.resolve()
    path = (root / filename).resolve()
    if path.parent != root or path.suffix != ".pdf" or not path.is_file():  # also blocks ../ traversal
        raise HTTPException(404, "Report not found")
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@router.get("/{ident}")
def get_incident(ident: str, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return detail_json(db, find_incident(db, ident))


class ActionBody(BaseModel):
    action: str = Field(max_length=32)
    notes: str = Field(default="", max_length=2000)


@router.post("/{ident}/action")
def analyst_action(ident: str, body: ActionBody, request: Request,
                   user: Principal = Depends(require(Perm.INCIDENT_WRITE)), db: Session = Depends(get_db)):
    target = ACTION_STATUS.get(body.action)
    if target is None:
        raise HTTPException(422, f"action must be one of {sorted(ACTION_STATUS)}")
    inc = find_incident(db, ident)
    try:
        check_transition(INCIDENT_TRANSITIONS, IncidentStatus(inc.status), target)
    except InvalidTransition as e:
        audit.record(db, actor=user.username, actor_role=user.role, action="incident_action", target_type="incident",
                     target_id=inc.id, result="rejected", ip=client_ip(request), data={"action": body.action, "error": str(e)})
        db.commit()
        raise HTTPException(409, str(e)) from None
    prev = inc.status
    inc.status = target.value
    if target in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE) and not inc.resolved_at:
        inc.resolved_at = utcnow()
    if target == IncidentStatus.CLOSED:
        inc.closed_at = utcnow()
        inc.resolved_at = inc.resolved_at or utcnow()
    if body.action == "reopen":
        inc.resolved_at = inc.closed_at = None
    db.add(AnalystAction(incident_id=inc.id, username=user.username, action=body.action, notes=body.notes))
    kind = TimelineKind.CLOSURE if target in (IncidentStatus.CLOSED, IncidentStatus.RESOLVED,
                                              IncidentStatus.FALSE_POSITIVE) else TimelineKind.STATUS
    timeline.add(db, inc, kind.value, f"{user.username}: {body.action} ({prev} → {target.value})", body.notes, actor=user.username)
    audit.record(db, actor=user.username, actor_role=user.role, action="incident_action", target_type="incident",
                 target_id=inc.id, ip=client_ip(request), data={"action": body.action, "from": prev, "to": target.value})
    return summary_json(inc)


class NoteBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/{ident}/notes", status_code=201)
def add_note(ident: str, body: NoteBody, request: Request, user: Principal = Depends(require(Perm.INCIDENT_WRITE)),
             db: Session = Depends(get_db)):
    inc = find_incident(db, ident)
    timeline.add(db, inc, TimelineKind.NOTE.value, f"Note by {user.username}", body.text, actor=user.username)
    audit.record(db, actor=user.username, actor_role=user.role, action="incident_note", target_type="incident",
                 target_id=inc.id, ip=client_ip(request))
    return {"ok": True}


@router.post("/{ident}/analyze")
def reanalyze(ident: str, request: Request, llm: bool = False,
              user: Principal = Depends(require(Perm.INCIDENT_WRITE)), db: Session = Depends(get_db)):
    inc = find_incident(db, ident)
    out = analysis.analyze_incident(db, inc, run_playbooks=False)
    llm_result = None
    if llm:
        from ai.llm_commander import commander
        llm_result = commander.analyze(db, inc)
    audit.record(db, actor=user.username, actor_role=user.role, action="incident_analyze", target_type="incident",
                 target_id=inc.id, ip=client_ip(request), data={"llm": llm})
    db.commit()
    return {"risk": out.get("risk"), "llm": llm_result}


@router.get("/{ident}/blast-radius")
def blast_radius(ident: str, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    from ai.blast_radius import blast_radius_predictor as blast
    inc = find_incident(db, ident)
    origin = blast.resolve_host(db, inc.primary_host) or blast.resolve_host(db, inc.primary_source_ip)
    g = blast.build_graph(db)
    if not origin:
        return {"status": "unknown_host", "message": "The incident's host is not in the asset inventory.",
                "graph": blast.export_graph_data(g)}
    return {**blast.predict_blast_radius(origin, g, db=db), "graph": blast.export_graph_data(g, highlight=origin)}


class ApplyBody(BaseModel):
    actions: list[dict[str, Any]] = Field(min_length=1, max_length=10)


@router.post("/{ident}/actions/run")
def run_actions(ident: str, body: ApplyBody, request: Request,
                user: Principal = Depends(require(Perm.PLAYBOOK_RUN)), db: Session = Depends(get_db)):
    """Run analyst/LLM-recommended actions through the same policy + approval path as playbooks."""
    inc = find_incident(db, ident)
    steps = [a for a in body.actions if a.get("action")]
    if not steps:
        raise HTTPException(422, "each item needs an 'action'")
    ex = engine.run_adhoc(db, inc, steps, user.username)
    audit.record(db, actor=user.username, actor_role=user.role, action="actions_run", target_type="incident",
                 target_id=inc.id, ip=client_ip(request), data={"actions": [a["action"] for a in steps], "execution": ex.id})
    return {"execution_id": ex.id, "status": ex.status}


@router.post("/{ident}/report")
def generate_report(ident: str, request: Request, user: Principal = Depends(require(Perm.INCIDENT_WRITE)),
                    db: Session = Depends(get_db)):
    from ai.report_generator.report_generator import generate_incident_report
    inc = find_incident(db, ident)
    path = generate_incident_report(db, inc, get_settings().reports_dir)
    inc.report_file = Path(path).name
    audit.record(db, actor=user.username, actor_role=user.role, action="report_generate", target_type="incident",
                 target_id=inc.id, ip=client_ip(request), data={"file": inc.report_file})
    return {"filename": inc.report_file}


@router.get("/{ident}/report/download")
def download_incident_report(ident: str, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    inc = find_incident(db, ident)
    root = get_settings().reports_dir.resolve()
    path = (root / (inc.report_file or "")).resolve()
    if not inc.report_file or path.parent != root or not path.is_file():
        raise HTTPException(404, "No report yet; generate one first")
    return FileResponse(path, media_type="application/pdf", filename=path.name)
