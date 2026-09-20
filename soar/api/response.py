"""Response endpoints: playbooks, executions, approvals and the blocklist feed."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar import audit, security
from soar.api.deps import Principal, client_ip, current_user, require
from soar.api.incidents import find_incident
from soar.db import get_db
from soar.domain import Perm
from soar.models import Approval, BlocklistEntry, Incident, Playbook, PlaybookExecution, utcnow
from soar.playbooks import engine
from soar.playbooks.actions import ACTIONS

router = APIRouter(tags=["response"])


def _exec_json(x: PlaybookExecution) -> dict[str, Any]:
    return {"id": x.id, "playbook": x.playbook_name, "version": x.playbook_version, "incident_id": x.incident_id,
            "status": x.status, "requested_by": x.requested_by, "error": x.error, "created_at": x.created_at,
            "started_at": x.started_at, "finished_at": x.finished_at,
            "steps": [{"id": s.id, "key": s.step_key, "action": s.action, "params": s.params, "status": s.status,
                       "approval_mode": s.approval_mode, "result": s.result, "verified": s.verified,
                       "verification": s.verification, "rollback": s.rollback} for s in x.steps]}


# ─── playbooks ───
@router.get("/playbooks")
def list_playbooks(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return {"playbooks": [{"name": p.name, "version": p.version, "description": p.description, "enabled": p.enabled,
                           "trigger": p.definition.get("trigger"), "conditions": p.definition.get("conditions", []),
                           "steps": [{**s, "risk": ACTIONS[s["action"]].risk} for s in p.definition["steps"]]}
                          for p in db.scalars(select(Playbook).order_by(Playbook.name))],
            "actions": [{"name": a.name, "risk": a.risk, "description": a.description, "reversible": a.rollback is not None}
                        for a in ACTIONS.values()]}


@router.get("/playbooks/stats")
def playbook_stats(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    from ai.optimizer.playbook_optimizer import playbook_report
    return playbook_report(db)


@router.get("/executions")
def list_executions(incident_id: str | None = None, status: str | None = None, limit: int = 50,
                    _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(PlaybookExecution).order_by(PlaybookExecution.created_at.desc()).limit(max(1, min(limit, 200)))
    if incident_id:
        q = q.where(PlaybookExecution.incident_id == incident_id)
    if status:
        q = q.where(PlaybookExecution.status == status)
    rows = db.scalars(q).all()
    numbers = {i.id: i.number for i in db.scalars(select(Incident).where(Incident.id.in_({x.incident_id for x in rows})))} if rows else {}
    return {"executions": [{**_exec_json(x), "incident_number": numbers.get(x.incident_id)} for x in rows]}


@router.get("/executions/{execution_id}")
def get_execution(execution_id: str, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    x = db.get(PlaybookExecution, execution_id)
    if not x:
        raise HTTPException(404, "Execution not found")
    return _exec_json(x)


@router.post("/incidents/{ident}/playbooks/{name}/run")
def run_playbook(ident: str, name: str, request: Request, user: Principal = Depends(require(Perm.PLAYBOOK_RUN)),
                 db: Session = Depends(get_db)):
    inc = find_incident(db, ident)
    try:
        ex = engine.start_playbook(db, name, inc, user.username)
    except engine.StateError as e:
        raise HTTPException(409, str(e)) from None
    audit.record(db, actor=user.username, actor_role=user.role, action="playbook_run", target_type="incident",
                 target_id=inc.id, ip=client_ip(request), data={"playbook": name, "execution": ex.id, "status": ex.status})
    return _exec_json(ex)


@router.post("/executions/{execution_id}/rollback")
def rollback(execution_id: str, request: Request, user: Principal = Depends(require(Perm.APPROVE_MEDIUM)),
             db: Session = Depends(get_db)):
    x = db.get(PlaybookExecution, execution_id)
    if not x:
        raise HTTPException(404, "Execution not found")
    try:
        result = engine.rollback_execution(db, x, user.username)
    except engine.StateError as e:
        raise HTTPException(409, str(e)) from None
    audit.record(db, actor=user.username, actor_role=user.role, action="execution_rollback", target_type="execution",
                 target_id=x.id, ip=client_ip(request), data={"steps": result})
    return {"rolled_back": result}


# ─── approvals ───
def _approval_json(a: Approval, numbers: dict[str, str]) -> dict[str, Any]:
    return {"id": a.id, "incident_id": a.incident_id, "incident_number": numbers.get(a.incident_id), "action": a.action,
            "params": a.params, "risk": a.risk_level, "reason": a.reason, "status": a.status,
            "requested_by": a.requested_by, "requested_at": a.requested_at, "expires_at": a.expires_at,
            "decided_by": a.decided_by, "decided_at": a.decided_at, "decision_note": a.decision_note}


@router.get("/approvals")
def list_approvals(status: str | None = "pending", _: Principal = Depends(require(Perm.VIEW)),
                   db: Session = Depends(get_db)):
    q = select(Approval).order_by(Approval.requested_at.desc()).limit(200)
    if status:
        q = q.where(Approval.status == status)
    rows = db.scalars(q).all()
    numbers = {i.id: i.number for i in db.scalars(select(Incident).where(Incident.id.in_({a.incident_id for a in rows})))} if rows else {}
    return {"approvals": [_approval_json(a, numbers) for a in rows]}


class DecideBody(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=1000)


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: str, body: DecideBody, request: Request, user: Principal = Depends(current_user),
                    db: Session = Depends(get_db)):
    ap = db.get(Approval, approval_id)
    if not ap:
        raise HTTPException(404, "Approval not found")
    needed = Perm.APPROVE_HIGH if ap.risk_level == "high" else Perm.APPROVE_MEDIUM
    if not user.can(needed):
        audit.record(db, actor=user.username, actor_role=user.role, action="approval_decide", target_type="approval",
                     target_id=ap.id, result="forbidden", ip=client_ip(request), data={"risk": ap.risk_level})
        db.commit()
        raise HTTPException(403, f"{ap.risk_level}-risk approvals require the {needed.value} permission")
    try:
        ap = engine.decide(db, approval_id, body.approve, user.username, user.role, body.note, ip=client_ip(request))
    except engine.StateError as e:
        db.commit()  # keep an EXPIRED marker if one was set
        raise HTTPException(409, str(e)) from None
    inc = db.get(Incident, ap.incident_id)
    return _approval_json(ap, {inc.id: inc.number})


# ─── blocklist ───
def _blocklist_principal(request: Request, x_api_key: str | None = Header(default=None),
                         db: Session = Depends(get_db)) -> str:
    if x_api_key is not None:
        if security.api_key_matches(x_api_key):
            return "feed-consumer"
        raise HTTPException(401, "Invalid API key")
    return current_user(request, db).username


def _active(db: Session) -> list[BlocklistEntry]:
    now = utcnow()
    return [b for b in db.scalars(select(BlocklistEntry).where(BlocklistEntry.active.is_(True)).order_by(BlocklistEntry.ip))
            if b.expires_at is None or b.expires_at > now]


@router.get("/blocklist")
def blocklist(_: str = Depends(_blocklist_principal), db: Session = Depends(get_db)):
    return {"blocklist": [{"ip": b.ip, "reason": b.reason, "created_by": b.created_by, "created_at": b.created_at,
                           "expires_at": b.expires_at, "incident_id": b.incident_id} for b in _active(db)]}


@router.get("/blocklist.txt", response_class=PlainTextResponse)
def blocklist_txt(_: str = Depends(_blocklist_principal), db: Session = Depends(get_db)):
    """One IP per line: consumable by firewalls / external dynamic lists (send X-API-Key)."""
    return "\n".join(b.ip for b in _active(db)) + "\n"


@router.delete("/blocklist/{ip}")
def unblock(ip: str, request: Request, user: Principal = Depends(require(Perm.APPROVE_MEDIUM)),
            db: Session = Depends(get_db)):
    e = db.scalar(select(BlocklistEntry).where(BlocklistEntry.ip == ip, BlocklistEntry.active.is_(True)))
    if not e:
        raise HTTPException(404, "IP is not on the blocklist")
    e.active, e.removed_at, e.removed_by = False, utcnow(), user.username
    audit.record(db, actor=user.username, actor_role=user.role, action="blocklist_remove", target_type="ip",
                 target_id=ip, ip=client_ip(request))
    return {"ok": True}
