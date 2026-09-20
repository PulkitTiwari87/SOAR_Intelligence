"""Playbook engine: trigger -> conditions -> steps -> approval gate -> execute -> verify -> rollback.

State lives in the database (`playbook_executions`, `execution_steps`, `approvals`), so a restart
never loses an execution that is waiting for a human. Status changes go through the explicit state
machines in soar.domain.

Concurrency: an approval is claimed with a conditional UPDATE (status must still be 'pending'), so
two people clicking Approve, or a retry, can run the step at most once. Auto-triggering is once per
(incident, playbook). Execution is at-most-once per step: a step that is not PENDING is never re-run.
"""
from __future__ import annotations

import logging
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from soar import audit
from soar.config import get_settings
from soar.domain import (EXEC_TRANSITIONS, INCIDENT_TRANSITIONS, ApprovalStatus, ExecStatus, IncidentStatus,
                         InvalidTransition, StepStatus, TimelineKind, check_transition)
from soar.models import (Approval, ExecutionStep, Incident, Playbook, PlaybookExecution, ThreatIntel, utcnow)
from soar.observability import metrics
from soar.pipeline import timeline
from soar.pipeline.correlation import is_public_ip
from soar.playbooks import policy
from soar.playbooks.actions import ACTIONS, ActionResult, Ctx

log = logging.getLogger("soar.playbooks")
APPROVAL_TTL = timedelta(hours=24)
REMEDIATION = {"block_ip", "isolate_host", "disable_account"}


class StateError(RuntimeError):
    """The requested change is not valid in the current state (maps to HTTP 409)."""


# ─── context, templating, matching ───
def incident_context(db: Session, inc: Incident) -> dict[str, Any]:
    event_types = {e.event_type for e in inc.events}
    ioc_ids = [i.id for i in inc.iocs]
    bad = db.scalar(select(ThreatIntel.id).where(ThreatIntel.verdict == "malicious",
                                                 ThreatIntel.ioc_id.in_(ioc_ids)).limit(1)) if ioc_ids else None
    return {"risk_score": inc.risk_score, "severity": inc.severity, "event_count": inc.event_count,
            "category": inc.category, "event_types": sorted(event_types), "primary_source_ip": inc.primary_source_ip,
            "primary_host": inc.primary_host, "primary_user": inc.primary_user,
            "has_external_source_ip": is_public_ip(inc.primary_source_ip),
            "mitre_ids": sorted({m.technique_id for m in inc.mitre}), "ioc_malicious": bad is not None,
            "number": inc.number}


def resolve_params(params: dict, ctx: dict) -> dict:
    out = {}
    for k, v in (params or {}).items():
        if isinstance(v, str) and (m := re.fullmatch(r"\$incident\.(\w+)", v)):
            out[k] = ctx.get(m.group(1))
        else:
            out[k] = v
    return out


_OPS = {"eq": lambda a, b: a == b, "ne": lambda a, b: a != b, "gt": lambda a, b: a is not None and a > b,
        "gte": lambda a, b: a is not None and a >= b, "lt": lambda a, b: a is not None and a < b,
        "lte": lambda a, b: a is not None and a <= b, "in": lambda a, b: a in b,
        "contains": lambda a, b: b in (a or [])}


def conditions_met(conds: list[dict], ctx: dict) -> tuple[bool, str]:
    for c in conds or []:
        op = _OPS.get(c.get("op", "eq"))
        if op is None or not op(ctx.get(c.get("field")), c.get("value")):
            return False, f"condition failed: {c.get('field')} {c.get('op', 'eq')} {c.get('value')!r}"
    return True, ""


def matches_trigger(defn: dict, ctx: dict) -> bool:
    t = defn.get("trigger") or {}
    if "min_risk" in t and ctx["risk_score"] < t["min_risk"]:
        return False
    if "min_severity" in t and ctx["severity"] < t["min_severity"]:
        return False
    if t.get("event_types") and not (set(t["event_types"]) & set(ctx["event_types"])):
        return False
    if t.get("mitre") and not (set(t["mitre"]) & set(ctx["mitre_ids"])):
        return False
    return bool(t)  # a playbook with an empty trigger is manual-only


# ─── state helpers ───
def _set_incident(db: Session, inc: Incident, target: IncidentStatus, actor: str, why: str) -> None:
    current = IncidentStatus(inc.status)
    try:
        check_transition(INCIDENT_TRANSITIONS, current, target)
    except InvalidTransition:
        return  # best effort: never abort a response because the status label cannot move
    if current != target:
        inc.status = target.value
        timeline.add(db, inc, TimelineKind.STATUS.value, f"Status: {current.value} → {target.value}", why, actor=actor)


def _set_exec(ex: PlaybookExecution, target: ExecStatus) -> None:
    try:
        check_transition(EXEC_TRANSITIONS, ExecStatus(ex.status), target)
    except InvalidTransition as e:
        raise StateError(str(e)) from None
    ex.status = target.value


# ─── creation ───
def create_execution(db: Session, name: str, version: int, steps: list[dict], inc: Incident,
                     requested_by: str) -> PlaybookExecution:
    ctx = incident_context(db, inc)
    ex = PlaybookExecution(playbook_name=name, playbook_version=version, incident_id=inc.id,
                           requested_by=requested_by)
    for i, s in enumerate(steps):
        ex.steps.append(ExecutionStep(idx=i, step_key=s.get("id") or f"step{i + 1}", action=s["action"],
                                      params=resolve_params(s.get("params", {}), ctx),
                                      approval_mode=s.get("approval", "policy")))
    db.add(ex)
    db.flush()
    timeline.add(db, inc, TimelineKind.ACTION.value, f"Playbook '{name}' started",
                 f"{len(steps)} step(s), requested by {requested_by}", actor=requested_by,
                 data={"execution_id": ex.id})
    metrics.count("playbook_executions")
    return ex


def start_playbook(db: Session, name: str, inc: Incident, requested_by: str) -> PlaybookExecution:
    pb = db.scalar(select(Playbook).where(Playbook.name == name))
    if not pb or not pb.enabled:
        raise StateError(f"playbook '{name}' not found or disabled")
    ok, why = conditions_met(pb.definition.get("conditions", []), incident_context(db, inc))
    if not ok:
        raise StateError(f"playbook '{name}' does not apply: {why}")
    return run_execution(db, create_execution(db, pb.name, pb.version, pb.definition["steps"], inc, requested_by),
                         requested_by)


def run_adhoc(db: Session, inc: Incident, actions: list[dict], requested_by: str) -> PlaybookExecution:
    """Run analyst- or LLM-suggested actions through the same policy/approval path as a playbook."""
    steps = [{"id": f"adhoc{i + 1}", "action": a["action"], "params": a.get("params", {"target": a.get("target")})}
             for i, a in enumerate(actions)]
    for s in steps:  # a block_ip target arrives as `target`; normalize to the action's parameter name
        if s["action"] == "block_ip":
            s["params"] = {"ip": s["params"].get("ip") or s["params"].get("target"),
                           "ttl_hours": s["params"].get("ttl_hours", 24)}
    return run_execution(db, create_execution(db, "adhoc", 1, steps, inc, requested_by), requested_by)


# ─── execution ───
def _execute_step(db: Session, ex: PlaybookExecution, step: ExecutionStep, inc: Incident, actor: str) -> None:
    action = ACTIONS[step.action]
    step.status, step.started_at = StepStatus.RUNNING.value, utcnow()
    try:
        with db.begin_nested():  # a crashing action must not leave half-applied state
            res = action.execute(Ctx(db, inc, actor), step.params)
    except Exception as e:  # noqa: BLE001 - any action failure is recorded, never propagated
        log.exception("action %s crashed", step.action)
        res = ActionResult("failed", f"unexpected error: {type(e).__name__}")
    step.result = {"status": res.status, "detail": res.detail, "data": res.data}
    step.finished_at = utcnow()
    step.status = {"succeeded": StepStatus.SUCCEEDED, "skipped": StepStatus.SKIPPED}.get(res.status, StepStatus.FAILED).value
    if step.status == StepStatus.FAILED.value:
        step.error = res.detail
    timeline.add(db, inc, TimelineKind.ACTION.value, f"{step.action}: {res.status}", res.detail, actor=actor,
                 data={"execution_id": ex.id, "step": step.step_key})
    metrics.count(f"action_{step.action}_{res.status}")
    if res.status == "succeeded":
        v = action.verify(Ctx(db, inc, actor), step.params, res)
        step.verified, step.verification = v.verified, {"detail": v.detail}
        timeline.add(db, inc, TimelineKind.VERIFICATION.value,
                     f"{step.action}: {'verified' if v.verified else 'unverified' if v.verified is None else 'verification FAILED'}",
                     v.detail, actor="system", data={"execution_id": ex.id, "step": step.step_key})


def _request_approval(db: Session, ex: PlaybookExecution, step: ExecutionStep, inc: Incident, d: policy.Decision) -> None:
    target = step.params.get("ip") or step.params.get("host") or step.params.get("user") or step.params.get("target")
    ap = Approval(incident_id=inc.id, execution_id=ex.id, step_id=step.id, action=step.action, params=step.params,
                  risk_level=d.risk, reason=f"{step.action} on {target}: {d.reason}"[:1000],
                  requested_by=ex.requested_by, expires_at=utcnow() + APPROVAL_TTL)
    db.add(ap)
    step.status = StepStatus.AWAITING_APPROVAL.value
    _set_exec(ex, ExecStatus.AWAITING_APPROVAL)
    _set_incident(db, inc, IncidentStatus.AWAITING_APPROVAL, ex.requested_by, "response action needs approval")
    timeline.add(db, inc, TimelineKind.APPROVAL.value, f"Approval requested: {step.action}", ap.reason,
                 actor=ex.requested_by, data={"execution_id": ex.id, "risk": d.risk})
    metrics.count("approvals_requested")


def _finish(db: Session, ex: PlaybookExecution, inc: Incident, status: ExecStatus, error: str | None = None) -> None:
    _set_exec(ex, status)
    ex.finished_at, ex.error = utcnow(), error
    timeline.add(db, inc, TimelineKind.ACTION.value, f"Playbook '{ex.playbook_name}' {status.value}",
                 error or "", actor=ex.requested_by, data={"execution_id": ex.id})
    remediated = any(s.action in REMEDIATION and s.status == StepStatus.SUCCEEDED.value for s in ex.steps)
    if status == ExecStatus.COMPLETED and remediated:
        _set_incident(db, inc, IncidentStatus.MONITORING, ex.requested_by, "response actions executed; monitoring")
        human = db.scalar(select(Approval.id).where(Approval.execution_id == ex.id).limit(1)) is not None
        inc.auto_handled = not human
    elif inc.status in (IncidentStatus.AWAITING_APPROVAL.value, IncidentStatus.RESPONDING.value):
        # Nothing was remediated (only enrichment/notification, or a rejection): a person owns it now.
        _set_incident(db, inc, IncidentStatus.INVESTIGATING, ex.requested_by, "playbook finished; analyst review")


def run_execution(db: Session, ex: PlaybookExecution, actor: str = "system") -> PlaybookExecution:
    inc = db.get(Incident, ex.incident_id)
    if ex.status == ExecStatus.PENDING.value:
        _set_exec(ex, ExecStatus.RUNNING)
        ex.started_at = utcnow()
    elif ex.status != ExecStatus.RUNNING.value:
        raise StateError(f"execution is {ex.status}, cannot run")
    if inc.status in (IncidentStatus.NEW.value, IncidentStatus.INVESTIGATING.value):
        _set_incident(db, inc, IncidentStatus.RESPONDING, actor, f"playbook '{ex.playbook_name}' running")
    for step in ex.steps:
        if step.status in (StepStatus.SUCCEEDED.value, StepStatus.SKIPPED.value, StepStatus.REJECTED.value,
                           StepStatus.ROLLED_BACK.value):
            continue
        if step.status == StepStatus.AWAITING_APPROVAL.value:
            return ex
        if step.status != StepStatus.PENDING.value:  # RUNNING/FAILED left behind: never re-run
            _finish(db, ex, inc, ExecStatus.FAILED, f"step {step.step_key} in state {step.status}")
            return ex
        d = policy.evaluate(db, step.action, step.params, inc, step.approval_mode)
        if d.outcome == "deny":
            step.status, step.error = StepStatus.SKIPPED.value, f"denied by policy: {d.reason}"
            step.result = {"status": "skipped", "detail": step.error, "data": {}}
            timeline.add(db, inc, TimelineKind.ACTION.value, f"{step.action}: denied by policy", d.reason, actor="policy")
            continue
        if d.outcome == "approval":
            _request_approval(db, ex, step, inc, d)
            return ex
        _execute_step(db, ex, step, inc, actor)
        if step.status == StepStatus.FAILED.value:
            _finish(db, ex, inc, ExecStatus.FAILED, f"step {step.step_key} failed: {step.error}")
            return ex
    _finish(db, ex, inc, ExecStatus.COMPLETED)
    return ex


# ─── approvals ───
def decide(db: Session, approval_id: str, approve: bool, actor: str, actor_role: str, note: str = "",
           ip: str | None = None) -> Approval:
    ap = db.get(Approval, approval_id)
    if ap is None:
        raise LookupError("approval not found")
    now = utcnow()
    if ap.status == ApprovalStatus.PENDING.value and ap.expires_at and ap.expires_at < now:
        ap.status = ApprovalStatus.EXPIRED.value
        raise StateError("approval expired; re-run the action to request a new one")
    new = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
    claimed = db.execute(update(Approval).where(Approval.id == ap.id, Approval.status == ApprovalStatus.PENDING.value)
                         .values(status=new.value, decided_by=actor, decided_at=now, decision_note=note[:1000])).rowcount
    if claimed != 1:
        raise StateError(f"approval already {ap.status}")
    db.refresh(ap)
    inc = db.get(Incident, ap.incident_id)
    audit.record(db, actor=actor, actor_role=actor_role, action=f"approval_{new.value}", target_type="approval",
                 target_id=ap.id, ip=ip, data={"action": ap.action, "risk": ap.risk_level, "incident": inc.number})
    timeline.add(db, inc, TimelineKind.APPROVAL.value, f"{ap.action} {new.value} by {actor}", note, actor=actor,
                 data={"approval_id": ap.id})
    metrics.count(f"approvals_{new.value}")
    step, ex = db.get(ExecutionStep, ap.step_id), db.get(PlaybookExecution, ap.execution_id)
    if step is None or ex is None:
        return ap
    if approve:
        step.approval_mode, step.status = "approved", StepStatus.PENDING.value
        _set_exec(ex, ExecStatus.RUNNING)
        run_execution(db, ex, actor)
    else:
        step.status = StepStatus.REJECTED.value
        _finish(db, ex, inc, ExecStatus.REJECTED, f"{ap.action} rejected by {actor}")
    return ap


# ─── rollback ───
def rollback_execution(db: Session, ex: PlaybookExecution, actor: str) -> list[dict]:
    if ex.status not in (ExecStatus.COMPLETED.value, ExecStatus.FAILED.value):
        raise StateError(f"cannot roll back an execution that is {ex.status}")
    inc = db.get(Incident, ex.incident_id)
    out = []
    for step in reversed(ex.steps):
        action = ACTIONS.get(step.action)
        if step.status != StepStatus.SUCCEEDED.value or not action or not action.rollback:
            continue
        res = action.rollback(Ctx(db, inc, actor), step.params, ActionResult("succeeded", "", step.result.get("data", {})))
        step.rollback = {"status": res.status, "detail": res.detail, "by": actor, "at": utcnow().isoformat()}
        if res.status == "succeeded":
            step.status = StepStatus.ROLLED_BACK.value
        timeline.add(db, inc, TimelineKind.ACTION.value, f"Rollback {step.action}: {res.status}", res.detail, actor=actor)
        out.append({"step": step.step_key, "action": step.action, "status": res.status, "detail": res.detail})
    return out


# ─── automatic triggering ───
def auto_trigger(db: Session, inc: Incident) -> list[PlaybookExecution]:
    if not get_settings().auto_playbooks_enabled:
        return []
    ctx = incident_context(db, inc)
    started = []
    for pb in db.scalars(select(Playbook).where(Playbook.enabled.is_(True))):
        d = pb.definition
        if not matches_trigger(d, ctx) or not conditions_met(d.get("conditions", []), ctx)[0]:
            continue
        if db.scalar(select(PlaybookExecution.id).where(PlaybookExecution.incident_id == inc.id,
                                                        PlaybookExecution.playbook_name == pb.name).limit(1)):
            continue  # once per incident per playbook
        started.append(run_execution(db, create_execution(db, pb.name, pb.version, d["steps"], inc, "system"), "system"))
    return started
