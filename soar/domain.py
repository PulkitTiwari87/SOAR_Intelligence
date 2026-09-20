"""Domain vocabulary: roles, permissions, and the explicit state machines.

Nothing here touches the database. Invalid transitions are rejected by
`check_transition`, so a status can never be mutated arbitrarily.
"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    INCIDENT_RESPONDER = "INCIDENT_RESPONDER"
    VIEWER = "VIEWER"


class Perm(str, Enum):
    VIEW = "view"
    INCIDENT_WRITE = "incident:write"      # triage, notes, status changes, analyze
    PLAYBOOK_RUN = "playbook:run"
    APPROVE_MEDIUM = "approve:medium"
    APPROVE_HIGH = "approve:high"
    ANALYZE_ADHOC = "analyze:adhoc"        # run ad-hoc ML/phishing analysis
    ASSET_WRITE = "asset:write"
    USER_ADMIN = "user:admin"
    AUDIT_VIEW = "audit:view"
    CONFIG_VIEW = "config:view"


_ANALYST = {Perm.VIEW, Perm.INCIDENT_WRITE, Perm.PLAYBOOK_RUN, Perm.APPROVE_MEDIUM,
            Perm.ANALYZE_ADHOC, Perm.AUDIT_VIEW}
ROLE_PERMS: dict[Role, set[Perm]] = {
    Role.VIEWER: {Perm.VIEW},
    Role.SOC_ANALYST: _ANALYST,
    Role.INCIDENT_RESPONDER: _ANALYST | {Perm.APPROVE_HIGH, Perm.ASSET_WRITE},
    Role.ADMIN: set(Perm),
}


def has_perm(role: str, perm: Perm) -> bool:
    try:
        return perm in ROLE_PERMS[Role(role)]
    except ValueError:
        return False


class Severity(int, Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RESPONDING = "responding"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


_I = IncidentStatus
INCIDENT_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    _I.NEW: {_I.INVESTIGATING, _I.AWAITING_APPROVAL, _I.RESPONDING, _I.MONITORING,
             _I.RESOLVED, _I.FALSE_POSITIVE},
    _I.INVESTIGATING: {_I.AWAITING_APPROVAL, _I.RESPONDING, _I.MONITORING, _I.RESOLVED,
                       _I.FALSE_POSITIVE},
    _I.AWAITING_APPROVAL: {_I.INVESTIGATING, _I.RESPONDING, _I.MONITORING, _I.RESOLVED,
                           _I.FALSE_POSITIVE},
    _I.RESPONDING: {_I.INVESTIGATING, _I.AWAITING_APPROVAL, _I.MONITORING, _I.RESOLVED,
                    _I.FALSE_POSITIVE},
    _I.MONITORING: {_I.INVESTIGATING, _I.RESPONDING, _I.RESOLVED, _I.FALSE_POSITIVE},
    _I.RESOLVED: {_I.CLOSED, _I.INVESTIGATING},
    _I.FALSE_POSITIVE: {_I.CLOSED, _I.INVESTIGATING},
    _I.CLOSED: set(),
}
OPEN_STATUSES = {_I.NEW, _I.INVESTIGATING, _I.AWAITING_APPROVAL, _I.RESPONDING, _I.MONITORING}


class ExecStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


_E = ExecStatus
EXEC_TRANSITIONS: dict[ExecStatus, set[ExecStatus]] = {
    _E.PENDING: {_E.RUNNING, _E.CANCELLED},
    _E.RUNNING: {_E.AWAITING_APPROVAL, _E.COMPLETED, _E.FAILED, _E.CANCELLED},
    _E.AWAITING_APPROVAL: {_E.RUNNING, _E.REJECTED, _E.CANCELLED},
    _E.COMPLETED: set(), _E.FAILED: set(), _E.REJECTED: set(), _E.CANCELLED: set(),
}


class StepStatus(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"        # not executed (condition false, or no connector configured)
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


RISK_ORDER = {"none": -1, "low": 0, "medium": 1, "high": 2}


class TimelineKind(str, Enum):
    DETECTION = "detection"
    ALERT = "alert"
    CORRELATION = "correlation"
    ML_ANALYSIS = "ml_analysis"
    THREAT_INTEL = "threat_intel"
    MITRE = "mitre"
    LLM_ANALYSIS = "llm_analysis"
    APPROVAL = "approval"
    ACTION = "action"
    VERIFICATION = "verification"
    STATUS = "status"
    NOTE = "note"
    CLOSURE = "closure"


class InvalidTransition(ValueError):
    pass


def check_transition(table: dict, current, target) -> None:
    if target == current:
        return
    if target not in table.get(current, set()):
        raise InvalidTransition(f"Invalid transition {current.value} -> {target.value}")
