"""Built-in playbooks and the loader/validator.

A playbook is plain data:
  trigger     all listed constraints must hold: min_risk, min_severity, event_types (any of), mitre (any of)
              (a playbook with no trigger never auto-runs; it can still be started manually)
  conditions  extra checks on the incident context, e.g. {"field": "has_external_source_ip", "op": "eq", "value": true}
  steps       ordered actions; `approval`: "policy" (default; the response policy decides) or "required"
              (a human must approve regardless). Params may reference "$incident.<field>".

Edit or add playbooks by dropping JSON files with this shape into <DATA_DIR>/playbooks/.
"""
from __future__ import annotations

import json
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.config import get_settings
from soar.models import Playbook
from soar.playbooks.actions import ACTIONS

log = logging.getLogger("soar.playbooks")

BUILTIN: list[dict] = [
    {
        "name": "ssh_brute_force_response", "version": 1,
        "description": "Credential brute force from an external address: enrich, preserve evidence, notify, "
                       "block the source (policy decides whether a human must approve), open a case.",
        "trigger": {"event_types": ["authentication_failure"], "min_risk": 50},
        "conditions": [{"field": "has_external_source_ip", "op": "eq", "value": True}],
        "steps": [
            {"id": "enrich", "action": "enrich_ioc"},
            {"id": "evidence", "action": "collect_evidence"},
            {"id": "notify", "action": "notify_analyst"},
            {"id": "block", "action": "block_ip", "params": {"ip": "$incident.primary_source_ip", "ttl_hours": 24}},
            {"id": "case", "action": "create_case"},
        ],
    },
    {
        "name": "phishing_response", "version": 1,
        "description": "Phishing email: enrich extracted URLs/domains, preserve the email as evidence, notify, open a case.",
        "trigger": {"event_types": ["phishing_email"], "min_risk": 40},
        "conditions": [],
        "steps": [
            {"id": "enrich", "action": "enrich_ioc"},
            {"id": "evidence", "action": "collect_evidence"},
            {"id": "notify", "action": "notify_analyst"},
            {"id": "case", "action": "create_case"},
        ],
    },
    {
        "name": "suspicious_process_response", "version": 1,
        "description": "Suspicious process / malware detection: evidence, enrichment, notification, and host isolation "
                       "that ALWAYS requires human approval.",
        "trigger": {"event_types": ["suspicious_process", "malware_detection"], "min_risk": 60},
        "conditions": [],
        "steps": [
            {"id": "evidence", "action": "collect_evidence"},
            {"id": "enrich", "action": "enrich_ioc"},
            {"id": "notify", "action": "notify_analyst"},
            {"id": "isolate", "action": "isolate_host", "params": {"host": "$incident.primary_host"}, "approval": "required"},
            {"id": "case", "action": "create_case"},
        ],
    },
    {
        "name": "high_risk_triage", "version": 1,
        "description": "Any incident scoring 75+: preserve evidence and notify the SOC.",
        "trigger": {"min_risk": 75}, "conditions": [],
        "steps": [{"id": "evidence", "action": "collect_evidence"}, {"id": "notify", "action": "notify_analyst"}],
    },
]


def validate_definition(d: dict) -> list[str]:
    errs = []
    if not isinstance(d.get("name"), str) or not d["name"]:
        errs.append("name is required")
    steps = d.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("steps must be a non-empty list")
        return errs
    for i, s in enumerate(steps):
        if s.get("action") not in ACTIONS:
            errs.append(f"step {i + 1}: unknown action {s.get('action')!r}")
        if s.get("approval", "policy") not in ("policy", "required"):
            errs.append(f"step {i + 1}: approval must be 'policy' or 'required'")
    return errs


def _user_playbooks() -> list[dict]:
    d = get_settings().data_dir / "playbooks"
    out = []
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except (OSError, ValueError) as e:
            log.error("ignoring playbook file %s: %s", f.name, e)
    return out


def load_library(db: Session) -> int:
    """Upsert built-in and user playbooks. Returns how many were valid and loaded."""
    n = 0
    for d in BUILTIN + _user_playbooks():
        errs = validate_definition(d)
        if errs:
            log.error("playbook %r rejected: %s", d.get("name"), "; ".join(errs))
            continue
        row = db.scalar(select(Playbook).where(Playbook.name == d["name"]))
        if row is None:
            db.add(Playbook(name=d["name"], version=d.get("version", 1), description=d.get("description", ""),
                            definition=d))
        elif row.version != d.get("version", 1) or row.definition != d:
            row.version, row.description, row.definition = d.get("version", 1), d.get("description", ""), d
        n += 1
    db.flush()
    return n
