"""Response policy, playbook engine, approvals, verification and rollback."""
import hashlib
from pathlib import Path

import pytest
from sqlalchemy import select

from soar.config import get_settings, reset_settings
from soar.domain import (INCIDENT_TRANSITIONS, ExecStatus, IncidentStatus, InvalidTransition, StepStatus,
                         check_transition)
from soar.models import Approval, BlocklistEntry, Notification, PlaybookExecution, TimelineEntry, utcnow
from soar.pipeline.ingest import ingest
from soar.playbooks import engine, policy
from soar.playbooks.library import BUILTIN, load_library, validate_definition
from soar.simulate import brute_force, malware


@pytest.fixture
def playbooks(db):
    load_library(db)
    db.commit()


def run(db, scenario):
    last = None
    for src, payload in scenario:
        last = ingest(db, src, payload)
    db.commit()
    return last.incident


def execution(db, inc, name):
    return db.scalar(select(PlaybookExecution).where(PlaybookExecution.incident_id == inc.id,
                                                     PlaybookExecution.playbook_name == name))


def step(ex, action):
    return next(s for s in ex.steps if s.action == action)


# ─────────────── policy ───────────────
def test_low_risk_actions_are_automatic_by_default(db):
    for a in ("enrich_ioc", "notify_analyst", "collect_evidence", "create_case"):
        assert policy.evaluate(db, a, {}).outcome == "auto"


def test_block_ip_needs_approval_under_default_ceiling(db):
    d = policy.evaluate(db, "block_ip", {"ip": "91.219.236.222"})
    assert (d.outcome, d.risk) == ("approval", "medium")


def test_ceiling_medium_lets_block_ip_run_automatically(db, monkeypatch):
    monkeypatch.setenv("AUTO_EXECUTE_MAX_RISK", "medium")
    reset_settings()
    assert policy.evaluate(db, "block_ip", {"ip": "91.219.236.222"}).outcome == "auto"


def test_high_risk_always_needs_approval_even_with_permissive_config(db, monkeypatch):
    monkeypatch.setenv("AUTO_EXECUTE_MAX_RISK", "medium")
    reset_settings()
    assert policy.evaluate(db, "isolate_host", {"host": "web-server-01"}).outcome == "approval"
    assert policy.evaluate(db, "disable_account", {"user": "bob"}).outcome == "approval"


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "not-an-ip", ""])
def test_protected_or_invalid_ips_can_never_be_blocked(db, ip):
    assert policy.evaluate(db, "block_ip", {"ip": ip}).outcome == "deny"


def test_protected_ips_setting_is_honoured(db, monkeypatch):
    monkeypatch.setenv("PROTECTED_IPS", "8.8.8.0/24")
    reset_settings()
    assert policy.evaluate(db, "block_ip", {"ip": "8.8.8.8"}).outcome == "deny"


def test_unknown_action_and_missing_target_are_denied(db):
    assert policy.evaluate(db, "rm_rf", {}).outcome == "deny"
    assert policy.evaluate(db, "isolate_host", {}).outcome == "deny"


def test_playbook_can_tighten_but_deny_survives_human_approval(db):
    assert policy.evaluate(db, "notify_analyst", {}, approval_mode="required").outcome == "approval"
    assert policy.evaluate(db, "block_ip", {"ip": "10.0.0.5"}, approval_mode="approved").outcome == "deny"


# ─────────────── state machines ───────────────
def test_invalid_incident_transition_is_rejected():
    with pytest.raises(InvalidTransition):
        check_transition(INCIDENT_TRANSITIONS, IncidentStatus.CLOSED, IncidentStatus.NEW)
    with pytest.raises(InvalidTransition):
        check_transition(INCIDENT_TRANSITIONS, IncidentStatus.RESOLVED, IncidentStatus.RESPONDING)
    check_transition(INCIDENT_TRANSITIONS, IncidentStatus.NEW, IncidentStatus.INVESTIGATING)


def test_builtin_playbooks_are_valid_and_reject_bad_definitions():
    assert all(validate_definition(d) == [] for d in BUILTIN)
    assert validate_definition({"name": "x", "steps": [{"action": "format_disk"}]})
    assert validate_definition({"name": "x", "steps": []})
    assert validate_definition({"name": "x", "steps": [{"action": "block_ip", "approval": "maybe"}]})


# ─────────────── engine + approvals ───────────────
def test_auto_playbook_runs_low_risk_steps_then_waits_for_block_approval(db, playbooks):
    inc = run(db, brute_force())
    ex = execution(db, inc, "ssh_brute_force_response")
    assert ex.status == ExecStatus.AWAITING_APPROVAL.value
    assert [s.status for s in ex.steps] == ["succeeded", "succeeded", "succeeded", "awaiting_approval", "pending"]
    assert inc.status == IncidentStatus.AWAITING_APPROVAL.value
    ap = db.scalar(select(Approval))
    assert (ap.action, ap.status, ap.risk_level) == ("block_ip", "pending", "medium")
    assert ap.params["ip"] == "91.219.236.222"
    assert db.scalar(select(BlocklistEntry)) is None  # nothing blocked yet


def test_approve_executes_verifies_and_completes(db, playbooks):
    inc = run(db, brute_force())
    ap = db.scalar(select(Approval))
    engine.decide(db, ap.id, True, "resp1", "INCIDENT_RESPONDER", "confirmed attacker")
    db.commit()
    ex = execution(db, inc, "ssh_brute_force_response")
    blk = step(ex, "block_ip")
    assert blk.status == StepStatus.SUCCEEDED.value and blk.verified is True
    assert "soar_blocklist" in blk.result["data"]["enforcement"]
    assert db.scalar(select(BlocklistEntry).where(BlocklistEntry.ip == "91.219.236.222")).active
    assert ex.status == ExecStatus.COMPLETED.value
    assert step(ex, "create_case").status == StepStatus.SKIPPED.value  # TheHive not configured: reported, not faked
    assert inc.status == IncidentStatus.MONITORING.value and inc.auto_handled is False
    db.refresh(inc)  # timeline rows were added by id; reload the collection
    kinds = [t.kind for t in inc.timeline]
    for k in ("approval", "action", "verification"):
        assert k in kinds
    assert db.get(Approval, ap.id).decided_by == "resp1"


def test_block_verification_states_what_is_and_is_not_enforced(db, playbooks):
    inc = run(db, brute_force())
    engine.decide(db, db.scalar(select(Approval)).id, True, "resp1", "INCIDENT_RESPONDER")
    v = step(execution(db, inc, "ssh_brute_force_response"), "block_ip").verification["detail"]
    assert "SOAR blocklist only" in v  # no Wazuh configured: must not claim network enforcement


def test_reject_stops_execution_without_acting(db, playbooks):
    inc = run(db, brute_force())
    ap = db.scalar(select(Approval))
    engine.decide(db, ap.id, False, "resp1", "INCIDENT_RESPONDER", "false alarm")
    ex = execution(db, inc, "ssh_brute_force_response")
    assert ex.status == ExecStatus.REJECTED.value
    assert step(ex, "block_ip").status == StepStatus.REJECTED.value
    assert step(ex, "create_case").status == StepStatus.PENDING.value  # never ran
    assert db.scalar(select(BlocklistEntry)) is None
    assert inc.status == IncidentStatus.INVESTIGATING.value


def test_an_approval_can_be_decided_only_once(db, playbooks):
    run(db, brute_force())
    ap = db.scalar(select(Approval))
    engine.decide(db, ap.id, True, "resp1", "INCIDENT_RESPONDER")
    with pytest.raises(engine.StateError):
        engine.decide(db, ap.id, True, "resp2", "INCIDENT_RESPONDER")
    with pytest.raises(engine.StateError):
        engine.decide(db, ap.id, False, "resp2", "INCIDENT_RESPONDER")
    assert db.query(BlocklistEntry).count() == 1


def test_expired_approval_cannot_be_used(db, playbooks):
    run(db, brute_force())
    ap = db.scalar(select(Approval))
    ap.expires_at = utcnow().replace(year=2020)
    db.flush()
    with pytest.raises(engine.StateError, match="expired"):
        engine.decide(db, ap.id, True, "resp1", "INCIDENT_RESPONDER")
    assert db.query(BlocklistEntry).count() == 0


def test_auto_trigger_runs_once_per_incident_per_playbook(db, playbooks):
    inc = run(db, brute_force())
    assert engine.auto_trigger(db, inc) == []
    assert db.query(PlaybookExecution).filter_by(incident_id=inc.id, playbook_name="ssh_brute_force_response").count() == 1


def test_rollback_reverses_the_block(db, playbooks):
    inc = run(db, brute_force())
    engine.decide(db, db.scalar(select(Approval)).id, True, "resp1", "INCIDENT_RESPONDER")
    ex = execution(db, inc, "ssh_brute_force_response")
    result = engine.rollback_execution(db, ex, "resp1")
    assert result and result[0]["action"] == "block_ip" and result[0]["status"] == "succeeded"
    assert not db.scalar(select(BlocklistEntry)).active
    assert step(ex, "block_ip").status == StepStatus.ROLLED_BACK.value


def test_rollback_refused_while_execution_is_waiting(db, playbooks):
    inc = run(db, brute_force())
    with pytest.raises(engine.StateError):
        engine.rollback_execution(db, execution(db, inc, "ssh_brute_force_response"), "x")


def test_isolate_host_without_a_connector_is_skipped_never_faked(db, playbooks):
    inc = run(db, malware())
    ex = execution(db, inc, "suspicious_process_response")
    ap = db.scalar(select(Approval).where(Approval.action == "isolate_host"))
    assert ap.risk_level == "high" and step(ex, "isolate_host").status == "awaiting_approval"
    engine.decide(db, ap.id, True, "resp1", "INCIDENT_RESPONDER")
    iso = step(ex, "isolate_host")
    assert iso.status == StepStatus.SKIPPED.value and "no connector configured" in iso.result["detail"]
    assert inc.status != IncidentStatus.MONITORING.value  # nothing was remediated


def test_adhoc_block_of_private_ip_is_denied_by_policy(db, playbooks):
    inc = run(db, brute_force())
    ex = engine.run_adhoc(db, inc, [{"action": "block_ip", "target": "10.0.0.5"}], "analyst1")
    s = ex.steps[0]
    assert s.status == StepStatus.SKIPPED.value and "denied by policy" in s.error
    assert db.scalar(select(BlocklistEntry).where(BlocklistEntry.ip == "10.0.0.5")) is None


def test_evidence_snapshot_is_written_and_hash_verified(db, playbooks):
    inc = run(db, brute_force())
    s = step(execution(db, inc, "ssh_brute_force_response"), "collect_evidence")
    path = Path(s.result["data"]["path"])
    assert path.is_file() and s.verified is True
    assert hashlib.sha256(path.read_bytes()).hexdigest() == s.result["data"]["sha256"]
    assert str(get_settings().evidence_dir) in str(path)
    path.write_bytes(b"tampered")  # verification must notice
    from soar.playbooks.actions import ACTIONS, ActionResult, Ctx
    v = ACTIONS["collect_evidence"].verify(Ctx(db, inc), {}, ActionResult("succeeded", "", s.result["data"]))
    assert v.verified is False


def test_notify_creates_a_notification_row(db, playbooks):
    inc = run(db, brute_force())
    n = db.scalar(select(Notification).where(Notification.incident_id == inc.id))
    assert n is not None and inc.number in n.message


def test_playbook_conditions_gate_execution(db, playbooks):
    from soar.pipeline.normalizer import normalize  # noqa: F401  (ensures module import path is healthy)
    inc = run(db, brute_force())
    inc.primary_source_ip = "10.1.1.1"  # internal source: brute-force playbook requires an external one
    db.flush()
    with pytest.raises(engine.StateError, match="does not apply"):
        engine.start_playbook(db, "ssh_brute_force_response", inc, "analyst1")


def test_every_step_is_recorded_on_the_timeline(db, playbooks):
    inc = run(db, brute_force())
    titles = [t.title for t in db.scalars(select(TimelineEntry).where(TimelineEntry.incident_id == inc.id))]
    assert any("Playbook 'ssh_brute_force_response' started" in t for t in titles)
    assert any(t.startswith("enrich_ioc") for t in titles) and any("Approval requested" in t for t in titles)
