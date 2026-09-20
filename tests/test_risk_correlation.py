"""Risk scoring, correlation and the analysis pipeline (through the real ingest path)."""
from datetime import datetime, timedelta, UTC

import pytest

from soar.config import get_settings
from soar.models import Event, Incident
from soar.pipeline import risk
from soar.pipeline.ingest import ingest

T0 = datetime(2026, 3, 6, 12, 0, tzinfo=UTC)


def wazuh(ip="91.219.236.222", host="kali-vm-01", minutes=0, level=10, rule_id="100001", user="root",
          groups=("authentication_failures",), desc="Multiple SSH authentication failures", **extra):
    return {"timestamp": (T0 + timedelta(minutes=minutes)).isoformat(),
            "rule": {"id": rule_id, "level": level, "description": desc, "groups": list(groups),
                     "frequency": 5, "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}},
            "agent": {"id": "001", "name": host, "ip": "192.168.64.9"},
            "data": {"srcip": ip, "dstuser": user}, "full_log": f"sshd: Failed password for {user} from {ip}", **extra}


# ───────────── risk ─────────────
def test_weights_sum_to_one():
    assert sum(risk.WEIGHTS.values()) == pytest.approx(1.0)


def test_missing_signals_are_excluded_not_zeroed():
    full = risk.compute_risk({k: 0.8 for k in risk.WEIGHTS})
    partial = risk.compute_risk({"ml": 0.8, "severity": 0.8})
    assert full.score == pytest.approx(80.0) and partial.score == pytest.approx(80.0)
    assert full.confidence == 1.0 and partial.confidence == pytest.approx(0.45)
    assert partial.breakdown["ioc"]["available"] is False


def test_no_signals_gives_zero_risk_and_zero_confidence():
    r = risk.compute_risk({})
    assert (r.score, r.confidence, r.severity) == (0.0, 0.0, 1)


def test_risk_is_monotonic_in_each_signal():
    base = {k: 0.3 for k in risk.WEIGHTS}
    for k in risk.WEIGHTS:
        assert risk.compute_risk({**base, k: 0.9}).score > risk.compute_risk(base).score


@pytest.mark.parametrize("score,sev", [(0, 1), (34.9, 1), (35, 2), (59.9, 2), (60, 3), (79.9, 3), (80, 4), (100, 4)])
def test_severity_cutoffs(score, sev):
    assert risk.severity_from_score(score) == sev


def test_signals_are_clamped():
    assert risk.compute_risk({"ml": 5.0, "severity": -2}).score == pytest.approx(100 * 0.25 / 0.45, abs=0.1)


# ───────────── correlation ─────────────
def test_same_external_ip_correlates_into_one_incident(db):
    a = ingest(db, "wazuh", wazuh(minutes=0))
    b = ingest(db, "wazuh", wazuh(minutes=3, host="web-server-01"))
    db.commit()
    assert a.created_incident and not b.created_incident
    assert a.incident.id == b.incident.id and b.incident.event_count == 2
    assert any("same external IP" in r for r in b.reasons)
    assert set(b.incident.entities["hosts"]) == {"kali-vm-01", "web-server-01"}


def test_unrelated_events_open_separate_incidents(db):
    a = ingest(db, "wazuh", wazuh(ip="45.33.32.156", host="h1"))
    b = ingest(db, "wazuh", wazuh(ip="185.220.101.44", host="h2"))
    assert a.incident.id != b.incident.id


def test_shared_host_alone_does_not_correlate(db):
    a = ingest(db, "wazuh", wazuh(ip="45.33.32.156", user="alice", rule_id="1"))
    b = ingest(db, "wazuh", wazuh(ip="185.220.101.44", user="bob", rule_id="2"))
    assert a.incident.id != b.incident.id  # host(2.0) < threshold(3.0)


def test_host_plus_user_correlates(db):
    a = ingest(db, "wazuh", wazuh(ip="45.33.32.156", user="alice", rule_id="1"))
    b = ingest(db, "wazuh", wazuh(ip="185.220.101.44", user="alice", rule_id="2"))
    assert a.incident.id == b.incident.id  # host(2.0) + user(1.0)


def test_time_window_is_respected(db):
    a = ingest(db, "wazuh", wazuh(minutes=0))
    far = get_settings().correlation_window_minutes + 10
    b = ingest(db, "wazuh", wazuh(minutes=far))
    assert a.incident.id != b.incident.id


def test_closed_incidents_do_not_absorb_new_events(db):
    a = ingest(db, "wazuh", wazuh(minutes=0))
    a.incident.status = "closed"
    db.flush()
    b = ingest(db, "wazuh", wazuh(minutes=1))
    assert b.created_incident and b.incident.id != a.incident.id


def test_duplicate_event_is_idempotent(db):
    payload = wazuh()
    a, b = ingest(db, "wazuh", payload), ingest(db, "wazuh", dict(payload))
    db.commit()
    assert b.duplicate and a.event.id == b.event.id
    assert db.query(Event).count() == 1 and a.incident.event_count == 1


def test_low_severity_events_are_stored_without_incident(db):
    r = ingest(db, "syslog", "Mar  6 12:00:01 h1 sshd[1]: Accepted password for bob from 10.0.0.5 port 22 ssh2")
    db.commit()
    assert r.incident is None and db.query(Event).count() == 1 and db.query(Incident).count() == 0


def test_loopback_addresses_never_correlate(db):
    a = ingest(db, "generic", {"event_type": "x", "severity": 3, "src_ip": "127.0.0.1", "host": "a", "timestamp": T0.isoformat()})
    b = ingest(db, "generic", {"event_type": "y", "severity": 3, "src_ip": "127.0.0.1", "host": "b", "timestamp": T0.isoformat()})
    assert a.incident.id != b.incident.id


def test_incident_numbers_are_sequential_and_unique(db):
    nums = [ingest(db, "wazuh", wazuh(ip=f"45.33.32.{i}", host=f"h{i}")).incident.number for i in range(1, 4)]
    assert nums == sorted(set(nums)) and nums[0].startswith(f"INC-{datetime.now(UTC).year}-0001")


# ───────────── analysis pipeline ─────────────
def test_ingest_runs_full_analysis(db):
    r = ingest(db, "wazuh", wazuh())
    db.commit()
    inc = r.incident
    kinds = {p.kind for p in inc.predictions}
    assert {"triage", "anomaly"} <= kinds
    assert inc.risk_score > 0 and set(inc.risk_breakdown) == set(risk.WEIGHTS)
    ids = {(m.technique_id, m.source) for m in inc.mitre}
    assert ("T1110", "wazuh_rule") in ids
    tl = [t.kind for t in inc.timeline]
    for expected in ("detection", "alert", "ml_analysis", "mitre"):
        assert expected in tl, tl
    assert inc.summary.endswith("[automated summary]")


def test_threat_intel_feed_hit_raises_risk(db, tmp_path):
    base = ingest(db, "wazuh", wazuh(ip="5.188.10.180", host="a1")).incident.risk_score
    feeds = get_settings().data_dir / "intel"
    feeds.mkdir(parents=True, exist_ok=True)
    (feeds / "test-feed.txt").write_text("# test\n104.244.72.115\n")
    hit = ingest(db, "wazuh", wazuh(ip="104.244.72.115", host="a2"))
    assert hit.incident.risk_score > base
    assert hit.incident.risk_breakdown["ioc"]["value"] > 0
    assert any(t.kind == "threat_intel" and "104.244.72.115" in t.detail for t in hit.incident.timeline)


def test_unknown_ioc_is_treated_as_missing_evidence_not_safe(db):
    r = ingest(db, "wazuh", wazuh(ip="45.33.32.5"))
    assert r.incident.risk_breakdown["ioc"]["available"] is False


def test_asset_criticality_feeds_risk(db):
    from soar.models import Asset
    db.add(Asset(hostname="dc-01", ip="192.168.64.13", criticality=10, role="domain_controller"))
    db.commit()
    hi = ingest(db, "wazuh", wazuh(ip="45.33.32.5", host="dc-01"))
    assert hi.incident.risk_breakdown["asset"]["value"] == 1.0
    lo = ingest(db, "wazuh", wazuh(ip="45.33.32.6", host="unknown-host"))
    assert lo.incident.risk_breakdown["asset"]["available"] is False


def test_phishing_email_creates_incident_with_iocs(db):
    raw = ("From: PayPal Support <help@paypa1-secure-login.top>\nTo: victim@corp.test\nSubject: Account limited\n"
           "Reply-To: x@evil.test\n\nYour account is limited. Verify immediately: http://paypa1-secure-login.top/verify")
    r = ingest(db, "email", {"raw": raw})
    db.commit()
    inc = r.incident
    assert inc is not None and r.event.event_type == "phishing_email"
    values = {i.value for i in inc.iocs}
    assert "paypa1-secure-login.top" in values and any(v.startswith("http://paypa1") for v in values)
    assert any(m.technique_id == "T1566.002" for m in inc.mitre)
    assert r.event.raw_event["raw"] == raw  # original email preserved as evidence
