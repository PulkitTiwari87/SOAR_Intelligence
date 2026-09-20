"""REST API: ingestion auth, incident listing/filters, actions and RBAC, security controls."""
import socket
from datetime import datetime, timedelta, UTC

import pytest

from soar.models import Asset, AssetLink
from soar.simulate import brute_force, phishing

KEY = {"X-API-Key": "test-ingest-key"}


def send(client, scenario, headers=KEY):
    last = None
    for source, payload in scenario:
        r = client.post("/api/events", json={"source": source, "payload": payload}, headers=headers)
        assert r.status_code == 200, r.text
        last = r.json()["results"][0]
    return last


# ─────────── ingestion auth & validation ───────────
def test_ingest_requires_credentials(client):
    body = {"source": "generic", "payload": {"event_type": "x", "severity": 3}}
    assert client.post("/api/events", json=body).status_code == 401
    assert client.post("/api/events", json=body, headers={"X-API-Key": "wrong"}).status_code == 401


def test_viewer_cannot_ingest_but_analyst_can(client, login):
    body = {"source": "generic", "payload": {"event_type": "x", "severity": 3, "host": "h"}}
    assert client.post("/api/events", json=body, headers=login("v1", "VIEWER")).status_code == 403
    assert client.post("/api/events", json=body, headers=login("a1", "SOC_ANALYST")).status_code == 200


def test_ingest_batch_limit_and_bad_payloads(client):
    ok = {"event_type": "x", "severity": 2, "host": "h"}
    assert client.post("/api/events", json={"source": "generic", "payloads": [ok] * 201}, headers=KEY).status_code == 422
    r = client.post("/api/events", json={"source": "nope", "payload": {}}, headers=KEY)
    assert r.status_code == 200 and "error" in r.json()["results"][0]
    assert client.post("/api/events", json={"source": "generic"}, headers=KEY).status_code == 422


def test_ingest_is_idempotent_over_http(client, admin):
    first = send(client, brute_force()[:1])
    again = send(client, brute_force()[:1])  # same payload timestamps? new base time => new event; resend exact body:
    payload = {"source": "generic", "payload": {"event_type": "dup", "severity": 3, "host": "hh", "timestamp": "2026-01-01T00:00:00Z"}}
    a = client.post("/api/events", json=payload, headers=KEY).json()["results"][0]
    b = client.post("/api/events", json=payload, headers=KEY).json()["results"][0]
    assert b["duplicate"] is True and a["event_id"] == b["event_id"] and first and again


# ─────────── listing / filters / detail ───────────
@pytest.fixture
def populated(client):
    send(client, brute_force())
    send(client, phishing())


def test_list_filters_and_pagination(client, admin, populated):
    allr = client.get("/api/incidents", headers=admin).json()
    assert allr["pagination"]["total"] == 2
    by_cat = {i["category"]: i for i in allr["incidents"]}
    assert set(by_cat) == {"authentication_failure", "phishing_email"}
    q = lambda **p: client.get("/api/incidents", params=p, headers=admin).json()  # noqa: E731
    assert q(source="email")["pagination"]["total"] == 1
    assert q(mitre="T1566")["pagination"]["total"] == 1 and q(mitre="t1110")["pagination"]["total"] == 1
    assert q(status="investigating")["pagination"]["total"] + q(status="awaiting_approval")["pagination"]["total"] == 2
    assert q(asset="kali")["pagination"]["total"] == 1
    assert q(q="INC-")["pagination"]["total"] == 2 and q(q="nothing-matches")["pagination"]["total"] == 0
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert q(date_from=future)["pagination"]["total"] == 0
    assert q(limit=1, page=2)["incidents"].__len__() == 1


def test_incident_detail_has_everything_the_dashboard_needs(client, admin, populated):
    number = next(i["number"] for i in client.get("/api/incidents", headers=admin).json()["incidents"]
                  if i["category"] == "authentication_failure")
    d = client.get(f"/api/incidents/{number}", headers=admin).json()
    for key in ("timeline", "events", "iocs", "mitre", "analysis", "executions", "approvals", "risk_breakdown", "entities"):
        assert d[key] not in (None,), key
    assert d["analysis"]["triage"]["prediction"] and d["timeline"][0]["kind"] == "detection"
    assert any(e["raw_event"] for e in d["events"]) and d["approvals"][0]["status"] == "pending"
    assert client.get("/api/incidents/INC-0000-9999", headers=admin).status_code == 404


def test_stats_are_computed_from_data_not_invented(client, admin):
    empty = client.get("/api/incidents/stats", headers=admin).json()
    assert empty["total"] == 0 and empty["mttr_seconds"] is None and empty["mttd_seconds"] is None
    send(client, brute_force())
    s = client.get("/api/incidents/stats", headers=admin).json()
    assert s["total"] == 1 and s["active"] == 1 and s["pending_approvals"] == 1 and s["alerts_today"] >= 1
    assert s["mttd_seconds"] is not None and s["mttr_seconds"] is None  # nothing resolved yet
    assert s["top_mitre"][0]["id"] == "T1110"


# ─────────── analyst actions / RBAC ───────────
def test_action_state_machine_and_rbac(client, login, populated):
    analyst, viewer = login("an1", "SOC_ANALYST"), login("vw1", "VIEWER")
    inc = client.get("/api/incidents", headers=analyst).json()["incidents"][0]["number"]
    act = lambda h, a: client.post(f"/api/incidents/{inc}/action", json={"action": a}, headers=h)  # noqa: E731
    assert act(viewer, "investigate").status_code == 403
    assert act(analyst, "bogus").status_code == 422
    assert act(analyst, "resolve").status_code == 200
    r = client.get(f"/api/incidents/{inc}", headers=analyst).json()
    assert r["status"] == "resolved" and r["resolved_at"]
    assert act(analyst, "close").status_code == 200
    assert act(analyst, "investigate").status_code == 409  # closed is terminal
    stats = client.get("/api/incidents/stats", headers=analyst).json()
    assert stats["mttr_seconds"] is not None


def test_notes_are_added_to_timeline(client, admin, populated):
    inc = client.get("/api/incidents", headers=admin).json()["incidents"][0]["number"]
    assert client.post(f"/api/incidents/{inc}/notes", json={"text": "called the owner"}, headers=admin).status_code == 201
    tl = client.get(f"/api/incidents/{inc}", headers=admin).json()["timeline"]
    assert any(t["kind"] == "note" and "called the owner" in t["detail"] for t in tl)


def test_audit_log_is_role_protected_and_records_actions(client, login, populated):
    viewer, analyst = login("vw2", "VIEWER"), login("an2", "SOC_ANALYST")
    assert client.get("/api/system/audit", headers=viewer).status_code == 403
    inc = client.get("/api/incidents", headers=analyst).json()["incidents"][0]["number"]
    client.post(f"/api/incidents/{inc}/action", json={"action": "investigate"}, headers=analyst)
    logs = client.get("/api/system/audit", headers=analyst).json()["logs"]
    actions = {(l["action"], l["actor"]) for l in logs}  # noqa: E741
    assert ("incident_action", "an2") in actions and ("events_ingest", "ingest-key") in actions


# ─────────── security controls ───────────
@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "internal", "a..b", "x;rm -rf /.com", "http://[::1]"])
def test_certificate_check_rejects_bad_hostnames(client, admin, host):
    assert client.post("/api/ai/certificate", json={"url": host}, headers=admin).status_code == 422


def test_certificate_check_refuses_hosts_resolving_to_private_addresses(client, admin, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.7", 443))])
    r = client.post("/api/ai/certificate", json={"url": "https://evil.example.com"}, headers=admin)
    assert r.status_code == 422 and "non-public" in r.text


def test_ai_input_validation(client, admin):
    assert client.post("/api/ai/triage", json={"rule_level": 99}, headers=admin).status_code == 422
    assert client.post("/api/ai/anomaly", json={"metrics": {"bogus": 1}}, headers=admin).status_code == 422
    assert client.post("/api/ai/phishing", json={}, headers=admin).status_code == 422
    ok = client.post("/api/ai/triage", json={"rule_level": 12, "failed_logins": 50}, headers=admin)
    assert ok.status_code == 200 and ok.json()["model_version"]


def test_report_download_blocks_path_traversal_and_missing_files(client, admin):
    for name in ("..%2F..%2Fetc%2Fpasswd", "..%5C..%5Csecret.pdf", "nope.pdf"):
        assert client.get(f"/api/incidents/reports/download/{name}", headers=admin).status_code == 404


def test_errors_do_not_leak_internals(client, admin):
    r = client.get("/api/incidents/xyz", headers=admin)
    assert r.status_code == 404 and "Traceback" not in r.text and "sqlalchemy" not in r.text.lower()
    assert client.get("/api/openapi.json").status_code == 200  # docs only exist outside production


def test_security_headers_present(client):
    h = client.get("/api/health").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["x-request-id"]


def test_health_endpoints_report_real_state(client, admin):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/ready").json()["database"] == "up"
    h = client.get("/api/system/health", headers=admin).json()
    assert h["database"]["ok"] and set(h["models"]) == {"triage", "anomaly", "phishing"}
    assert h["llm"]["configured"] is False  # tests run with LLM_PROVIDER=none
    integ = {i["name"]: i["status"] for i in client.get("/api/system/integrations", headers=admin).json()["integrations"]}
    assert integ["wazuh_api"] == "not_configured" and integ["misp"] == "not_configured"


def test_metrics_endpoint_counts_pipeline_activity(client, admin):
    send(client, brute_force())
    m = client.get("/api/system/metrics", headers=admin).json()
    assert m["counters"]["events_ingested"] >= 9 and m["counters"]["incidents_created"] >= 1
    assert "analysis_ms" in m["latency_ms"] and m["database_counts"]["incidents"] == 1


# ─────────── assets / graph ───────────
def test_asset_management_and_graph(client, login):
    resp, viewer = login("ir1", "INCIDENT_RESPONDER"), login("vw3", "VIEWER")
    assert client.post("/api/assets", json={"hostname": "a", "criticality": 5}, headers=viewer).status_code == 403
    for h, c in (("web-01", 6), ("db-01", 9)):
        assert client.post("/api/assets", json={"hostname": h, "criticality": c, "role": "srv"}, headers=resp).status_code == 201
    assert client.post("/api/assets/links", json={"src": "web-01", "dst": "db-01", "protocol": "mysql", "port": 3306}, headers=resp).status_code == 201
    assert client.post("/api/assets/links", json={"src": "web-01", "dst": "ghost"}, headers=resp).status_code == 404
    g = client.get("/api/assets/graph?highlight=web-01", headers=viewer).json()
    assert {n["id"] for n in g["nodes"]} == {"web-01", "db-01"} and g["edges"][0]["port"] == 3306
    assert next(n for n in g["nodes"] if n["id"] == "web-01")["compromised"] is True
    assert client.post("/api/assets", json={"hostname": "x", "criticality": 11}, headers=resp).status_code == 422
    assert Asset and AssetLink
