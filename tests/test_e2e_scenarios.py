"""End-to-end security scenarios through the HTTP API (the same events `soar.cli simulate` sends)."""
from soar.simulate import ATTACKER, brute_force, malware, phishing

KEY = {"X-API-Key": "test-ingest-key"}


def feed(client, scenario):
    out = []
    for source, payload in scenario:
        r = client.post("/api/events", json={"source": source, "payload": payload}, headers=KEY)
        assert r.status_code == 200, r.text
        out.append(r.json()["results"][0])
    return out


def timeline_kinds(client, headers, number):
    return {t["kind"] for t in client.get(f"/api/incidents/{number}", headers=headers).json()["timeline"]}


def test_brute_force_event_to_response_to_report(client, login):
    """syslog failures + Wazuh alert -> correlation -> ML -> MITRE -> incident -> playbook -> approval -> block -> verify -> report."""
    analyst, responder = login("soc1", "SOC_ANALYST"), login("ir1", "INCIDENT_RESPONDER")
    results = feed(client, brute_force())
    numbers = {r["incident_number"] for r in results}
    assert len(numbers) == 1 and results[0]["created_incident"] and not results[-1]["created_incident"]
    number = numbers.pop()

    inc = client.get(f"/api/incidents/{number}", headers=analyst).json()
    assert inc["event_count"] == 9 and inc["primary_source_ip"] == ATTACKER
    assert inc["analysis"]["triage"]["prediction"] == "malicious" and inc["risk_score"] >= 60
    assert {"T1110"} <= {m["technique_id"] for m in inc["mitre"]}
    assert inc["status"] == "awaiting_approval"
    exe = inc["executions"][0]
    assert [s["status"] for s in exe["steps"][:3]] == ["succeeded"] * 3  # enrich, evidence, notify ran automatically
    approval = inc["approvals"][0]
    assert approval["action"] == "block_ip" and approval["status"] == "pending" and approval["risk"] == "medium"

    # nothing is blocked before a human decides
    assert client.get("/api/blocklist.txt", headers=KEY).text.strip() == ""

    # a viewer cannot decide; an analyst can decide medium-risk approvals
    viewer = login("vw", "VIEWER")
    assert client.post(f"/api/approvals/{approval['id']}/decide", json={"approve": True}, headers=viewer).status_code == 403
    r = client.post(f"/api/approvals/{approval['id']}/decide", json={"approve": True, "note": "confirmed"}, headers=analyst)
    assert r.status_code == 200 and r.json()["decided_by"] == "soc1"
    # ...and only once
    assert client.post(f"/api/approvals/{approval['id']}/decide", json={"approve": True}, headers=responder).status_code == 409

    inc = client.get(f"/api/incidents/{number}", headers=analyst).json()
    block = next(s for e in inc["executions"] for s in e["steps"] if s["action"] == "block_ip")
    assert block["status"] == "succeeded" and block["verified"] is True
    assert client.get("/api/blocklist.txt", headers=KEY).text.split() == [ATTACKER]
    assert inc["status"] == "monitoring"
    assert {"detection", "alert", "correlation", "ml_analysis", "threat_intel", "mitre", "approval", "action",
            "verification"} <= timeline_kinds(client, analyst, number)

    # rollback removes the block (recorded, audited)
    ex_id = inc["executions"][0]["id"]
    assert client.post(f"/api/executions/{ex_id}/rollback", headers=analyst).status_code == 200
    assert client.get("/api/blocklist.txt", headers=KEY).text.strip() == ""

    # report distinguishes facts / analysis / recommendations / actions
    assert client.post(f"/api/incidents/{number}/report", headers=analyst).status_code == 200
    pdf = client.get(f"/api/incidents/{number}/report/download", headers=analyst)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and len(pdf.content) > 2000
    assert client.get("/api/incidents/reports/all", headers=analyst).json()["reports"][0]["filename"] == f"{number}.pdf"

    audit = {(a["action"], a["result"]) for a in client.get("/api/system/audit?limit=200", headers=analyst).json()["logs"]}
    assert ("approval_approved", "success") in audit and ("execution_rollback", "success") in audit
    assert ("approval_decide", "forbidden") in audit  # the viewer's attempt was recorded too


def test_phishing_email_to_incident_with_iocs_and_actions(client, login):
    analyst = login("soc2", "SOC_ANALYST")
    (res,) = feed(client, phishing())
    inc = client.get(f"/api/incidents/{res['incident_number']}", headers=analyst).json()
    assert inc["category"] == "phishing_email" and inc["severity"] >= 3
    ioc_values = {i["value"] for i in inc["iocs"]}
    assert "micros0ft-365-verify.top" in ioc_values and any(v.startswith("http://micros0ft") for v in ioc_values)
    assert {"T1566", "T1566.002"} <= {m["technique_id"] for m in inc["mitre"]}
    email = inc["events"][0]["raw_event"]["raw"]
    assert "micros0ft-365-verify.top" in email  # original email kept as evidence
    ex = inc["executions"][0]
    assert ex["playbook"] == "phishing_response" and ex["status"] == "completed"
    steps = {s["action"]: s for s in ex["steps"]}
    assert steps["collect_evidence"]["verified"] is True and steps["enrich_ioc"]["status"] == "succeeded"
    assert steps["create_case"]["status"] == "skipped"  # TheHive absent: honestly skipped
    assert inc["status"] == "investigating" and not inc["approvals"]  # nothing high-impact was attempted
    intel = client.get("/api/intel/iocs", headers=analyst).json()["iocs"]
    assert {i["value"] for i in intel} >= {"micros0ft-365-verify.top"}


def test_malware_reverse_shell_requires_human_approval_for_isolation(client, login):
    analyst, responder = login("soc3", "SOC_ANALYST"), login("ir3", "INCIDENT_RESPONDER")
    results = feed(client, malware())
    assert len({r["incident_number"] for r in results}) == 1  # shell command + C2 connection correlate
    number = results[0]["incident_number"]
    inc = client.get(f"/api/incidents/{number}", headers=analyst).json()
    assert {"T1059"} <= {m["technique_id"] for m in inc["mitre"]}
    assert "185.220.101.44" in {i["value"] for i in inc["iocs"]}
    ap = inc["approvals"][0]
    assert ap["action"] == "isolate_host" and ap["risk"] == "high" and ap["status"] == "pending"

    # high-impact: SOC_ANALYST may not approve, INCIDENT_RESPONDER may
    assert client.post(f"/api/approvals/{ap['id']}/decide", json={"approve": True}, headers=analyst).status_code == 403
    r = client.post(f"/api/approvals/{ap['id']}/decide", json={"approve": True, "note": "isolate it"}, headers=responder)
    assert r.status_code == 200
    inc = client.get(f"/api/incidents/{number}", headers=analyst).json()
    iso = next(s for e in inc["executions"] for s in e["steps"] if s["action"] == "isolate_host")
    assert iso["status"] == "skipped" and "no connector configured" in iso["result"]["detail"]
    assert inc["status"] != "monitoring"  # no remediation actually happened, so no false 'handled' state

    blast = client.get(f"/api/incidents/{number}/blast-radius", headers=analyst).json()
    assert blast["status"] == "unknown_host"  # no asset inventory registered in this test


def test_false_positive_closure_flow(client, login):
    analyst = login("soc4", "SOC_ANALYST")
    number = feed(client, phishing())[0]["incident_number"]
    for a in ("false_positive", "close"):
        assert client.post(f"/api/incidents/{number}/action", json={"action": a, "notes": "test mail"}, headers=analyst).status_code == 200
    inc = client.get(f"/api/incidents/{number}", headers=analyst).json()
    assert inc["status"] == "closed" and [a["action"] for a in inc["analyst_actions"]] == ["false_positive", "close"]
    assert "closure" in timeline_kinds(client, analyst, number)
    # new matching activity after closure opens a NEW incident rather than mutating a closed one
    (again,) = feed(client, phishing())
    assert again["duplicate"] or again["incident_number"] != number
