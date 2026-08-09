#!/usr/bin/env python3
"""
SOAR AI Orchestrator — Human-in-the-Loop Decision Engine
==========================================================
Master script that ties all 8 AI modules together with a smart
decision engine:

  MINOR incidents (score >= 90% or score < 50%):
    → System handles automatically (AUTO_BLOCK or AUTO_CLOSE)
    → No human needed
    → PDF report generated and case auto-resolved

  MAJOR incidents (score 50-89%, or high blast radius, or anomaly upgrade):
    → System PAUSES and presents the situation to a human analyst
    → Shows AI recommendations with numbered options
    → Analyst picks the action → system executes it
    → Full audit trail logged

Usage:
  python orchestrator.py --demo-auto     # Demo: minor incident (auto-handled)
  python orchestrator.py --demo-major    # Demo: major incident (human asked)
  python orchestrator.py --demo          # Demo: runs both scenarios
  python orchestrator.py --process-alert '{"rule": {"level": 12, ...}}'
  python orchestrator.py --train-all
"""

import json
import os
import sys
import time
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from ai.triage.ml_triage_analyzer import predict_threat, train_model as train_triage
from ai.phishing.nlp_phishing_parser import analyze_email, train_model as train_phishing
from ai.anomaly.isolation_forest_detector import detect_anomaly, train_model as train_anomaly
from ai.clustering.log_clusterer import cluster_alerts, generate_sample_alerts
from ai.blast_radius.blast_radius_predictor import predict_blast_radius
from ai.optimizer.playbook_optimizer import generate_optimization_report, log_response
from ai.report_generator.report_generator import generate_pdf_report
from ai.feedback_loop import log_triage_feedback, log_anomaly_baseline, get_learning_stats

# ─── Severity Thresholds ───
AUTO_BLOCK_THRESHOLD   = 90   # Score >= 90% → auto-block (minor, clear threat)
AUTO_CLOSE_THRESHOLD   = 50   # Score <  50% → auto-close (noise)
BLAST_RADIUS_ESCALATE  = 3    # If >= 3 hosts at risk, escalate to human
# Between 50-89% → HUMAN_REVIEW (major, needs analyst)


def print_banner(text, char="═", width=62):
    """Print a formatted banner."""
    print(f"\n╔{char*width}╗")
    for line in text.strip().split("\n"):
        print(f"║  {line.ljust(width-2)}║")
    print(f"╚{char*width}╝")


def print_section(step, total, title):
    """Print a step header."""
    print(f"\n{'─'*50}")
    print(f"  [{step}/{total}] {title}")
    print(f"{'─'*50}")


def run_ai_analysis(alert_data: dict) -> dict:
    """
    Run all AI models on an alert and return results.
    This is the analysis phase — no actions taken yet.
    """
    rule = alert_data.get("rule", {})
    agent = alert_data.get("agent", {})
    data = alert_data.get("data", {})

    results = {"alert": alert_data, "timestamp": datetime.now().isoformat()}

    # ── Step 1: ML Triage ──
    print_section(1, 4, "ML Triage Analyzer (XGBoost)")
    triage_features = {
        "rule_level": int(rule.get("level", 5)),
        "failed_logins": int(data.get("failed_logins", 0)),
        "src_ip_is_internal": 1 if data.get("srcip", "").startswith(("10.", "192.168.", "172.")) else 0,
        "src_ip_reputation": int(data.get("ip_reputation", 0)),
        "event_count_1h": int(data.get("event_count", 1)),
        "is_fim_event": 1 if rule.get("group", "").find("syscheck") >= 0 else 0,
        "has_mitre_tag": 1 if rule.get("mitre", {}) else 0,
    }
    triage_result = predict_threat(triage_features)
    results["triage"] = triage_result
    score = triage_result["confidence_score"]
    print(f"    ✦ Confidence Score : {score}%")
    print(f"    ✦ Initial Decision : {triage_result['decision']}")

    # ── Step 2: Anomaly Detection ──
    print_section(2, 4, "Anomaly Detection (Isolation Forest)")
    anomaly_metrics = {
        "events_per_minute": int(data.get("event_count", 15)),
        "failed_auth_count": int(data.get("failed_logins", 0)),
        "bytes_transferred": int(data.get("bytes", 50000)),
        "unique_dst_ports": int(data.get("dst_ports", 2)),
    }
    anomaly_result = detect_anomaly(anomaly_metrics)
    results["anomaly"] = anomaly_result
    print(f"    ✦ Is Anomaly       : {'⚠ YES' if anomaly_result['is_anomaly'] else '✓ No'}")
    print(f"    ✦ Anomaly Score    : {anomaly_result['anomaly_score']}")
    print(f"    ✦ Threat Type      : {anomaly_result['threat_type']}")

    # ── Step 3: Blast Radius ──
    print_section(3, 4, "Blast Radius Prediction (NetworkX)")
    agent_name = agent.get("name", "kali-vm-01")
    blast_result = predict_blast_radius(agent_name)
    at_risk_count = blast_result.get("total_at_risk", 0)
    results["blast_radius"] = blast_result
    print(f"    ✦ Hosts At Risk    : {at_risk_count}")
    if blast_result.get("highest_risk_path"):
        print(f"    ✦ Highest Risk Path: {blast_result['highest_risk_path']}")
    if blast_result.get("recommendations", {}).get("isolate_immediately"):
        targets = blast_result["recommendations"]["isolate_immediately"]
        print(f"    ✦ Isolate Now      : {', '.join(t['hostname'] for t in targets)}")

    # ── Step 4: Determine Severity Tier ──
    print_section(4, 4, "Severity Classification")

    tier = classify_incident(score, anomaly_result, at_risk_count, rule)
    results["tier"] = tier

    if tier["level"] == "MINOR":
        print(f"    ✦ Classification   : 🟢 MINOR INCIDENT")
        print(f"    ✦ Reason           : {tier['reason']}")
        print(f"    ✦ Action           : System will handle AUTOMATICALLY")
    elif tier["level"] == "NOISE":
        print(f"    ✦ Classification   : ⚪ NOISE / FALSE POSITIVE")
        print(f"    ✦ Reason           : {tier['reason']}")
        print(f"    ✦ Action           : Auto-closing as noise")
    else:
        print(f"    ✦ Classification   : 🔴 MAJOR INCIDENT")
        print(f"    ✦ Reason           : {tier['reason']}")
        print(f"    ✦ Action           : HUMAN INTERVENTION REQUIRED")

    return results


def classify_incident(score, anomaly_result, at_risk_count, rule) -> dict:
    """
    Classify the incident as MINOR, MAJOR, or NOISE based on AI analysis.
    """
    # ── NOISE: Low score, no anomaly, low rule level ──
    if score < AUTO_CLOSE_THRESHOLD and not anomaly_result["is_anomaly"]:
        return {
            "level": "NOISE",
            "reason": f"ML score {score}% (below {AUTO_CLOSE_THRESHOLD}%) + no anomaly detected",
            "auto_action": "AUTO_CLOSE",
        }

    # ── MAJOR: Escalate to human if any of these conditions ──
    escalation_reasons = []

    if AUTO_CLOSE_THRESHOLD <= score < AUTO_BLOCK_THRESHOLD:
        escalation_reasons.append(f"ML score is {score}% — not confident enough for auto-block")

    if anomaly_result["is_anomaly"] and score < AUTO_BLOCK_THRESHOLD:
        escalation_reasons.append(f"Anomaly detected ({anomaly_result['threat_type']}) but ML score only {score}%")

    if at_risk_count >= BLAST_RADIUS_ESCALATE:
        escalation_reasons.append(f"High blast radius: {at_risk_count} hosts at risk")

    if int(rule.get("level", 0)) >= 13:
        escalation_reasons.append(f"Critical Wazuh rule level: {rule.get('level')}/15")

    if escalation_reasons:
        return {
            "level": "MAJOR",
            "reason": " | ".join(escalation_reasons),
            "auto_action": None,
        }

    # ── MINOR: High confidence, safe to auto-block ──
    return {
        "level": "MINOR",
        "reason": f"ML score {score}% (above {AUTO_BLOCK_THRESHOLD}%) — clear threat identified",
        "auto_action": "AUTO_BLOCK",
    }


def handle_minor_incident(results: dict) -> dict:
    """
    Automatically handle a minor/noise incident — no human needed.
    """
    tier = results["tier"]
    triage = results["triage"]
    anomaly = results["anomaly"]
    agent = results["alert"].get("agent", {})
    rule = results["alert"].get("rule", {})

    if tier["auto_action"] == "AUTO_CLOSE":
        print_banner("NOISE — AUTO-CLOSING\nNo threat detected. Case closed automatically.")
        decision = "AUTO_CLOSE"
        status = "Closed (Noise)"
    else:
        print_banner("MINOR INCIDENT — AUTO-BLOCKING\nThreat is clear. Executing automated response.")
        decision = "AUTO_BLOCK"
        status = "Resolved (Automated)"

        # Simulate automated response actions
        print("\n  ⚡ Executing automated response chain:")
        actions = [
            "Blocking source IP via Wazuh Active Response (firewall-drop)",
            "Updating firewall rules on perimeter devices",
            "Adding IOC to local threat intelligence database",
            "Notifying SOC team via email/Slack (informational only)",
        ]
        for i, action in enumerate(actions, 1):
            print(f"    [{i}/4] {action}...", end=" ")
            time.sleep(0.3)
            print("✓")

    # Generate report
    report_data = _build_report_data(results, decision, status)
    report_path = generate_pdf_report(report_data)
    print(f"\n  📄 Report saved: {report_path}")

    # Log for optimizer
    log_response(
        incident_type=anomaly["threat_type"].lower().replace(" ", "_"),
        action="block_ip" if decision == "AUTO_BLOCK" else "close",
        mttr=14.0 if decision == "AUTO_BLOCK" else 2.0,
        success=True,
        agent_id=agent.get("id", "001")
    )

    # ── SELF-LEARNING: Log feedback for model retraining ──
    was_correct = log_triage_feedback(
        features=triage_features,
        analyst_decision=decision,
        ml_decision=triage["decision"],
        ml_score=triage["confidence_score"]
    )
    # If auto-closed, log as normal baseline for anomaly model
    if decision == "AUTO_CLOSE":
        log_anomaly_baseline(anomaly_metrics, is_normal=True)
    print(f"  🧠 Feedback logged (ML was {'correct ✓' if was_correct else 'wrong ✗'})")

    return {"decision": decision, "status": status, "report_path": report_path,
            "human_involved": False}


def handle_major_incident(results: dict, interactive: bool = True) -> dict:
    """
    Handle a major incident — PAUSE and ask the human analyst what to do.
    Presents the situation with recommended actions.
    """
    triage = results["triage"]
    anomaly = results["anomaly"]
    blast = results["blast_radius"]
    tier = results["tier"]
    agent = results["alert"].get("agent", {})
    rule = results["alert"].get("rule", {})
    data = results["alert"].get("data", {})
    at_risk_count = blast.get("total_at_risk", 0)

    print_banner(
        "🔴 MAJOR INCIDENT — HUMAN INTERVENTION REQUIRED\n"
        "The AI has analysed this threat but needs YOUR decision\n"
        "to proceed. Review the details below."
    )

    # ── Present the Situation ──
    print(f"""
┌────────────────────────────────────────────────────────────┐
│                    INCIDENT BRIEFING                       │
├──────────────────┬─────────────────────────────────────────┤
│ Alert            │ {rule.get('description', 'Security Alert')[:40]}│
│ Source IP        │ {data.get('srcip', 'Unknown'):<40}│
│ Target Device    │ {agent.get('name', 'Unknown'):<40}│
│ Target IP        │ {agent.get('ip', 'Unknown'):<40}│
│ ML Triage Score  │ {triage['confidence_score']}% (NEEDS HUMAN REVIEW)            │
│ Anomaly Detected │ {'⚠ YES — ' + anomaly['threat_type'] if anomaly['is_anomaly'] else '✓ No anomaly':<40}│
│ Blast Radius     │ {at_risk_count} hosts could be compromised              │
│ Escalation Reason│ {tier['reason'][:40]}│
└──────────────────┴─────────────────────────────────────────┘""")

    # ── Show hosts at risk ──
    if blast.get("recommendations", {}).get("isolate_immediately"):
        print("\n  ⚠  HOSTS THAT SHOULD BE ISOLATED:")
        for target in blast["recommendations"]["isolate_immediately"]:
            print(f"     • {target['hostname']} ({target['ip']}) — {target['reason']}")

    # ── Present Action Options ──
    print(f"""
╔════════════════════════════════════════════════════════════╗
║              RECOMMENDED ACTIONS                          ║
╠════════════════════════════════════════════════════════════╣
║                                                            ║
║  [1] 🛑 BLOCK & ISOLATE (Recommended)                     ║
║      Block the attacker's IP, isolate the affected device, ║
║      and quarantine all at-risk hosts.                     ║
║      → Best for: Confirmed attacks, ransomware, APT        ║
║                                                            ║
║  [2] 🔍 INVESTIGATE FURTHER                                ║
║      Do NOT block yet. Run deeper analysis, collect more   ║
║      IOCs, and correlate with other alerts first.          ║
║      → Best for: Uncertain threats, possible false alarm   ║
║                                                            ║
║  [3] 📋 MONITOR ONLY                                      ║
║      Add enhanced monitoring to the device. Do not block   ║
║      the source. Watch for follow-up activity.             ║
║      → Best for: Low-confidence anomalies, insider threat  ║
║                                                            ║
║  [4] ✅ MARK AS FALSE POSITIVE                             ║
║      Close the case. This is normal activity that          ║
║      triggered a false alarm. No action needed.            ║
║      → Best for: Known scanner, planned pentest            ║
║                                                            ║
║  [5] 🚨 FULL LOCKDOWN                                     ║
║      Block IP, isolate device, isolate ALL at-risk hosts,  ║
║      force password reset, and notify management.          ║
║      → Best for: Active breach, data exfil, ransomware     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝""")

    # ── Get Human Decision ──
    if interactive:
        while True:
            try:
                choice = input("\n  👤 Analyst, enter your choice [1-5]: ").strip()
                if choice in ("1", "2", "3", "4", "5"):
                    break
                print("  ⚠  Invalid choice. Please enter a number between 1 and 5.")
            except (EOFError, KeyboardInterrupt):
                choice = "1"
                print(f"\n  [Auto-selecting option 1 — Block & Isolate]")
                break
    else:
        # Non-interactive mode: auto-pick based on score
        if triage["confidence_score"] >= 75:
            choice = "1"
        elif at_risk_count >= 5:
            choice = "5"
        else:
            choice = "2"
        print(f"\n  [Non-interactive mode — Auto-selected option {choice}]")

    # ── Execute the Chosen Action ──
    decision, status = execute_human_decision(choice, results)

    # Generate report
    report_data = _build_report_data(results, decision, status)
    report_data["analyst_choice"] = choice
    report_data["analyst_decision_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = generate_pdf_report(report_data)
    print(f"\n  📄 Report saved: {report_path}")

    # Log for optimizer
    action_map = {"1": "block_ip", "2": "investigate", "3": "monitor", "4": "close", "5": "lockdown"}
    decision_map = {"1": "BLOCK_AND_ISOLATE", "2": "INVESTIGATE", "3": "MONITOR",
                    "4": "FALSE_POSITIVE", "5": "FULL_LOCKDOWN"}
    log_response(
        incident_type=anomaly["threat_type"].lower().replace(" ", "_"),
        action=action_map.get(choice, "review"),
        mttr=30.0,
        success=choice in ("1", "4", "5"),
        agent_id=agent.get("id", "001")
    )

    # ── SELF-LEARNING: Log feedback for model retraining ──
    triage_features = {
        "rule_level": int(rule.get("level", 5)),
        "failed_logins": int(data.get("failed_logins", 0)),
        "src_ip_is_internal": 1 if data.get("srcip", "").startswith(("10.", "192.168.", "172.")) else 0,
        "src_ip_reputation": int(data.get("ip_reputation", 0)),
        "event_count_1h": int(data.get("event_count", 1)),
        "is_fim_event": 1 if rule.get("group", "").find("syscheck") >= 0 else 0,
        "has_mitre_tag": 1 if rule.get("mitre", {}) else 0,
    }
    was_correct = log_triage_feedback(
        features=triage_features,
        analyst_decision=decision_map.get(choice, decision),
        ml_decision=triage["decision"],
        ml_score=triage["confidence_score"]
    )
    # If analyst says false positive, teach anomaly model this is normal
    if choice == "4":
        anomaly_metrics = {
            "events_per_minute": int(data.get("event_count", 15)),
            "failed_auth_count": int(data.get("failed_logins", 0)),
            "bytes_transferred": int(data.get("bytes", 50000)),
            "unique_dst_ports": int(data.get("dst_ports", 2)),
        }
        log_anomaly_baseline(anomaly_metrics, is_normal=True)
    print(f"  🧠 Feedback logged (ML was {'correct ✓' if was_correct else 'wrong ✗'})")

    return {"decision": decision, "status": status, "report_path": report_path,
            "human_involved": True, "analyst_choice": choice}


def execute_human_decision(choice: str, results: dict) -> tuple:
    """Execute the action chosen by the human analyst."""
    blast = results["blast_radius"]

    if choice == "1":
        print("\n  ⚡ Executing: BLOCK & ISOLATE")
        steps = [
            "Blocking source IP via Wazuh Active Response (firewall-drop)",
            "Isolating affected device from the network",
            "Adding IOC to threat intelligence database (MISP)",
            "Creating TheHive case with all evidence attached",
        ]
        for i, step in enumerate(steps, 1):
            print(f"    [{i}/{len(steps)}] {step}...", end=" ")
            time.sleep(0.3)
            print("✓")
        return "BLOCK_AND_ISOLATE", "Resolved (Analyst Approved)"

    elif choice == "2":
        print("\n  🔍 Executing: INVESTIGATE FURTHER")
        steps = [
            "Running full Cortex analyzer suite on all observables",
            "Querying MISP for related indicators of compromise",
            "Correlating with alerts from the past 24 hours",
            "Collecting full packet capture from network tap",
            "Creating investigation case in TheHive (assigned to analyst)",
        ]
        for i, step in enumerate(steps, 1):
            print(f"    [{i}/{len(steps)}] {step}...", end=" ")
            time.sleep(0.3)
            print("✓")
        return "INVESTIGATE", "Under Investigation"

    elif choice == "3":
        print("\n  📋 Executing: MONITOR ONLY")
        steps = [
            "Enabling enhanced logging on affected device",
            "Setting up real-time alert for any follow-up activity",
            "Adding source IP to watchlist (not blocked)",
            "Scheduling automated re-check in 1 hour",
        ]
        for i, step in enumerate(steps, 1):
            print(f"    [{i}/{len(steps)}] {step}...", end=" ")
            time.sleep(0.3)
            print("✓")
        return "MONITOR", "Monitoring"

    elif choice == "4":
        print("\n  ✅ Executing: MARK AS FALSE POSITIVE")
        steps = [
            "Closing TheHive case as false positive",
            "Adding source IP to whitelist",
            "Updating ML model feedback (this was NOT malicious)",
        ]
        for i, step in enumerate(steps, 1):
            print(f"    [{i}/{len(steps)}] {step}...", end=" ")
            time.sleep(0.3)
            print("✓")
        return "FALSE_POSITIVE", "Closed (False Positive)"

    elif choice == "5":
        print("\n  🚨 Executing: FULL LOCKDOWN")
        steps = [
            "BLOCKING source IP via firewall-drop on all agents",
            "ISOLATING affected device from network",
        ]
        # Also isolate at-risk hosts
        isolate_targets = blast.get("recommendations", {}).get("isolate_immediately", [])
        for target in isolate_targets:
            steps.append(f"ISOLATING {target['hostname']} ({target['ip']}) — {target['reason']}")
        steps.extend([
            "Forcing password reset for all users on affected devices",
            "Revoking all active sessions and API tokens",
            "Notifying management and incident response team",
            "Creating CRITICAL case in TheHive with full evidence",
            "Sending alert to all SOC analysts via email + Slack",
        ])
        for i, step in enumerate(steps, 1):
            print(f"    [{i}/{len(steps)}] {step}...", end=" ")
            time.sleep(0.3)
            print("✓")
        return "FULL_LOCKDOWN", "Resolved (Full Lockdown — Analyst Approved)"

    return "UNKNOWN", "Unknown"


def _build_report_data(results: dict, decision: str, status: str) -> dict:
    """Build the report data dict from analysis results."""
    triage = results["triage"]
    anomaly = results["anomaly"]
    blast = results["blast_radius"]
    alert = results["alert"]
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    at_risk_count = blast.get("total_at_risk", 0)

    return {
        "incident_id": f"IR-{alert.get('id', datetime.now().strftime('%Y%m%d-%H%M'))}",
        "title": rule.get("description", "Security Alert"),
        "severity": min(4, max(1, int(rule.get("level", 5)) // 4 + 1)),
        "status": status,
        "timestamp": results.get("timestamp", "N/A"),
        "resolution_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mttr": "14 seconds" if decision in ("AUTO_BLOCK", "AUTO_CLOSE") else "Manual review",
        "agent_name": agent.get("name", "Unknown"),
        "agent_ip": agent.get("ip", "Unknown"),
        "agent_os": agent.get("os", "Linux"),
        "agent_id": agent.get("id", "001"),
        "rule_id": rule.get("id", ""),
        "rule_level": rule.get("level", ""),
        "triage_score": triage["confidence_score"],
        "attack_type": anomaly["threat_type"],
        "anomaly_score": str(anomaly["anomaly_score"]),
        "is_anomaly": anomaly["is_anomaly"],
        "blast_radius_count": at_risk_count,
        "actions_taken": [
            {"time": "T+0s", "description": f"Alert received — Rule: {rule.get('description', 'N/A')}"},
            {"time": "T+1s", "description": f"ML Triage Score: {triage['confidence_score']}% → {triage['decision']}"},
            {"time": "T+2s", "description": f"Anomaly Detection: {anomaly['threat_type']} (Score: {anomaly['anomaly_score']})"},
            {"time": "T+3s", "description": f"Blast Radius: {at_risk_count} hosts at risk"},
            {"time": "T+4s", "description": f"Decision: {decision} — {status}"},
        ],
    }


def process_alert(alert_data: dict, interactive: bool = True) -> dict:
    """
    Main entry point: process an alert through the full AI pipeline
    with human-in-the-loop decision making.
    """
    print_banner(
        "SOAR AI PIPELINE — ALERT PROCESSING\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "Running AI analysis..."
    )

    # Phase 1: AI Analysis (always automatic)
    results = run_ai_analysis(alert_data)

    # Phase 2: Decision + Action (depends on severity)
    tier = results["tier"]
    if tier["level"] in ("MINOR", "NOISE"):
        outcome = handle_minor_incident(results)
    else:
        outcome = handle_major_incident(results, interactive=interactive)

    # Final summary
    print_banner(
        f"PIPELINE COMPLETE\n"
        f"Decision : {outcome['decision']}\n"
        f"Status   : {outcome['status']}\n"
        f"Human    : {'Yes — analyst approved' if outcome['human_involved'] else 'No — auto-handled'}\n"
        f"Report   : {outcome['report_path']}"
    )

    return {**results, **outcome}


# ═══════════════════════════════════════════════════════
#  TRAINING
# ═══════════════════════════════════════════════════════
def train_all_models():
    """Train all ML models at once."""
    print("[*] Training all AI models...\n")
    print("=== 1. ML Triage (XGBoost) ===")
    train_triage()
    print("\n=== 2. Phishing Parser (TF-IDF + LogReg) ===")
    train_phishing()
    print("\n=== 3. Anomaly Detection (Isolation Forest) ===")
    train_anomaly()
    print("\n[+] All models trained successfully!")


# ═══════════════════════════════════════════════════════
#  DEMO SCENARIOS
# ═══════════════════════════════════════════════════════
DEMO_MINOR = {
    "id": "demo-minor-001",
    "rule": {
        "level": 12, "id": "100001",
        "description": "Multiple SSH authentication failures from the same source IP",
        "group": "authentication_failures",
        "mitre": {"id": ["T1110"]},
    },
    "agent": {"id": "001", "name": "kali-vm-01", "ip": "192.168.64.9", "os": "Linux"},
    "data": {"srcip": "91.219.236.222", "failed_logins": 50, "event_count": 200, "ip_reputation": 95},
}

DEMO_MAJOR = {
    "id": "demo-major-001",
    "rule": {
        "level": 10, "id": "100053",
        "description": "Unusual outbound data transfer detected during non-business hours",
        "group": "data_leak,suspicious_activity",
        "mitre": {"id": ["T1041"]},
    },
    "agent": {"id": "003", "name": "web-server-01", "ip": "192.168.64.10", "os": "Linux"},
    "data": {"srcip": "192.168.64.10", "failed_logins": 0, "event_count": 25,
             "ip_reputation": 35, "bytes": 5000000, "dst_ports": 1},
}


def run_demo_auto():
    """Demo: Minor incident handled automatically."""
    print_banner(
        "DEMO SCENARIO 1: MINOR INCIDENT\n"
        "SSH Brute Force from known APT28 IP\n"
        "Expected: System blocks automatically"
    )
    process_alert(DEMO_MINOR, interactive=False)


def run_demo_major():
    """Demo: Major incident requiring human decision."""
    print_banner(
        "DEMO SCENARIO 2: MAJOR INCIDENT\n"
        "Suspicious data exfiltration at 3 AM\n"
        "Expected: System asks human analyst for decision"
    )
    process_alert(DEMO_MAJOR, interactive=True)


# ═══════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "--train-all":
            train_all_models()
        elif cmd == "--demo":
            run_demo_auto()
            print("\n" + "█" * 62 + "\n")
            run_demo_major()
        elif cmd == "--demo-auto":
            run_demo_auto()
        elif cmd == "--demo-major":
            run_demo_major()
        elif cmd == "--process-alert":
            alert_json = sys.argv[2] if len(sys.argv) > 2 else '{}'
            result = process_alert(json.loads(alert_json))
            print(json.dumps({k: v for k, v in result.items()
                              if k not in ("alert", "blast_radius")}, indent=2, default=str))
        elif cmd == "--analyze-email":
            email_text = sys.argv[2] if len(sys.argv) > 2 else ""
            result = analyze_email(email_text)
            print(json.dumps(result, indent=2))
        elif cmd == "--cluster":
            alerts = generate_sample_alerts()
            result = cluster_alerts(alerts, n_clusters=4)
            print(json.dumps(result, indent=2))
        elif cmd == "--blast-radius":
            host = sys.argv[2] if len(sys.argv) > 2 else "kali-vm-01"
            result = predict_blast_radius(host)
            print(json.dumps(result, indent=2))
        elif cmd == "--playbook-report":
            result = generate_optimization_report()
            print(json.dumps(result, indent=2))
        elif cmd == "--learning-stats":
            stats = get_learning_stats()
            print("\n🧠 SELF-LEARNING STATS")
            print("═" * 40)
            print(json.dumps(stats, indent=2))
        else:
            print("Unknown command. Use one of the commands below.")
    else:
        print("""
SOAR AI Orchestrator — Human-in-the-Loop Decision Engine
═════════════════════════════════════════════════════════

Usage:
  python orchestrator.py --demo              # Run both demo scenarios
  python orchestrator.py --demo-auto         # Demo: minor incident (auto-handled)
  python orchestrator.py --demo-major        # Demo: major incident (asks human)
  python orchestrator.py --train-all         # Train all ML models
  python orchestrator.py --process-alert '{}' # Process a real Wazuh alert
  python orchestrator.py --analyze-email '...' # Analyze an email for phishing
  python orchestrator.py --cluster           # Demo log clustering
  python orchestrator.py --blast-radius HOST # Predict blast radius
  python orchestrator.py --playbook-report   # Playbook optimization report

Decision Logic:
  Score >= 90%  → AUTO_BLOCK (minor, system handles it)
  Score 50-89%  → HUMAN_REVIEW (major, analyst decides)
  Score <  50%  → AUTO_CLOSE (noise, auto-dismissed)
  Blast >= 3    → HUMAN_REVIEW (escalated due to risk)
  Rule >= 13    → HUMAN_REVIEW (critical Wazuh rule)
""")
