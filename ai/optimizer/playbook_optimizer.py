#!/usr/bin/env python3
"""
Module 3.7: Self-Healing Playbook Optimizer
=============================================
Tracks historical MTTR per responder action and uses statistical
analysis to identify the most effective response strategies.

Generates optimization reports recommending which responder
actions to prioritize for each incident type.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict

import numpy as np
import pandas as pd


HISTORY_PATH = os.path.join(os.path.dirname(__file__), "response_history.json")


def generate_sample_history() -> list:
    """Generate sample historical incident response data."""
    np.random.seed(42)
    records = []
    incident_types = ["brute_force", "malware", "ransomware", "phishing", "data_exfiltration"]
    actions = ["block_ip", "isolate_host", "kill_process", "revoke_token", "quarantine_file"]

    base_time = datetime(2026, 1, 1)

    for i in range(200):
        incident = np.random.choice(incident_types)
        action = np.random.choice(actions)

        # Simulate realistic MTTR based on action type
        if action == "block_ip":
            mttr = np.random.normal(12, 3) if incident in ["brute_force"] else np.random.normal(45, 15)
            success = np.random.choice([True, True, True, False]) if incident == "brute_force" else np.random.choice([True, False])
        elif action == "isolate_host":
            mttr = np.random.normal(8, 2)
            success = np.random.choice([True, True, True, True, False])  # 80% success
        elif action == "kill_process":
            mttr = np.random.normal(5, 1)
            success = True if incident in ["malware"] else np.random.choice([True, False, False])
        elif action == "revoke_token":
            mttr = np.random.normal(3, 1)
            success = True if incident == "phishing" else np.random.choice([True, False])
        elif action == "quarantine_file":
            mttr = np.random.normal(15, 5)
            success = True if incident in ["malware", "ransomware"] else np.random.choice([True, False])
        else:
            mttr = np.random.normal(30, 10)
            success = np.random.choice([True, False])

        records.append({
            "incident_id": f"IR-2026-{i+1:04d}",
            "timestamp": (base_time + timedelta(hours=i * 4)).isoformat(),
            "incident_type": str(incident),
            "action_taken": str(action),
            "mttr_seconds": float(max(1, round(mttr, 2))),
            "success": bool(success),
            "agent_id": f"00{int(np.random.randint(1, 5))}",
        })

    return records


def load_history() -> list:
    """Load response history from disk or generate sample data."""
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, 'r') as f:
            return json.load(f)
    else:
        history = generate_sample_history()
        save_history(history)
        return history


def save_history(history: list):
    """Save response history to disk."""
    with open(HISTORY_PATH, 'w') as f:
        json.dump(history, f, indent=2)


def log_response(incident_type: str, action: str, mttr: float, success: bool, agent_id: str = "001"):
    """Log a new response action for future learning."""
    history = load_history()
    history.append({
        "incident_id": f"IR-{datetime.now().strftime('%Y')}-{len(history)+1:04d}",
        "timestamp": datetime.now().isoformat(),
        "incident_type": incident_type,
        "action_taken": action,
        "mttr_seconds": round(mttr, 2),
        "success": success,
        "agent_id": agent_id,
    })
    save_history(history)


def generate_optimization_report() -> dict:
    """
    Analyze historical response data and generate an optimization report.
    Returns recommendations for the best action per incident type.
    """
    history = load_history()
    df = pd.DataFrame(history)

    if df.empty:
        return {"error": "No historical data available."}

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_incidents_analyzed": len(df),
        "date_range": {
            "from": df["timestamp"].min(),
            "to": df["timestamp"].max(),
        },
        "overall_metrics": {
            "avg_mttr_seconds": round(df["mttr_seconds"].mean(), 2),
            "success_rate": f"{round(df['success'].mean() * 100, 1)}%",
            "total_successful": int(df["success"].sum()),
            "total_failed": int((~df["success"]).sum()),
        },
        "per_incident_analysis": {},
        "recommendations": [],
    }

    # Analyze each incident type
    for incident_type in df["incident_type"].unique():
        incident_df = df[df["incident_type"] == incident_type]

        action_stats = []
        for action in incident_df["action_taken"].unique():
            action_df = incident_df[incident_df["action_taken"] == action]
            success_df = action_df[action_df["success"] == True]

            stats = {
                "action": action,
                "total_uses": len(action_df),
                "success_count": len(success_df),
                "success_rate": round(len(success_df) / len(action_df) * 100, 1) if len(action_df) > 0 else 0,
                "avg_mttr": round(action_df["mttr_seconds"].mean(), 2),
                "avg_mttr_successful": round(success_df["mttr_seconds"].mean(), 2) if len(success_df) > 0 else None,
            }
            # Effectiveness score = success_rate * (1 / avg_mttr) * 100
            if stats["avg_mttr"] > 0:
                stats["effectiveness_score"] = round(
                    stats["success_rate"] * (1 / stats["avg_mttr"]) * 10, 2
                )
            else:
                stats["effectiveness_score"] = 0
            action_stats.append(stats)

        # Sort by effectiveness
        action_stats.sort(key=lambda x: x["effectiveness_score"], reverse=True)

        report["per_incident_analysis"][incident_type] = {
            "total_incidents": len(incident_df),
            "action_breakdown": action_stats,
        }

        # Generate recommendation
        if len(action_stats) >= 2:
            best = action_stats[0]
            worst = action_stats[-1]
            report["recommendations"].append({
                "incident_type": incident_type,
                "best_action": best["action"],
                "best_effectiveness": best["effectiveness_score"],
                "best_success_rate": f"{best['success_rate']}%",
                "best_avg_mttr": f"{best['avg_mttr']}s",
                "worst_action": worst["action"],
                "worst_effectiveness": worst["effectiveness_score"],
                "suggestion": (
                    f"For '{incident_type}' incidents, '{best['action']}' is "
                    f"{round(best['effectiveness_score'] / max(worst['effectiveness_score'], 0.01), 1)}x "
                    f"more effective than '{worst['action']}'. "
                    f"Consider making '{best['action']}' the default responder."
                ),
            })

    return report


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--report":
        report = generate_optimization_report()
        print(json.dumps(report, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--log":
        log_response("brute_force", "block_ip", 11.5, True)
        print("[+] Response logged successfully.")
    else:
        print("Usage:")
        print("  python playbook_optimizer.py --report    # Generate optimization report")
        print("  python playbook_optimizer.py --log       # Log a sample response")
