#!/usr/bin/env python3
"""
Module 3.2: LLM Incident Commander
====================================
Uses Google Gemini API to automatically generate natural-language
incident summaries from raw TheHive case data.

Usage:
  - As a standalone script: python incident_summarizer.py --case '{"title": "..."}'
  - As a module: from incident_summarizer import summarize_incident
"""

import json
import os
import sys
from datetime import datetime

try:
    import google.generativeai as genai
except ImportError:
    os.system("pip install google-generativeai")
    import google.generativeai as genai

# --- Configuration ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY")
MODEL_NAME = "gemini-2.0-flash"


def configure_gemini():
    """Initialize the Gemini client."""
    genai.configure(api_key=GEMINI_API_KEY)
    return genai.GenerativeModel(MODEL_NAME)


SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst working inside a SOAR system.
Your job is to analyze raw security incident data and produce a concise, professional incident summary.

Your summary MUST include:
1. **Incident Overview** — What happened in 2-3 sentences.
2. **Affected Assets** — Device name, IP, OS, agent ID.
3. **Threat Assessment** — What type of attack, MITRE ATT&CK mapping if available.
4. **Actions Taken** — What automated responses were executed.
5. **Risk Assessment** — Current risk level after remediation.
6. **Recommendations** — 2-3 actionable steps to prevent recurrence.

Keep the language professional but clear. Use bullet points where appropriate.
Do NOT include speculative information — only analyze what is provided."""


def summarize_incident(case_data: dict) -> str:
    """
    Generate a natural-language incident summary using Gemini.

    Args:
        case_data: Dict containing TheHive case details
                   (title, description, observables, tags, severity, etc.)

    Returns:
        A formatted incident summary string.
    """
    model = configure_gemini()

    user_prompt = f"""Analyze this security incident and generate a professional summary:

```json
{json.dumps(case_data, indent=2)}
```

Generate the incident summary now."""

    try:
        response = model.generate_content(
            [{"role": "user", "parts": [SYSTEM_PROMPT + "\n\n" + user_prompt]}]
        )
        return response.text
    except Exception as e:
        return f"[LLM Error] Failed to generate summary: {str(e)}"


def summarize_from_thehive_api(thehive_url: str, api_key: str, case_id: str) -> str:
    """
    Fetch case data from TheHive API and generate a summary.
    """
    import requests
    headers = {"Authorization": f"Bearer {api_key}"}

    # Fetch case details
    case_resp = requests.get(f"{thehive_url}/api/v1/case/{case_id}", headers=headers, verify=False)
    if case_resp.status_code != 200:
        return f"[Error] Could not fetch case {case_id}: {case_resp.text}"

    case = case_resp.json()

    # Fetch observables
    obs_resp = requests.get(
        f"{thehive_url}/api/v1/case/{case_id}/observable",
        headers=headers, verify=False
    )
    observables = obs_resp.json() if obs_resp.status_code == 200 else []

    case_data = {
        "title": case.get("title"),
        "description": case.get("description"),
        "severity": case.get("severity"),
        "tags": case.get("tags", []),
        "status": case.get("status"),
        "created_at": case.get("_createdAt"),
        "observables": [
            {"type": o.get("dataType"), "value": o.get("data"), "tags": o.get("tags", [])}
            for o in observables
        ]
    }

    return summarize_incident(case_data)


# --- Demo / Testing ---
DEMO_CASE = {
    "title": "Wazuh Alert: Multiple SSH authentication failures",
    "description": "Agent: kali-vm-01 (192.168.64.9). 50 failed SSH logins detected from 91.219.236.222.",
    "severity": 3,
    "tags": ["wazuh", "agent:kali-vm-01", "rule:100001", "level:10", "mitre:T1110"],
    "status": "Resolved",
    "created_at": "2026-03-06T12:00:00Z",
    "observables": [
        {"type": "ip", "value": "91.219.236.222", "tags": ["source", "malicious"]},
        {"type": "ip", "value": "192.168.64.9", "tags": ["destination", "internal"]}
    ],
    "actions_taken": [
        "Cortex queried MISP — IP matched APT28 C2 infrastructure (score 100/100)",
        "ML Triage Score: 97% — AUTO_BLOCK triggered",
        "Wazuh Active Response: firewall-drop 91.219.236.222 on agent 001",
        "Threat neutralized in 14 seconds"
    ]
}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        print("[*] Generating demo incident summary...\n")
        summary = summarize_incident(DEMO_CASE)
        print(summary)
    elif len(sys.argv) > 1 and sys.argv[1] == "--case":
        case_json = sys.argv[2]
        case_data = json.loads(case_json)
        summary = summarize_incident(case_data)
        print(summary)
    else:
        print("Usage:")
        print("  python incident_summarizer.py --demo")
        print("  python incident_summarizer.py --case '{...}'")
