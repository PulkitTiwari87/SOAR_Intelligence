#!/usr/bin/env python3
"""
Cortex Analyzer: IP Reputation Checker
=======================================
Checks an IP address against known threat databases.
In production, replace the mock logic with real API calls to:
  - AbuseIPDB (https://www.abuseipdb.com/api)
  - VirusTotal (https://www.virustotal.com/api/v3/)
  - AlienVault OTX (https://otx.alienvault.com/api)

Cortex Analyzer I/O:
  - Input: JSON via stdin with observable data
  - Output: JSON to stdout with taxonomies and artifacts
"""

import sys
import json
import ipaddress


# --- Mock Threat Intelligence Database ---
# In production, these would be API calls to external services.
KNOWN_MALICIOUS_IPS = {
    "45.33.32.156": {"threat": "Nmap Scanners", "score": 85, "source": "AbuseIPDB"},
    "185.220.101.1": {"threat": "Tor Exit Node", "score": 90, "source": "AlienVault"},
    "91.219.236.222": {"threat": "C2 Server - APT28", "score": 100, "source": "MISP"},
    "203.0.113.50": {"threat": "Brute Force Origin", "score": 75, "source": "Custom Intel"},
}

KNOWN_SAFE_RANGES = [
    "10.0.0.0/8",       # Private
    "172.16.0.0/12",     # Private
    "192.168.0.0/16",    # Private
    "127.0.0.0/8",       # Loopback
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP belongs to a private/internal range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def analyze_ip(ip: str) -> dict:
    """Analyze an IP and return a threat assessment."""
    # Check private ranges first
    if is_private_ip(ip):
        return {
            "ip": ip,
            "reputation": "safe",
            "score": 0,
            "category": "Internal/Private IP",
            "description": "This is a private network address. No external threat.",
            "source": "Local Analysis"
        }

    # Check against known malicious IPs
    if ip in KNOWN_MALICIOUS_IPS:
        intel = KNOWN_MALICIOUS_IPS[ip]
        return {
            "ip": ip,
            "reputation": "malicious",
            "score": intel["score"],
            "category": intel["threat"],
            "description": f"Known malicious IP: {intel['threat']}. Source: {intel['source']}.",
            "source": intel["source"]
        }

    # Default: unknown (not in our database)
    return {
        "ip": ip,
        "reputation": "unknown",
        "score": 30,
        "category": "No Intel Available",
        "description": "IP not found in any threat database. Requires manual review.",
        "source": "N/A"
    }


def main():
    """Cortex Analyzer entry point."""
    input_data = sys.stdin.read()
    if not input_data:
        print(json.dumps({"success": False, "errorMessage": "No input received."}))
        sys.exit(1)

    try:
        cortex_job = json.loads(input_data)
    except json.JSONDecodeError:
        print(json.dumps({"success": False, "errorMessage": "Invalid JSON input."}))
        sys.exit(1)

    data_type = cortex_job.get("dataType") or cortex_job.get("observable", {}).get("dataType")
    data_value = cortex_job.get("data") or cortex_job.get("observable", {}).get("data")

    if data_type != "ip":
        print(json.dumps({
            "success": False,
            "errorMessage": f"Unsupported dataType '{data_type}'. This analyzer only supports 'ip'."
        }))
        sys.exit(1)

    result = analyze_ip(data_value)

    # Map to Cortex taxonomy level
    level_map = {"safe": "safe", "malicious": "malicious", "unknown": "suspicious"}
    level = level_map.get(result["reputation"], "info")

    # Build Cortex response
    output = {
        "success": True,
        "summary": {
            "taxonomies": [
                {
                    "level": level,
                    "namespace": "IPReputation",
                    "predicate": "Score",
                    "value": f"{result['score']}/100"
                },
                {
                    "level": level,
                    "namespace": "IPReputation",
                    "predicate": "Category",
                    "value": result["category"]
                }
            ]
        },
        "artifacts": [result],
        "full": result
    }

    print(json.dumps(output))


if __name__ == "__main__":
    main()
