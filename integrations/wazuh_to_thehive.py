#!/var/ossec/framework/python/bin/python3
"""
Wazuh-to-TheHive Integration Script
====================================
Forwards high-severity Wazuh alerts to TheHive 5.x as structured alerts.
Called by Wazuh Manager's integrator daemon (ossec-integratord).

Configuration:
  1. Set THEHIVE_URL and THEHIVE_API_KEY below.
  2. Copy this script to /var/ossec/integrations/ inside the Wazuh Manager container.
  3. Add an <integration> block in Wazuh's ossec.conf:
     <integration>
       <name>custom-thehive</name>
       <hook_url>http://thehive:9000</hook_url>
       <level>7</level>
       <alert_format>json</alert_format>
     </integration>
"""

import sys
import os
import json
import logging
import requests
import urllib3

# Suppress SSL warnings for internal services
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
THEHIVE_URL = os.environ.get('THEHIVE_URL', 'http://thehive:9000')
THEHIVE_API_KEY = os.environ.get('THEHIVE_API_KEY', 'mZMfJp3OWSvn3+pITEpaalxdWSwynI3D')
ALERT_LEVEL_THRESHOLD = 7

# Setup logging
LOG_FILE = '/var/ossec/logs/integrations.log'
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [thehive-integration]: %(message)s'
)


def map_severity(rule_level: int) -> int:
    """Map Wazuh rule level (0-15) to TheHive severity (1-4)."""
    if rule_level >= 13:
        return 4  # Critical
    elif rule_level >= 10:
        return 3  # High
    elif rule_level >= 7:
        return 2  # Medium
    return 1      # Low


def extract_observables(alert_data: dict) -> list:
    """Extract observables (IPs, hashes, filenames) from alert data."""
    observables = []
    data = alert_data.get('data', {})

    # Source IP
    src_ip = data.get('srcip') or alert_data.get('data', {}).get('src_ip')
    if src_ip:
        observables.append({
            "dataType": "ip",
            "data": src_ip,
            "message": "Source IP address from Wazuh alert",
            "tags": ["wazuh", "source"]
        })

    # Destination IP
    dst_ip = data.get('dstip') or data.get('dst_ip')
    if dst_ip:
        observables.append({
            "dataType": "ip",
            "data": dst_ip,
            "message": "Destination IP address from Wazuh alert",
            "tags": ["wazuh", "destination"]
        })

    # File hashes (from syscheck / FIM events)
    syscheck = alert_data.get('syscheck', {})
    md5 = syscheck.get('md5_after')
    sha256 = syscheck.get('sha256_after')
    if md5:
        observables.append({"dataType": "hash", "data": md5, "message": "MD5 from FIM", "tags": ["wazuh", "fim"]})
    if sha256:
        observables.append({"dataType": "hash", "data": sha256, "message": "SHA256 from FIM", "tags": ["wazuh", "fim"]})

    # Filename
    filename = syscheck.get('path')
    if filename:
        observables.append({"dataType": "filename", "data": filename, "message": "Modified file path", "tags": ["wazuh", "fim"]})

    return observables


def send_to_thehive(alert_data: dict) -> None:
    """Send a structured alert to TheHive 5.x API."""
    rule = alert_data.get('rule', {})
    rule_level = int(rule.get('level', 0))
    description = rule.get('description', 'No description')
    rule_id = rule.get('id', 'unknown')
    agent = alert_data.get('agent', {})
    agent_name = agent.get('name', 'Unknown')
    agent_ip = agent.get('ip', 'Unknown')
    timestamp = alert_data.get('timestamp', '')

    # Skip low-severity alerts
    if rule_level < ALERT_LEVEL_THRESHOLD:
        logging.info(f"Skipping alert (level {rule_level} < {ALERT_LEVEL_THRESHOLD})")
        return

    severity = map_severity(rule_level)
    observables = extract_observables(alert_data)

    # MITRE ATT&CK tags
    mitre_ids = [m.get('id', '') for m in rule.get('mitre', {}).get('id', []) if isinstance(m, dict)]
    if isinstance(rule.get('mitre', {}).get('id'), list):
        mitre_ids = rule['mitre']['id']

    tags = [
        "wazuh",
        f"agent:{agent_name}",
        f"rule:{rule_id}",
        f"level:{rule_level}",
    ] + [f"mitre:{m}" for m in mitre_ids]

    # TheHive 5.x Alert payload
    hive_alert = {
        "type": "wazuh",
        "source": "Wazuh-SOAR",
        "sourceRef": f"wazuh-{rule_id}-{timestamp}",
        "title": f"[Wazuh] {description}",
        "description": (
            f"**Agent:** {agent_name} ({agent_ip})\n"
            f"**Rule:** {rule_id} (Level {rule_level})\n"
            f"**Time:** {timestamp}\n\n"
            f"### Full Alert Data\n```json\n{json.dumps(alert_data, indent=2)}\n```"
        ),
        "severity": severity,
        "tlp": 2,              # TLP:AMBER
        "pap": 2,              # PAP:AMBER (TheHive 5 field)
        "tags": tags,
        "observables": observables
    }

    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",  # TheHive 5.x uses /api/v1/
            headers=headers,
            json=hive_alert,
            verify=False,
            timeout=30
        )

        if response.status_code in (200, 201):
            logging.info(f"Alert sent to TheHive: {description} (Level {rule_level})")
        else:
            logging.error(
                f"TheHive rejected alert. Status: {response.status_code}, "
                f"Body: {response.text[:500]}"
            )
    except requests.exceptions.ConnectionError:
        logging.error(f"Cannot connect to TheHive at {THEHIVE_URL}")
    except requests.exceptions.Timeout:
        logging.error("TheHive request timed out after 30s")


def main():
    """Entry point — read alert file from Wazuh and forward to TheHive."""
    if len(sys.argv) < 2:
        print("Usage: wazuh_to_thehive.py <alert_file>", file=sys.stderr)
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, 'r') as f:
            alert_data = json.load(f)
        send_to_thehive(alert_data)
    except FileNotFoundError:
        logging.error(f"Alert file not found: {alert_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in alert file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
