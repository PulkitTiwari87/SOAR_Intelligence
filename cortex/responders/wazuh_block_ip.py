#!/usr/bin/env python3
"""
Cortex Responder: Block IP via Wazuh Active Response
=====================================================
Receives an IP observable from Cortex/TheHive and triggers
the 'firewall-drop' active response command on the target
Wazuh agent via the Wazuh Manager API.

Requires: requests
"""

import sys
import json
import logging
import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration — read from environment or use defaults
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh.manager:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "MyS3cr37P450r.*-")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def get_auth_token() -> str:
    """Authenticate with Wazuh API and return a JWT token."""
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        response = requests.post(
            url,
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            token = response.json().get("data", {}).get("token", "")
            return token
        else:
            logging.error(f"Auth failed: {response.status_code} - {response.text[:200]}")
            return ""
    except Exception as e:
        logging.error(f"Auth error: {e}")
        return ""


def find_agent_by_ip(token: str, ip: str) -> str:
    """Find the Wazuh agent ID associated with a given IP."""
    url = f"{WAZUH_API_URL}/agents"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            agents = response.json().get("data", {}).get("affected_items", [])
            for agent in agents:
                if agent.get("ip") == ip or agent.get("registerIP") == ip:
                    return agent.get("id", "001")
    except Exception as e:
        logging.error(f"Agent lookup error: {e}")
    # Default to agent 001 if lookup fails
    return "001"


def run_active_response(token: str, agent_id: str, command: str, arguments: list) -> dict:
    """Trigger Wazuh active response on a specific agent."""
    url = f"{WAZUH_API_URL}/active-response"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "command": command,
        "custom": False,
        "arguments": arguments,
        "alert": {"data": {"srcip": arguments[0]}} if arguments else {}
    }
    params = {"agents_list": agent_id}

    response = requests.put(
        url, headers=headers, params=params,
        json=payload, verify=False, timeout=15
    )
    return response.json()


def main():
    """Read Cortex job input and execute the block action."""
    try:
        input_data = sys.stdin.read()
        if not input_data:
            logging.error("No input provided via stdin.")
            sys.exit(1)

        cortex_job = json.loads(input_data)
        data_type = cortex_job.get('observable', {}).get('dataType')
        data_value = cortex_job.get('observable', {}).get('data')

        if data_type != 'ip':
            result = {"success": False, "message": f"Unsupported dataType '{data_type}'. Only 'ip' is supported."}
            print(json.dumps(result))
            sys.exit(0)

        ip_to_block = data_value
        logging.info(f"Blocking IP: {ip_to_block}")

        # Step 1: Authenticate
        token = get_auth_token()
        if not token:
            print(json.dumps({"success": False, "message": "Failed to authenticate with Wazuh API"}))
            sys.exit(1)

        # Step 2: Find target agent (or default to 001)
        agent_id = find_agent_by_ip(token, ip_to_block)
        logging.info(f"Target agent: {agent_id}")

        # Step 3: Trigger firewall-drop
        result = run_active_response(token, agent_id, "firewall-drop", [ip_to_block])
        logging.info(f"Active Response result: {result}")

        print(json.dumps({
            "success": True,
            "message": f"Blocked {ip_to_block} on agent {agent_id}",
            "full_response": result
        }))
        sys.exit(0)

    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON input: {e}")
        print(json.dumps({"success": False, "message": f"JSON parse error: {e}"}))
        sys.exit(1)
    except Exception as e:
        logging.error(f"Responder failed: {e}")
        print(json.dumps({"success": False, "message": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
