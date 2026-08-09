#!/bin/bash
# =============================================================
# Wazuh Agent Installer for Kali Linux (Debian-based)
# Usage: sudo ./agent_install.sh <WAZUH_MANAGER_IP> [AGENT_NAME]
# =============================================================

set -e

WAZUH_MANAGER_IP=$1
AGENT_NAME=${2:-$(hostname)}

if [ -z "$WAZUH_MANAGER_IP" ]; then
  echo "Usage: sudo ./agent_install.sh <WAZUH_MANAGER_IP> [AGENT_NAME]"
  exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo)."
  exit 1
fi

echo "============================================="
echo " Wazuh Agent Installer"
echo " Manager IP : $WAZUH_MANAGER_IP"
echo " Agent Name : $AGENT_NAME"
echo "============================================="

# Step 1: Install dependencies
echo "[*] Installing prerequisites..."
apt-get update -y
apt-get install -y curl apt-transport-https gnupg

# Step 2: Add Wazuh GPG key and repository
echo "[*] Adding Wazuh repository key..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "[*] Adding Wazuh 4.x repository..."
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

echo "[*] Updating package index..."
apt-get update -y

# Step 3: Install the Wazuh agent with Manager IP pre-configured
echo "[*] Installing Wazuh Agent..."
WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install wazuh-agent -y

# Step 4: Verify the manager address was written correctly
if grep -q "$WAZUH_MANAGER_IP" /var/ossec/etc/ossec.conf 2>/dev/null; then
  echo "[+] Manager IP correctly set in ossec.conf."
else
  echo "[*] Patching ossec.conf with Manager IP..."
  sed -i "s#<address>.*</address>#<address>$WAZUH_MANAGER_IP</address>#g" /var/ossec/etc/ossec.conf
fi

# Step 5: Enable and start the agent service
echo "[*] Enabling and starting Wazuh agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Step 6: Verify agent is running
if systemctl is-active --quiet wazuh-agent; then
  echo "============================================="
  echo "[+] SUCCESS! Wazuh agent is running."
  echo "[+] Manager: $WAZUH_MANAGER_IP"
  echo "[+] Agent Name: $AGENT_NAME"
  echo "[+] Check the Wazuh Dashboard for this agent."
  echo "============================================="
else
  echo "[!] WARNING: Agent service failed to start."
  echo "[!] Check logs: journalctl -u wazuh-agent"
  exit 1
fi
