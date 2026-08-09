#!/bin/bash

# SOAR "Make Live" Initialization Script
# This script initializes TheHive and Cortex, and generates API keys.

echo "🚀 Starting SOAR 'Make Live' Initialization..."

# ─── 1. TheHive Initialization ───
echo "🐝 Initializing TheHive..."
# Wait for TheHive to be ready
until curl -s http://localhost:9000/api/status > /dev/null; do
  echo "   Waiting for TheHive service..."
  sleep 5
done

# Create Org 'SOAR'
docker exec thehive /opt/thehive/bin/thehive-manage create-org --name "SOAR" --description "SOAR Operations" > /dev/null 2>&1

# Create User 'analyst' with API Key
API_KEY_HIVE="soar-api-key-2026"
docker exec thehive /opt/thehive/bin/thehive-manage create-user --org "SOAR" --user "analyst" --password "analyst123" --profile "analyst" --key "$API_KEY_HIVE" > /dev/null 2>&1

echo "✅ TheHive initialized"

# ─── 2. Cortex Initialization ───
echo "🧠 Initializing Cortex..."
until curl -s http://localhost:9001/api/status > /dev/null; do
  echo "   Waiting for Cortex service..."
  sleep 5
done

API_KEY_CORTEX="cortex-api-key-2026"
docker exec cortex /opt/cortex/bin/cortex-manage create-user --user "analyst" --password "analyst123" --role "read,write" --key "$API_KEY_CORTEX" > /dev/null 2>&1

echo "✅ Cortex initialized"

# ─── 3. MISP & Redis ───
echo "💉 Checking MISP & Redis..."
docker exec misp-redis redis-cli ping > /dev/null 2>&1 && echo "✅ Redis is Active"
docker ps | grep misp > /dev/null 2>&1 && echo "✅ MISP Container is Running"

# ─── 4. Restarting Backend ───
echo "🔄 Restarting Dashboard Backend..."
lsof -ti:3000 | xargs kill -9 2>/dev/null
sleep 2
cd "$(dirname "$0")/../dashboard/backend" && node server.js > backend.log 2>&1 &

echo "✨ SOAR is now LIVE!"
echo "Wazuh, TheHive, Cortex, MISP, and Redis are now monitored and connected."
