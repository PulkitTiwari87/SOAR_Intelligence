#!/bin/bash
# Fix ossec.conf for Wazuh Agent 4.9.0 compatibility
# Replace the entire syscollector block with a 4.9.0 compatible one

CONFIG="/var/ossec/etc/ossec.conf"

# Use python3 to cleanly replace the syscollector block
python3 << 'PYEOF'
import re

with open("/var/ossec/etc/ossec.conf", "r") as f:
    content = f.read()

# Replace the entire syscollector wodle block
new_syscollector = """  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>"""

content = re.sub(
    r'<wodle name="syscollector">.*?</wodle>',
    new_syscollector,
    content,
    flags=re.DOTALL
)

with open("/var/ossec/etc/ossec.conf", "w") as f:
    f.write(content)

print("Config patched successfully")
PYEOF

# Start the agent
/var/ossec/bin/wazuh-control stop 2>/dev/null
sleep 1
/var/ossec/bin/wazuh-control start
sleep 5
/var/ossec/bin/wazuh-control status
echo "--- Last 10 log lines ---"
tail -10 /var/ossec/logs/ossec.log
