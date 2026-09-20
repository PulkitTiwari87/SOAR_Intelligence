"""MITRE ATT&CK mapping.

Three sources, always recorded so the UI can tell them apart:
  wazuh_rule    technique ids carried by the Wazuh rule that fired (authored by rule writers)
  rule_engine   deterministic heuristics below, each with an evidence string and a confidence
  llm_inferred  suggested by the LLM commander; accepted only if the id is in CATALOG

The catalog is a curated subset of ATT&CK (enterprise), not the full matrix. Nothing is mapped
when no rule matches; an empty mapping is a valid answer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# id -> (name, [tactics], parent_id | None)
CATALOG: dict[str, tuple[str, list[str], str | None]] = {
    "T1595": ("Active Scanning", ["Reconnaissance"], None),
    "T1566": ("Phishing", ["Initial Access"], None),
    "T1566.001": ("Spearphishing Attachment", ["Initial Access"], "T1566"),
    "T1566.002": ("Spearphishing Link", ["Initial Access"], "T1566"),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"], None),
    "T1078": ("Valid Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation",
                                 "Initial Access"], None),
    "T1059": ("Command and Scripting Interpreter", ["Execution"], None),
    "T1059.004": ("Unix Shell", ["Execution"], "T1059"),
    "T1204": ("User Execution", ["Execution"], None),
    "T1204.002": ("Malicious File", ["Execution"], "T1204"),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"], None),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"], None),
    "T1136": ("Create Account", ["Persistence"], None),
    "T1505": ("Server Software Component", ["Persistence"], None),
    "T1505.003": ("Web Shell", ["Persistence"], "T1505"),
    "T1547": ("Boot or Logon Autostart Execution", ["Persistence", "Privilege Escalation"], None),
    "T1068": ("Exploitation for Privilege Escalation", ["Privilege Escalation"], None),
    "T1548": ("Abuse Elevation Control Mechanism", ["Privilege Escalation", "Defense Evasion"], None),
    "T1055": ("Process Injection", ["Defense Evasion", "Privilege Escalation"], None),
    "T1027": ("Obfuscated Files or Information", ["Defense Evasion"], None),
    "T1070": ("Indicator Removal", ["Defense Evasion"], None),
    "T1110": ("Brute Force", ["Credential Access"], None),
    "T1110.001": ("Password Guessing", ["Credential Access"], "T1110"),
    "T1110.003": ("Password Spraying", ["Credential Access"], "T1110"),
    "T1110.004": ("Credential Stuffing", ["Credential Access"], "T1110"),
    "T1003": ("OS Credential Dumping", ["Credential Access"], None),
    "T1046": ("Network Service Discovery", ["Discovery"], None),
    "T1021": ("Remote Services", ["Lateral Movement"], None),
    "T1021.004": ("SSH", ["Lateral Movement"], "T1021"),
    "T1071": ("Application Layer Protocol", ["Command and Control"], None),
    "T1071.004": ("DNS", ["Command and Control"], "T1071"),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"], None),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"], None),
    "T1048": ("Exfiltration Over Alternative Protocol", ["Exfiltration"], None),
    "T1567": ("Exfiltration Over Web Service", ["Exfiltration"], None),
    "T1486": ("Data Encrypted for Impact", ["Impact"], None),
    "T1496": ("Resource Hijacking", ["Impact"], None),
}


@dataclass
class Mapping:
    technique_id: str
    technique_name: str
    tactic: str
    subtechnique: str | None
    source: str
    confidence: float
    evidence: str


def lookup(technique_id: str) -> dict | None:
    entry = CATALOG.get(technique_id.strip().upper())
    if not entry:
        return None
    name, tactics, parent = entry
    return {"id": technique_id.upper(), "name": name, "tactics": tactics, "parent": parent}


def _mk(tid: str, source: str, conf: float, evidence: str) -> Mapping:
    name, tactics, parent = CATALOG[tid]
    if parent:  # sub-technique: report parent name as technique, own name as sub-technique
        return Mapping(tid, CATALOG[parent][0], tactics[0], name, source, conf, evidence)
    return Mapping(tid, name, tactics[0], None, source, conf, evidence)


def _meta(e: Any) -> dict:
    """ORM events keep it in `.meta`; NormalizedEvent in `.metadata`. (On the ORM class `.metadata`
    is SQLAlchemy's MetaData, so only accept real dicts.)"""
    for attr in ("meta", "metadata"):
        m = getattr(e, attr, None)
        if isinstance(m, dict):
            return m
    return {}


_REVSHELL = re.compile(r"(nc|ncat|netcat)\s+.*-e\s|/dev/tcp/|bash\s+-i|socat\s+.*exec:|"
                       r"python\S*\s+-c\s+.*socket", re.I)
_SENSITIVE_FILES = ("/etc/passwd", "/etc/shadow", "/etc/sudoers")


def from_wazuh(events: list[Any]) -> list[Mapping]:
    out: dict[str, Mapping] = {}
    for e in events:
        m = _meta(e).get("mitre") or {}
        ids, names, tactics = m.get("ids") or [], m.get("techniques") or [], m.get("tactics") or []
        for i, tid in enumerate(ids):
            tid = str(tid).upper()
            if tid in out:
                continue
            ev = f"Wazuh rule {getattr(e, 'rule_id', '')} carries {tid}"
            if tid in CATALOG:
                out[tid] = _mk(tid, "wazuh_rule", 0.9, ev)
            elif i < len(names):  # not in our catalog: trust what the rule states, nothing more
                tactic = tactics[i] if i < len(tactics) else (tactics[0] if tactics else "Unknown")
                out[tid] = Mapping(tid, str(names[i]), str(tactic), None, "wazuh_rule", 0.9, ev)
    return list(out.values())


def from_rules(events: list[Any]) -> list[Mapping]:
    out: dict[str, Mapping] = {}

    def put(tid: str, conf: float, evidence: str) -> None:
        if tid not in out or out[tid].confidence < conf:
            out[tid] = _mk(tid, "rule_engine", conf, evidence)

    types = [e.event_type for e in events]
    fails = [e for e in events if e.event_type == "authentication_failure"]
    n_fail = sum(int(_meta(e).get("failed_logins") or 1) for e in fails)
    if n_fail >= 5:
        users = {e.username for e in fails if e.username}
        ips = {e.source_ip for e in fails if e.source_ip}
        put("T1110", 0.75, f"{n_fail} failed logins from {len(ips) or 'unknown'} source(s)")
        if len(users) >= 3 and n_fail / max(len(users), 1) <= 5:
            put("T1110.003", 0.6, f"{len(users)} distinct accounts with few attempts each")
        elif len(users) == 1:
            put("T1110.001", 0.6, f"repeated guesses against one account ({next(iter(users))})")
    ok_after_fail = fails and any(
        e.event_type == "authentication_success" and e.source_ip in {f.source_ip for f in fails}
        for e in events)
    if ok_after_fail:
        put("T1078", 0.5, "successful login from an IP that previously failed authentication")
    for e in events:
        cmd = e.command or ""
        if e.event_type == "suspicious_process" and _REVSHELL.search(cmd):
            put("T1059", 0.7, f"reverse-shell style command: {cmd[:120]}")
            if re.search(r"/bin/(ba|z)?sh|bash\s+-i", cmd):
                put("T1059.004", 0.65, "command invokes a Unix shell")
        if e.event_type == "file_integrity":
            path = str(_meta(e).get("fim_path") or "")
            if path in _SENSITIVE_FILES:
                put("T1098", 0.4, f"heuristic: integrity change on {path}")
        if e.event_type == "phishing_email":
            put("T1566", 0.8, "email classified as phishing")
            if e.url or _meta(e).get("urls"):
                put("T1566.002", 0.7, "phishing email contains link(s)")
            if _meta(e).get("attachments"):
                put("T1566.001", 0.7, "phishing email has attachment(s)")
    if "network_scan" in types:
        put("T1046", 0.8, "network scan activity observed")
    if "web_attack" in types:
        put("T1190", 0.7, "web attack against a public-facing application")
    if "privilege_escalation" in types:
        put("T1548", 0.5, "privilege escalation activity")
    if "data_exfiltration" in types:
        put("T1041", 0.4, "large/unusual outbound transfer; exfiltration channel unknown")
    return list(out.values())


def map_events(events: list[Any]) -> list[Mapping]:
    """Wazuh-provided mappings win over heuristics for the same technique."""
    merged = {m.technique_id: m for m in from_rules(events)}
    merged.update({m.technique_id: m for m in from_wazuh(events)})
    return sorted(merged.values(), key=lambda m: -m.confidence)


def from_llm(items: list[dict]) -> tuple[list[Mapping], list[str]]:
    """Validate LLM-suggested techniques; return (accepted, rejected ids)."""
    accepted, rejected = [], []
    for it in items:
        tid = str(it.get("id", "")).strip().upper()
        if tid in CATALOG:
            conf = max(0.0, min(0.7, float(it.get("confidence", 0.4))))  # LLM is capped below rules
            accepted.append(_mk(tid, "llm_inferred", conf, str(it.get("evidence", ""))[:500]))
        else:
            rejected.append(tid)
    return accepted, rejected
