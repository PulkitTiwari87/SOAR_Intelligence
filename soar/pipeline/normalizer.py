"""Event normalization: every source is converted to one common schema.

The original payload is always kept in `raw_event`; nothing is dropped. `event_id` is a hash
of (source, canonical payload), so re-sending the same event is idempotent.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, UTC
from typing import Any

from pydantic import BaseModel, Field

SOURCES = {"wazuh", "syslog", "network", "email", "misp", "generic"}


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: int = Field(ge=1, le=4)
    rule_id: str | None = None
    title: str = ""
    source_ip: str | None = None
    destination_ip: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    username: str | None = None
    process: str | None = None
    command: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None
    raw_event: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizationError(ValueError):
    pass


# ─── helpers ───
def valid_ip(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def parse_timestamp(value: Any) -> datetime:
    """ISO-8601 (incl. Wazuh's `+0000`), epoch seconds/ms; falls back to now."""
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        v = value.strip().replace("Z", "+00:00")
        v = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v)  # +0000 -> +00:00
        try:
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _hash_event(source: str, payload: Any) -> str:
    canon = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(f"{source}|{canon}".encode()).hexdigest()[:32]


def _clip(value: Any, n: int = 2000) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s[:n] if s else None


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def wazuh_level_to_severity(level: int) -> int:
    return 1 if level <= 6 else 2 if level <= 9 else 3 if level <= 12 else 4


def _clamp_sev(v: Any) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 1
    return max(1, min(4, n))


# ─── Wazuh ───
def _wazuh_event_type(rule: dict, alert: dict) -> str:
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = groups.split(",")
    g = {x.strip().lower() for x in groups if x}
    desc = (rule.get("description") or "").lower()
    full = (alert.get("full_log") or "").lower()
    if g & {"authentication_failed", "authentication_failures", "invalid_login"} or \
            ("authentication" in desc and "fail" in desc) or "failed password" in full:
        return "authentication_failure"
    if "authentication_success" in g:
        return "authentication_success"
    if "reverse shell" in desc or "suspicious_activity" in g or "suspicious" in desc:
        return "suspicious_process"
    if g & {"malware", "malware_detection", "virustotal", "yara"} or "malware" in desc:
        return "malware_detection"
    if g & {"web", "attack", "sql_injection", "web_scan", "attacks"} or "injection" in desc:
        return "web_attack"
    if g & {"privilege_escalation", "sudo"} or "privilege" in desc:
        return "privilege_escalation"
    if "syscheck" in g or alert.get("syscheck"):
        return "file_integrity"
    if g & {"data_leak", "exfiltration"} or "exfil" in desc:
        return "data_exfiltration"
    if g & {"recon", "scan"} or "scan" in desc:
        return "network_scan"
    if "phishing" in g:
        return "phishing_email"
    return "security_alert"


def _norm_wazuh(a: dict) -> dict:
    rule, agent, data = a.get("rule") or {}, a.get("agent") or {}, a.get("data") or {}
    syscheck = a.get("syscheck") or {}
    level = int(rule.get("level") or 0)
    mitre = rule.get("mitre") or {}
    etype = _wazuh_event_type(rule, a)
    win = (data.get("win") or {}).get("eventdata") or {}
    command = _first(data, "command", "cmd") or win.get("commandLine")
    if not command and etype == "suspicious_process":
        command = a.get("full_log")
    freq = rule.get("frequency")
    failed = (int(freq) if freq else 1) if etype == "authentication_failure" else 0
    return dict(
        event_type=etype, severity=wazuh_level_to_severity(level),
        rule_id=str(rule.get("id") or "") or None,
        title=_clip(rule.get("description") or "Wazuh alert", 400),
        timestamp=parse_timestamp(a.get("timestamp") or a.get("@timestamp")),
        source_ip=valid_ip(_first(data, "srcip", "src_ip", "source_ip")),
        destination_ip=valid_ip(_first(data, "dstip", "dst_ip")),
        source_host=_clip(agent.get("name")), destination_host=None,
        username=_clip(_first(data, "dstuser", "srcuser", "user") or win.get("targetUserName"), 128),
        process=_clip((data.get("audit") or {}).get("exe") or win.get("image"), 255),
        command=_clip(command, 1000),
        file_hash=(syscheck.get("sha256_after") or syscheck.get("md5_after") or "").lower() or None,
        domain=None, url=_clip(_first(data, "url")),
        metadata={"wazuh_level": level, "agent_id": agent.get("id"), "agent_ip": agent.get("ip"),
                  "groups": rule.get("groups"), "location": a.get("location"),
                  "mitre": {"ids": mitre.get("id") or [], "tactics": mitre.get("tactic") or [],
                            "techniques": mitre.get("technique") or []},
                  "failed_logins": failed, "fim_path": syscheck.get("path")},
    )


# ─── syslog / auth log lines ───
_SYSLOG = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\s(?P<prog>[^:\[\s]+)"
                     r"(?:\[\d+\])?:\s(?P<msg>.*)$")
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
                       r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
_SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from "
                     r"(?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
_SUDO = re.compile(r"(?P<user>\S+)\s*: .*?COMMAND=(?P<cmd>.*)$")


def _norm_syslog(p: dict | str) -> dict:
    line = p if isinstance(p, str) else str(p.get("message") or p.get("line") or "")
    host = None if isinstance(p, str) else p.get("host")
    ts = None if isinstance(p, str) else p.get("timestamp")
    msg = line
    m = _SYSLOG.match(line.strip())
    if m:
        host = host or m["host"]
        msg = m["msg"]
        if not ts:
            try:
                ts = datetime.strptime(f"{datetime.now().year} {m['ts']}", "%Y %b %d %H:%M:%S") \
                    .replace(tzinfo=UTC)
            except ValueError:
                ts = None
    out: dict[str, Any] = dict(event_type="log_event", severity=1, title=_clip(msg, 300) or "log",
                               source_host=_clip(host), timestamp=parse_timestamp(ts),
                               metadata={"program": m["prog"] if m else None})
    if f := (_SSH_FAIL.search(msg) or _SSH_INVALID.search(msg)):
        out.update(event_type="authentication_failure", severity=2, username=f["user"],
                   source_ip=valid_ip(f["ip"]), title=f"SSH authentication failure for {f['user']}")
        out["metadata"]["failed_logins"] = 1
    elif ok := _SSH_OK.search(msg):
        out.update(event_type="authentication_success", severity=1, username=ok["user"],
                   source_ip=valid_ip(ok["ip"]), title=f"SSH login accepted for {ok['user']}")
    elif s := _SUDO.search(msg):
        out.update(event_type="privilege_use", severity=2, username=s["user"],
                   command=_clip(s["cmd"], 1000), title=f"sudo command by {s['user']}")
    return out


# ─── network telemetry ───
def _norm_network(p: dict) -> dict:
    dport = p.get("dst_port") or p.get("destination_port")
    scanned = int(p.get("unique_dst_ports") or 0)
    etype = _first(p, "event_type") or ("network_scan" if scanned >= 10 else "network_connection")
    domain = _first(p, "domain", "dns_query")
    return dict(
        event_type=str(etype)[:64],
        severity=_clamp_sev(p.get("severity", 3 if etype == "network_scan" else 1)),
        title=_clip(p.get("title") or f"{etype} {p.get('src_ip', '')} -> "
                    f"{p.get('dst_ip', '')}:{dport or ''}", 300),
        timestamp=parse_timestamp(p.get("timestamp")),
        source_ip=valid_ip(_first(p, "src_ip", "source_ip")),
        destination_ip=valid_ip(_first(p, "dst_ip", "destination_ip")),
        source_host=_clip(_first(p, "src_host", "source_host")),
        destination_host=_clip(_first(p, "dst_host", "destination_host")),
        domain=str(domain).lower() if domain else None, url=_clip(p.get("url")),
        metadata={k: p[k] for k in ("dst_port", "protocol", "bytes_out", "bytes_in", "duration",
                                    "unique_dst_ports", "action") if k in p},
    )


# ─── email ───
def _norm_email(p: dict) -> dict:
    from email import message_from_string, policy
    raw = p.get("raw")
    subject, sender, reply_to, body, to = (p.get("subject"), p.get("from"), p.get("reply_to"),
                                           p.get("body"), p.get("to"))
    headers: dict[str, str] = dict(p.get("headers") or {})
    if raw:
        msg = message_from_string(raw, policy=policy.default)
        subject, sender = subject or msg["subject"], sender or msg["from"]
        reply_to, to = reply_to or msg["reply-to"], to or msg["to"]
        headers.update({k: str(v) for k, v in msg.items()})
        part = msg.get_body(preferencelist=("plain", "html"))
        body = body or (part.get_content() if part else "")
    sender_addr = re.search(r"[\w.+-]+@([\w.-]+)", str(sender or ""))
    return dict(
        event_type="email_received", severity=1,
        title=_clip(f"Email: {subject or '(no subject)'}", 300),
        timestamp=parse_timestamp(p.get("timestamp") or headers.get("Date")),
        username=_clip(to, 128), domain=sender_addr.group(1).lower() if sender_addr else None,
        metadata={"subject": str(subject) if subject else None,
                  "from": str(sender) if sender else None,
                  "reply_to": str(reply_to) if reply_to else None, "to": str(to) if to else None,
                  "body": _clip(body, 20000), "headers": {k: headers[k] for k in list(headers)[:40]}},
    )


# ─── MISP indicator ───
_MISP_TYPES = {"ip-src": "source_ip", "ip-dst": "destination_ip", "domain": "domain",
               "url": "url", "sha256": "file_hash", "md5": "file_hash", "sha1": "file_hash"}


def _norm_misp(p: dict) -> dict:
    attr = p.get("Attribute", p)
    field = _MISP_TYPES.get(str(attr.get("type")))
    if not field:
        raise NormalizationError(f"Unsupported MISP attribute type: {attr.get('type')}")
    value = str(attr.get("value") or "").strip()
    out: dict[str, Any] = dict(
        event_type="threat_intel_indicator", severity=1,
        title=f"MISP indicator {attr.get('type')}: {value}"[:300],
        timestamp=parse_timestamp(attr.get("timestamp")),
        metadata={"misp_event_id": attr.get("event_id"), "to_ids": attr.get("to_ids"),
                  "category": attr.get("category")})
    out[field] = valid_ip(value) if field.endswith("_ip") else value.lower()
    return out


# ─── generic (already close to the schema) ───
def _norm_generic(p: dict) -> dict:
    return dict(
        event_type=str(p.get("event_type") or "generic_event")[:64],
        severity=_clamp_sev(p.get("severity", 1)), rule_id=_clip(p.get("rule_id"), 64),
        title=_clip(p.get("title") or p.get("message") or "event", 400),
        timestamp=parse_timestamp(p.get("timestamp")),
        source_ip=valid_ip(_first(p, "source_ip", "src_ip", "srcip")),
        destination_ip=valid_ip(_first(p, "destination_ip", "dst_ip", "dstip")),
        source_host=_clip(_first(p, "source_host", "host", "hostname")),
        destination_host=_clip(p.get("destination_host")),
        username=_clip(p.get("username") or p.get("user"), 128),
        process=_clip(p.get("process"), 255), command=_clip(p.get("command"), 1000),
        file_hash=str(p["file_hash"]).lower() if p.get("file_hash") else None,
        domain=str(p["domain"]).lower() if p.get("domain") else None, url=_clip(p.get("url")),
        metadata=dict(p.get("metadata") or {}),
    )


_HANDLERS = {"wazuh": _norm_wazuh, "syslog": _norm_syslog, "network": _norm_network,
             "email": _norm_email, "misp": _norm_misp, "generic": _norm_generic}


def normalize(source: str, payload: dict | str) -> NormalizedEvent:
    source = (source or "").lower()
    if source not in _HANDLERS:
        raise NormalizationError(f"Unknown source '{source}'. Supported: {sorted(SOURCES)}")
    if isinstance(payload, str) and source != "syslog":
        raise NormalizationError(f"Source '{source}' expects a JSON object")
    if not isinstance(payload, (dict, str)):
        raise NormalizationError("Payload must be an object (or a log line for syslog)")
    try:
        fields = _HANDLERS[source](payload)  # type: ignore[arg-type]
    except NormalizationError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError) as e:
        raise NormalizationError(f"Could not normalize {source} payload: {e}") from e
    raw = payload if isinstance(payload, dict) else {"line": payload}
    fields["metadata"] = {k: v for k, v in (fields.get("metadata") or {}).items() if v is not None}
    return NormalizedEvent(event_id=_hash_event(source, raw), source=source, raw_event=raw, **fields)
