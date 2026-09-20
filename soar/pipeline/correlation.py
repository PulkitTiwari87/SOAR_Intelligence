"""Incident correlation: decide whether an event belongs to an open incident or starts a new one.

Signals are entity overlaps between the event and an open incident inside a time window, each with
a weight. The best-scoring incident wins if it reaches CORRELATION_THRESHOLD (default 3.0):

    shared file hash            4.0      shared external IP   3.0     shared domain/URL host  3.0
    shared internal IP          2.0      shared host          2.0     shared username         1.0
    (generic accounts such as root/admin count 0.5)                    shared Wazuh rule id    0.5

So one shared public IP is enough, while a shared host alone is not (host + user, or host + IP,
is). Loopback/unspecified/multicast addresses never count. Matching is deliberately conservative:
two incidents are never auto-merged, an event joins at most one incident.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from soar.config import get_settings
from soar.domain import OPEN_STATUSES, SEVERITY_LABELS, IncidentStatus, TimelineKind
from soar.models import IOC, Event, Incident, incident_iocs, utcnow
from soar.pipeline import timeline
from soar.pipeline.normalizer import NormalizedEvent

GENERIC_USERS = {"root", "admin", "administrator", "system", "unknown", "guest", "user"}
ENTITY_KEYS = ("ips", "hosts", "users", "hashes", "domains", "rules")


def usable_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local)


def is_public_ip(ip: str | None) -> bool:
    return usable_ip(ip) and ipaddress.ip_address(ip).is_global  # type: ignore[arg-type]


def _url_host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlparse(url if "://" in url else f"//{url}").hostname or "").lower() or None
    except ValueError:
        return None


_IPV4_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def ips_in_text(*texts: str | None) -> set[str]:
    """IPv4 addresses mentioned in a command line or URL (e.g. the peer of a reverse shell)."""
    found = set()
    for t in texts:
        for cand in _IPV4_IN_TEXT.findall(t or ""):
            if usable_ip(cand):
                found.add(str(ipaddress.ip_address(cand)))
    return found


def event_entities(e: Any) -> dict[str, set[str]]:
    ips = {ip for ip in (e.source_ip, e.destination_ip) if usable_ip(ip)} | ips_in_text(e.command)
    hosts = {h.lower() for h in (e.source_host, e.destination_host) if h}
    domains = {d for d in (e.domain, _url_host(e.url)) if d}
    return {"ips": ips, "hosts": hosts, "users": {e.username.lower()} if e.username else set(),
            "hashes": {e.file_hash.lower()} if e.file_hash else set(), "domains": domains,
            "rules": {str(e.rule_id)} if e.rule_id else set()}


def score_match(ev: dict[str, set[str]], inc: dict[str, list[str]]) -> tuple[float, list[str]]:
    score, reasons = 0.0, []
    for h in ev["hashes"] & set(inc.get("hashes", [])):
        score += 4.0
        reasons.append(f"same file hash {h[:12]}…")
    for ip in ev["ips"] & set(inc.get("ips", [])):
        w = 3.0 if is_public_ip(ip) else 2.0
        score += w
        reasons.append(f"same {'external' if w == 3.0 else 'internal'} IP {ip}")
    for d in ev["domains"] & set(inc.get("domains", [])):
        score += 3.0
        reasons.append(f"same domain {d}")
    for h in ev["hosts"] & set(inc.get("hosts", [])):
        score += 2.0
        reasons.append(f"same host {h}")
    for u in ev["users"] & set(inc.get("users", [])):
        w = 0.5 if u in GENERIC_USERS else 1.0
        score += w
        reasons.append(f"same user {u}")
    for r in ev["rules"] & set(inc.get("rules", [])):
        score += 0.5
        reasons.append(f"same rule {r}")
    return score, reasons


def find_incident(db: Session, ev: NormalizedEvent) -> tuple[Incident | None, list[str]]:
    s = get_settings()
    window = timedelta(minutes=s.correlation_window_minutes)
    open_states = [x.value for x in OPEN_STATUSES]
    candidates = db.scalars(select(Incident).where(
        Incident.status.in_(open_states), Incident.last_event_at >= ev.timestamp - window,
        Incident.first_event_at <= ev.timestamp + window))
    entities = event_entities(ev)
    best, best_score, best_reasons = None, 0.0, []
    for inc in candidates:
        sc, reasons = score_match(entities, inc.entities or {})
        if sc > best_score:
            best, best_score, best_reasons = inc, sc, reasons
    if best is not None and best_score >= s.correlation_threshold:
        return best, best_reasons
    return None, []


def _next_number(db: Session, year: int) -> int:
    prefix = f"INC-{year}-"
    last = db.scalar(select(Incident.number).where(Incident.number.like(f"{prefix}%"))
                     .order_by(Incident.number.desc()).limit(1))
    return int(last.rsplit("-", 1)[1]) + 1 if last else 1


def _merge_entities(inc: Incident, ents: dict[str, set[str]]) -> None:
    merged = {k: set((inc.entities or {}).get(k, [])) | ents.get(k, set()) for k in ENTITY_KEYS}
    inc.entities = {k: sorted(v) for k, v in merged.items()}


def _update_span(inc: Incident, ev: NormalizedEvent) -> None:
    inc.first_event_at = min(inc.first_event_at, ev.timestamp) if inc.first_event_at else ev.timestamp
    inc.last_event_at = max(inc.last_event_at, ev.timestamp) if inc.last_event_at else ev.timestamp


def create_incident(db: Session, ev: NormalizedEvent, event_row: Event) -> Incident:
    year = utcnow().year
    for _ in range(5):  # unique(number) protects against concurrent creators
        try:
            with db.begin_nested():
                inc = Incident(
                    number=f"INC-{year}-{_next_number(db, year):04d}", title=ev.title[:300] or "Incident",
                    status=IncidentStatus.NEW.value, severity=ev.severity, source=ev.source,
                    category=ev.event_type, primary_source_ip=ev.source_ip if usable_ip(ev.source_ip) else None,
                    primary_host=ev.source_host, primary_user=ev.username, event_count=0,
                    entities={k: [] for k in ENTITY_KEYS})
                db.add(inc)
                db.flush()
            break
        except IntegrityError:
            continue
    else:  # pragma: no cover
        raise RuntimeError("Could not allocate an incident number")
    _merge_entities(inc, event_entities(ev))
    _attach(db, inc, ev, event_row)
    timeline.add(db, inc, TimelineKind.DETECTION.value, f"Detected: {ev.title}",
                 f"{ev.source} event {ev.event_type} (severity {SEVERITY_LABELS[ev.severity]})",
                 data={"event_id": ev.event_id, "rule_id": ev.rule_id}, ts=ev.timestamp)
    timeline.add(db, inc, TimelineKind.ALERT.value, f"Incident {inc.number} created",
                 f"Opened from {ev.source} alert; risk analysis pending")
    return inc


def _attach(db: Session, inc: Incident, ev: NormalizedEvent, event_row: Event) -> None:
    event_row.incident_id = inc.id
    inc.event_count = (inc.event_count or 0) + 1
    inc.severity = max(inc.severity or 1, ev.severity)
    _update_span(inc, ev)
    _merge_entities(inc, event_entities(ev))
    inc.primary_host = inc.primary_host or ev.source_host
    inc.primary_user = inc.primary_user or ev.username
    if not inc.primary_source_ip and usable_ip(ev.source_ip):
        inc.primary_source_ip = ev.source_ip


def attach_event(db: Session, inc: Incident, ev: NormalizedEvent, event_row: Event,
                 reasons: list[str]) -> None:
    _attach(db, inc, ev, event_row)
    n = inc.event_count
    if n <= 5 or n % 10 == 0:  # keep the timeline readable during floods
        timeline.add(db, inc, TimelineKind.CORRELATION.value,
                     f"Correlated event #{n}: {ev.title}"[:300], "; ".join(reasons),
                     data={"event_id": ev.event_id, "reasons": reasons}, ts=ev.timestamp)


_IOC_LINK = incident_iocs


def extract_iocs(ev: NormalizedEvent) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for ip in [ev.source_ip, ev.destination_ip, *sorted(ips_in_text(ev.command))]:
        if is_public_ip(ip):
            out.append(("ip", ip))  # type: ignore[arg-type]
    if ev.domain and ev.source != "email":  # an email's sender domain is context, not an IOC
        out.append(("domain", ev.domain))
    if ev.url:
        out.append(("url", ev.url[:1000]))
    if ev.file_hash:
        out.append(("hash", ev.file_hash))
    for u in (ev.metadata.get("urls") or []):
        out.append(("url", str(u)[:1000]))
    for d in (ev.metadata.get("url_domains") or []):
        out.append(("domain", str(d).lower()))
    return list(dict.fromkeys(out))


def link_iocs(db: Session, inc: Incident, iocs: list[tuple[str, str]]) -> list[IOC]:
    rows: list[IOC] = []
    linked = {i.id for i in inc.iocs}
    for typ, value in iocs:
        row = db.scalar(select(IOC).where(IOC.type == typ, IOC.value == value))
        if row is None:
            row = IOC(type=typ, value=value)
            db.add(row)
            db.flush()
        row.last_seen = utcnow()
        if row.id not in linked:
            inc.iocs.append(row)
            linked.add(row.id)
        rows.append(row)
    return rows


def now() -> datetime:  # indirection so tests can patch time if needed
    return utcnow()
