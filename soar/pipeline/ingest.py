"""Ingestion: raw source payload -> normalized event -> (correlated) incident -> analysis."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai.phishing import nlp_phishing_parser as phishing
from soar.models import IOC, Event, Incident, utcnow
from soar.observability import metrics
from soar.pipeline import analysis, correlation
from soar.pipeline.normalizer import NormalizedEvent, normalize

log = logging.getLogger("soar.ingest")
ALERT_MIN_SEVERITY = 2  # events below this are stored (baselines, context) but do not open incidents


@dataclass
class IngestResult:
    event: Event
    incident: Incident | None = None
    duplicate: bool = False
    created_incident: bool = False
    reasons: list[str] = field(default_factory=list)
    analyzed: bool = False


def should_reanalyze(n: int, material: bool = False) -> bool:
    """Analyze on creation, on any material change (higher severity, a new detection rule), the
    first few correlations, then sparsely, so floods stay cheap but the strongest signal is never
    skipped."""
    return material or n <= 3 or n in (5, 10) or n % 25 == 0


def _enrich_email(ev: NormalizedEvent) -> None:
    m = ev.metadata
    res = phishing.analyze_email({"subject": m.get("subject"), "from": m.get("from"), "reply_to": m.get("reply_to"),
                                  "body": m.get("body"), "headers": m.get("headers")})
    m["phishing"] = {k: res[k] for k in ("phishing_score", "verdict", "text_score", "indicator_score", "indicators",
                                         "top_terms", "model_version", "evidence_sha256", "threat_type")}
    m["urls"] = [u["url"] for u in res["urls"]]
    m["url_domains"] = res["domains"]
    ev.url = ev.url or (m["urls"][0] if m["urls"] else None)
    if res["verdict"] != "legitimate":
        ev.event_type = "phishing_email"
        score = res["phishing_score"]
        ev.severity = 4 if score >= 85 else 3 if score >= 70 else 2
        ev.title = f"Phishing email: {m.get('subject') or '(no subject)'}"[:400]


def persist_event(db: Session, ev: NormalizedEvent) -> Event:
    row = Event(event_id=ev.event_id, timestamp=ev.timestamp, source=ev.source, event_type=ev.event_type,
                severity=ev.severity, rule_id=ev.rule_id, title=ev.title, source_ip=ev.source_ip,
                destination_ip=ev.destination_ip, source_host=ev.source_host, destination_host=ev.destination_host,
                username=ev.username, process=ev.process, command=ev.command, file_hash=ev.file_hash,
                domain=ev.domain, url=ev.url, raw_event=ev.raw_event, meta=ev.metadata)
    db.add(row)
    db.flush()
    return row


def ingest(db: Session, source: str, payload: dict | str, analyze: bool = True) -> IngestResult:
    ev = normalize(source, payload)
    existing = db.scalar(select(Event).where(Event.event_id == ev.event_id))
    if existing:
        metrics.count("events_duplicate")
        return IngestResult(event=existing, incident=existing.incident, duplicate=True)
    if ev.source == "email":
        _enrich_email(ev)
    row = persist_event(db, ev)
    metrics.count("events_ingested")

    if ev.event_type == "threat_intel_indicator":  # indicator feed: store as IOC, no incident
        for typ, val in correlation.extract_iocs(ev):
            if not db.scalar(select(IOC).where(IOC.type == typ, IOC.value == val)):
                db.add(IOC(type=typ, value=val))
        return IngestResult(event=row)

    inc, reasons = correlation.find_incident(db, ev)
    created, material = False, False
    if inc is None:
        if ev.severity < ALERT_MIN_SEVERITY:
            return IngestResult(event=row)
        inc, created = correlation.create_incident(db, ev, row), True
        metrics.count("incidents_created")
    else:
        prev_max = db.scalar(select(func.max(Event.severity)).where(Event.incident_id == inc.id,
                                                                    Event.id != row.id)) or 0
        material = ev.severity > prev_max or bool(ev.rule_id and ev.rule_id not in (inc.entities or {}).get("rules", []))
        correlation.attach_event(db, inc, ev, row, reasons)
        metrics.count("events_correlated")
    correlation.link_iocs(db, inc, correlation.extract_iocs(ev))
    res = IngestResult(event=row, incident=inc, created_incident=created, reasons=reasons)
    if analyze and should_reanalyze(inc.event_count, material):
        analysis.analyze_incident(db, inc)
        res.analyzed = True
    inc.updated_at = utcnow()
    return res
