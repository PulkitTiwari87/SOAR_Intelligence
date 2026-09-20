"""Incident analysis pipeline. Runs whenever an incident is created or grows meaningfully.

  1 threat-intel enrichment of the incident's IOCs        (soar.intel.enrich)
  2 ML triage on features derived from the correlated events (ai.triage)
  3 anomaly check on the host's recent behavior             (ai.anomaly)
  4 MITRE ATT&CK mapping                                    (soar.pipeline.mitre)
  5 blast radius from the asset inventory                   (ai.blast_radius)
  6 centralized risk score -> severity                      (soar.pipeline.risk)
  7 automatic playbooks, gated by the response policy       (soar.playbooks.engine)

Every stage writes a `model_predictions` row and/or a timeline entry, so the outcome is auditable.
A failing stage is logged and skipped; it never blocks the others.
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai.anomaly import isolation_forest_detector as anomaly
from ai.blast_radius import blast_radius_predictor as blast
from ai.triage import ml_triage_analyzer as triage
from soar.domain import SEVERITY_LABELS, TimelineKind
from soar.intel import enrich
from soar.models import Asset, Event, Incident, MitreMapping, ModelPrediction, ThreatIntel, utcnow
from soar.observability import metrics
from soar.pipeline import mitre, risk, timeline
from soar.pipeline.correlation import is_public_ip

log = logging.getLogger("soar.analysis")
_LEVEL_FROM_SEVERITY = {1: 3, 2: 8, 3: 11, 4: 14}


def save_mitre(db: Session, inc: Incident, mappings: list[mitre.Mapping]) -> int:
    new = 0
    for m in mappings:
        row = db.scalar(select(MitreMapping).where(MitreMapping.incident_id == inc.id,
                                                   MitreMapping.technique_id == m.technique_id,
                                                   MitreMapping.source == m.source))
        if row is None:
            db.add(MitreMapping(incident_id=inc.id, tactic=m.tactic, technique_id=m.technique_id,
                                technique_name=m.technique_name, subtechnique=m.subtechnique, source=m.source,
                                confidence=m.confidence, evidence=m.evidence))
            new += 1
        elif m.confidence > row.confidence:
            row.confidence, row.evidence = m.confidence, m.evidence
    db.flush()
    db.refresh(inc)
    return new


def _record(db: Session, inc: Incident, kind: str, name: str, version: str, prediction: str,
            confidence: float | None, result: dict, started: float) -> ModelPrediction:
    ms = (time.perf_counter() - started) * 1000
    metrics.observe(f"{kind}_latency_ms", ms)
    p = ModelPrediction(incident_id=inc.id, kind=kind, model_name=name, model_version=version,
                        prediction=prediction, confidence=confidence, result=result, latency_ms=round(ms, 2))
    db.add(p)
    return p


def triage_features(inc: Incident, events: list[Event], ioc_score: float | None) -> dict:
    meta = [e.meta or {} for e in events]
    level = max([int(m.get("wazuh_level") or 0) for m in meta] + [_LEVEL_FROM_SEVERITY[max((e.severity for e in events), default=1)]])
    last = max((e.timestamp for e in events), default=utcnow())
    return triage.build_features(
        rule_level=level, failed_logins=sum(int(m.get("failed_logins") or 0) for m in meta),
        src_ip_is_internal=0 if is_public_ip(inc.primary_source_ip) else 1, ioc_score=ioc_score,
        event_count=inc.event_count, is_fim_event=int(any(e.event_type == "file_integrity" for e in events)),
        has_mitre_tag=int(any((m.get("mitre") or {}).get("ids") for m in meta)),
        off_hours=int(last.hour < 7 or last.hour >= 20))


def host_metrics(db: Session, inc: Incident, events: list[Event]) -> dict:
    """Behavior metrics for the incident's host over its own event span (only what we can measure)."""
    if not events:
        return {}
    start, end = min(e.timestamp for e in events), max(e.timestamp for e in events)
    minutes = max(1.0, (end - start).total_seconds() / 60)
    meta = [e.meta or {} for e in events]
    return {
        "events_per_minute": len(events) / minutes,
        "failed_auth_count": sum(int(m.get("failed_logins") or 0) for m in meta),
        "unique_src_ips": len({e.source_ip for e in events if e.source_ip}) or None,
        "unique_dst_ports": max([int(m.get("unique_dst_ports") or 0) for m in meta] or [0]) or None,
        "bytes_transferred": sum(int(m.get("bytes_out") or 0) for m in meta) or None,
        "hour_of_day": end.hour,
        "file_changes": sum(1 for e in events if e.event_type == "file_integrity") or None,
        "new_process_count": sum(1 for e in events if e.process or e.command) or None,
    }


def analyze_incident(db: Session, inc: Incident, run_playbooks: bool = True) -> dict[str, Any]:
    started_all = time.perf_counter()
    db.refresh(inc)
    events = sorted(inc.events, key=lambda e: e.timestamp)
    out: dict[str, Any] = {}
    signals: dict[str, float | None] = {}

    # 1 ── threat intel
    t0 = time.perf_counter()
    by_ioc: dict[str, list[ThreatIntel]] = {}
    for ioc in inc.iocs:
        try:
            by_ioc[ioc.id] = enrich.enrich_ioc(db, ioc)
        except Exception:  # noqa: BLE001
            log.exception("enrichment failed for %s", ioc.value)
    signals["ioc"] = enrich.ioc_risk_signal(by_ioc)
    known = [enrich.best_verdict(r) for r in by_ioc.values()]
    known = [k for k in known if k and k.verdict in ("malicious", "suspicious")]
    ioc_score = max((k.score for k in known), default=None)
    if by_ioc and not any(t.data.get("stage") == "intel" for t in inc.timeline):
        flagged = [f"{k.ioc.value} ({k.verdict}, {k.provider})" for k in known]
        timeline.add(db, inc, TimelineKind.THREAT_INTEL.value, f"Threat intel: {len(by_ioc)} indicator(s) checked",
                     ("Flagged: " + ", ".join(flagged)) if flagged else "No provider flagged any indicator",
                     data={"stage": "intel", "flagged": len(known)})
    metrics.observe("intel_stage_ms", (time.perf_counter() - t0) * 1000)

    # 2 ── ML triage
    try:
        t0 = time.perf_counter()
        feats = triage_features(inc, events, ioc_score)
        res = triage.predict_threat(feats)
        _record(db, inc, "triage", "xgboost_triage", res["model_version"], res["label"], res["probability"], res, t0)
        signals["ml"] = res["probability"]
        out["triage"] = res
        timeline.add(db, inc, TimelineKind.ML_ANALYSIS.value, f"ML triage: {res['label']} ({res['confidence_score']}%)",
                     "top factors: " + ", ".join(f"{t['feature']} ({t['contribution']:+.2f})" for t in res["top_features"][:3]),
                     data={"model_version": res["model_version"]})
    except Exception:  # noqa: BLE001
        log.exception("triage failed for %s", inc.number)

    # 3 ── anomaly
    try:
        t0 = time.perf_counter()
        hm = host_metrics(db, inc, events)
        if hm:
            a = anomaly.detect_anomaly(hm)
            _record(db, inc, "anomaly", "isolation_forest", a["model_version"],
                    "anomalous" if a["is_anomaly"] else "normal", a["anomaly_score"] / 100, a, t0)
            signals["anomaly"] = a["anomaly_score"] / 100 if a["is_anomaly"] else a["anomaly_score"] / 200
            out["anomaly"] = a
            if a["is_anomaly"]:
                timeline.add(db, inc, TimelineKind.ML_ANALYSIS.value, f"Anomaly: {a['threat_type']}",
                             f"trigger={a['trigger']}; deviating: {a['deviating_features']}")
    except Exception:  # noqa: BLE001
        log.exception("anomaly detection failed for %s", inc.number)

    # 4 ── MITRE
    mapped = mitre.map_events(events)
    new_maps = save_mitre(db, inc, mapped)
    signals["mitre"] = risk.tactic_signal([m.tactic for m in mapped])
    if new_maps:
        timeline.add(db, inc, TimelineKind.MITRE.value, f"MITRE ATT&CK: {', '.join(m.technique_id for m in mapped)}",
                     "; ".join(f"{m.technique_id} via {m.source} ({m.confidence:.0%})" for m in mapped))
    out["mitre"] = [m.__dict__ for m in mapped]

    # 5 ── blast radius + asset criticality
    hosts = [h for h in {inc.primary_host, *(inc.entities or {}).get("hosts", [])} if h]
    assets = list(db.scalars(select(Asset).where(func.lower(Asset.hostname).in_([h.lower() for h in hosts])))) if hosts else []
    signals["asset"] = max((a.criticality for a in assets), default=None) / 10 if assets else None
    origin = blast.resolve_host(db, inc.primary_host) or blast.resolve_host(db, inc.primary_source_ip)
    if origin:
        t0 = time.perf_counter()
        br = blast.predict_blast_radius(origin, blast.build_graph(db), db=db)
        if br.get("status") == "ok":
            _record(db, inc, "blast_radius", "graph_bfs", "1", f"{br['total_at_risk']} hosts", None, br, t0)
            out["blast_radius"] = br

    # 6 ── history + correlation → risk
    cutoff = utcnow() - timedelta(days=30)
    conds = [Incident.primary_source_ip == inc.primary_source_ip] if inc.primary_source_ip else []
    if inc.primary_host:
        conds.append(Incident.primary_host == inc.primary_host)
    prior = db.scalar(select(func.count()).select_from(Incident).where(
        Incident.id != inc.id, Incident.created_at >= cutoff, conds[0] if len(conds) == 1 else (conds[0] | conds[1]))) if conds else 0
    signals["history"] = risk.history_signal(prior)
    signals["correlation"] = risk.correlation_signal(inc.event_count)
    signals["severity"] = risk.severity_signal(max((e.severity for e in events), default=1))
    r = risk.compute_risk(signals)
    changed = round(inc.risk_score, 1) != r.score
    inc.risk_score, inc.risk_breakdown, inc.confidence, inc.severity = r.score, r.breakdown, r.confidence, r.severity
    inc.summary = (f"{inc.category.replace('_', ' ')}: {inc.event_count} event(s)"
                   + (f" from {inc.primary_source_ip}" if inc.primary_source_ip else "")
                   + (f" on {inc.primary_host}" if inc.primary_host else "")
                   + f". Risk {r.score} ({SEVERITY_LABELS[r.severity]}). [automated summary]")
    if changed:
        timeline.add(db, inc, TimelineKind.ML_ANALYSIS.value, f"Risk score {r.score} → {SEVERITY_LABELS[r.severity]}",
                     f"evidence coverage {r.confidence:.0%}; prior incidents (30d): {prior}", data={"risk": r.score})
    out["risk"] = {"score": r.score, "severity": r.severity, "confidence": r.confidence, "breakdown": r.breakdown}
    db.flush()

    # 7 ── automatic playbooks
    if run_playbooks:
        from soar.playbooks import engine
        out["executions"] = [x.id for x in engine.auto_trigger(db, inc)]
    metrics.observe("analysis_ms", (time.perf_counter() - started_all) * 1000)
    metrics.count("analyses")
    return out
