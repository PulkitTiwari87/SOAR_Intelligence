"""Incident PDF report built from the stored incident (nothing is invented or hardcoded).

Sections are grouped by epistemic status so a reader can tell them apart:
  A. Observed facts       events, indicators, affected assets, timeline
  B. Automated analysis   risk score, ML output, threat intel, MITRE mapping (with source), LLM analysis
  C. Recommendations      what the analysis suggests (NOT actions that were taken)
  D. Actions taken        playbook steps that ran, verification results, approvals and decisions, status
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.domain import SEVERITY_LABELS
from soar.models import AnalystAction, Approval, Asset, Incident, PlaybookExecution, ThreatIntel

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], fontSize=18, textColor=colors.HexColor("#0f3460"))
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=12, textColor=colors.HexColor("#0f3460"), spaceBefore=10)
BODY = ParagraphStyle("b", parent=_ss["BodyText"], fontSize=9, leading=12)
SMALL = ParagraphStyle("s", parent=BODY, fontSize=8, leading=10, textColor=colors.HexColor("#444444"))


def _p(text: object, style=BODY) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "—")), style)


def _table(rows: list[list], widths: list[float], header: bool = True) -> Table:
    data = [[_p(c, SMALL) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f6fa")])]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6ebf5")))
    t.setStyle(TableStyle(style))
    return t


def _ts(d: datetime | None) -> str:
    return d.strftime("%Y-%m-%d %H:%M:%S UTC") if d else "—"


def _rows(header: list[str], body: list[list], empty: str) -> list[list]:
    return [header] + (body or [[empty] + [""] * (len(header) - 1)])


def generate_incident_report(db: Session, inc: Incident, out_dir: Path) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{inc.number}.pdf"
    W = A4[0] - 30 * mm
    events = sorted(inc.events, key=lambda e: e.timestamp)
    preds = {p.kind: p for p in inc.predictions}
    llm = preds.get("llm_commander")
    hosts = {h.lower() for h in (inc.entities or {}).get("hosts", [])}
    assets = [a for a in db.scalars(select(Asset)) if a.hostname.lower() in hosts]
    execs = db.scalars(select(PlaybookExecution).where(PlaybookExecution.incident_id == inc.id)
                       .order_by(PlaybookExecution.created_at)).all()
    approvals = db.scalars(select(Approval).where(Approval.incident_id == inc.id).order_by(Approval.requested_at)).all()
    acts = db.scalars(select(AnalystAction).where(AnalystAction.incident_id == inc.id)
                      .order_by(AnalystAction.created_at)).all()

    s: list = [_p(f"Incident Report {inc.number}", H1), _p(inc.title),
               _p(f"Generated {_ts(datetime.now().astimezone())} · reflects the stored incident record", SMALL),
               HRFlowable(width="100%", color=colors.HexColor("#0f3460"))]
    s.append(_table([["Incident ID", inc.number], ["Status", inc.status], ["Severity", SEVERITY_LABELS.get(inc.severity)],
                     ["Risk score", f"{inc.risk_score} / 100 (evidence coverage {inc.confidence:.0%})"],
                     ["Detection source", inc.source], ["Category", inc.category],
                     ["First event", _ts(inc.first_event_at)], ["Incident created", _ts(inc.detected_at)],
                     ["Resolved", _ts(inc.resolved_at)], ["Correlated events", inc.event_count]],
                    [40 * mm, W - 40 * mm], header=False))

    s.append(_p("A. Observed facts", H2))
    s.append(_p("Summary (automated)", SMALL))
    s.append(_p(inc.summary))
    s.append(_p("Affected assets", SMALL))
    s.append(_table(_rows(["Host", "IP", "Role", "Criticality"],
                          [[a.hostname, a.ip, a.role, a.criticality] for a in assets], "No registered assets matched"),
                    [50 * mm, 35 * mm, 45 * mm, W - 130 * mm]))
    s.append(_p("Indicators of compromise", SMALL))
    ioc_rows = []
    for i in inc.iocs:
        best = db.scalars(select(ThreatIntel).where(ThreatIntel.ioc_id == i.id).order_by(ThreatIntel.score.desc())).first()
        ioc_rows.append([i.type, i.value[:90], f"{best.verdict} ({best.provider})" if best else "not enriched"])
    s.append(_table(_rows(["Type", "Value", "Verdict (provider)"], ioc_rows, "none"), [18 * mm, W - 68 * mm, 50 * mm]))
    s.append(_p("Timeline", SMALL))
    s.append(_table(_rows(["Time (UTC)", "Kind", "Event"], [[_ts(t.timestamp), t.kind, t.title] for t in inc.timeline], "none"),
                    [38 * mm, 28 * mm, W - 66 * mm]))
    s.append(_p("Evidence", SMALL))
    s.append(_p(f"{len(events)} raw event(s) are preserved unmodified in the incident record; "
                "the collect_evidence action produces a snapshot file with a SHA-256."))

    s.append(_p("B. Automated analysis (machine-generated, not analyst-verified)", H2))
    t = preds.get("triage")
    if t:
        top = ", ".join(f"{f['feature']}={f['value']} ({f['contribution']:+.2f})" for f in (t.result or {}).get("top_features", [])[:4])
        s.append(_p(f"ML triage: {t.prediction} (p={t.confidence}) · model {t.model_version} · trained on "
                    f"{(t.result or {}).get('trained_on', 'n/a')}. Top factors: {top}"))
    a = preds.get("anomaly")
    if a:
        s.append(_p(f"Anomaly detection: {a.prediction} (percentile {a.result.get('anomaly_score')}, trigger {a.result.get('trigger')})"))
    s.append(_p("Risk score breakdown (weights are heuristic, not validated)", SMALL))
    s.append(_table(_rows(["Signal", "Weight", "Value", "Points"],
                          [[k, v["weight"], v["value"] if v["available"] else "n/a", v.get("points", "—")]
                           for k, v in (inc.risk_breakdown or {}).items()], "not computed"),
                    [45 * mm, 30 * mm, 30 * mm, W - 105 * mm]))
    s.append(_p("MITRE ATT&CK mapping", SMALL))
    s.append(_table(_rows(["Technique", "Tactic", "Source", "Conf.", "Evidence"],
                          [[f"{m.technique_id} {m.technique_name}" + (f" / {m.subtechnique}" if m.subtechnique else ""), m.tactic,
                            m.source + (" (inferred)" if m.source == "llm_inferred" else ""), f"{m.confidence:.0%}",
                            m.evidence[:80]] for m in inc.mitre], "none mapped"),
                    [45 * mm, 28 * mm, 30 * mm, 14 * mm, W - 117 * mm]))
    if llm:
        r = llm.result or {}
        s.append(_p(f"LLM analysis via {r.get('provider')} ("
                    f"{'LLM' if r.get('llm_used') else 'deterministic fallback, no LLM used'})", SMALL))
        s.append(_p(r.get("summary", "")))

    s.append(_p("C. Recommendations (not actions taken)", H2))
    recs = (llm.result or {}).get("recommended_actions", []) if llm else []
    s.append(_table(_rows(["Action", "Target", "Policy", "Rationale"],
                          [[r["action"], r.get("target"), (r.get("policy") or {}).get("outcome"), r.get("rationale")]
                           for r in recs], "No recommendations recorded"),
                    [32 * mm, 38 * mm, 22 * mm, W - 92 * mm]))

    s.append(_p("D. Actions taken", H2))
    step_rows = [[f"{x.playbook_name} ({x.status})", st.action, st.status,
                  {True: "yes", False: "FAILED", None: "n/a"}[st.verified],
                  ((st.result or {}).get("detail") or st.error or "")[:90]] for x in execs for st in x.steps]
    s.append(_table(_rows(["Playbook", "Step", "Status", "Verified", "Detail"], step_rows, "No playbook executed"),
                    [38 * mm, 26 * mm, 22 * mm, 16 * mm, W - 102 * mm]))
    s.append(_p("Approvals and analyst decisions", SMALL))
    dec = [[_ts(p.decided_at or p.requested_at), p.decided_by or "(pending)", f"{p.action} → {p.status}: {p.reason[:70]}"]
           for p in approvals] + [[_ts(x.created_at), x.username, f"{x.action}: {x.notes[:70]}"] for x in acts]
    s.append(_table(_rows(["When", "Who", "What"], dec, "none"), [38 * mm, 30 * mm, W - 68 * mm]))
    s.append(_p(f"Final status: {inc.status}", BODY))

    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                      bottomMargin=15 * mm, title=f"Incident {inc.number}").build(s)
    return str(path)
