"""Playbook effectiveness report computed ONLY from stored executions, steps and approvals.

There is no sample or synthetic history. With few executions the report says so instead of drawing
conclusions: recommendations require at least MIN_SAMPLES observations of the thing they describe.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.models import Approval, ExecutionStep, PlaybookExecution

MIN_SAMPLES = 10


def _avg(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 2) if xs else None


def playbook_report(db: Session) -> dict:
    execs = db.scalars(select(PlaybookExecution)).all()
    steps = db.scalars(select(ExecutionStep)).all()
    approvals = db.scalars(select(Approval)).all()

    per_pb: dict[str, dict] = defaultdict(lambda: {"executions": 0, "by_status": defaultdict(int), "durations": []})
    for x in execs:
        d = per_pb[x.playbook_name]
        d["executions"] += 1
        d["by_status"][x.status] += 1
        if x.status == "completed" and x.started_at and x.finished_at:
            d["durations"].append((x.finished_at - x.started_at).total_seconds())

    per_action: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for s in steps:
        a = per_action[s.action]
        a["runs"] += 1
        a[s.status] += 1
        if s.verified is True:
            a["verified"] += 1
        elif s.verified is False:
            a["verification_failed"] += 1

    waits = [(a.decided_at - a.requested_at).total_seconds() for a in approvals if a.decided_at]
    decided = [a for a in approvals if a.status in ("approved", "rejected")]

    recommendations = []
    for action, a in per_action.items():
        if a["runs"] >= MIN_SAMPLES:
            if a["failed"] / a["runs"] > 0.3:
                recommendations.append(f"{action}: {a['failed']}/{a['runs']} runs failed; check its connector/credentials.")
            if a["skipped"] / a["runs"] > 0.5:
                recommendations.append(f"{action}: skipped in {a['skipped']}/{a['runs']} runs (no data or no connector configured).")
    if len(decided) >= MIN_SAMPLES and sum(a.status == "rejected" for a in decided) / len(decided) > 0.5:
        recommendations.append("Over half of approvals are rejected: consider tightening playbook triggers or conditions.")
    if not recommendations and len(execs) < MIN_SAMPLES:
        recommendations.append(f"Not enough executions yet ({len(execs)}/{MIN_SAMPLES}) for recommendations.")

    return {
        "totals": {"executions": len(execs), "steps": len(steps), "approvals": len(approvals)},
        "enough_data": len(execs) >= MIN_SAMPLES,
        "playbooks": {name: {"executions": d["executions"], "by_status": dict(d["by_status"]),
                             "avg_completed_seconds": _avg(d["durations"])} for name, d in per_pb.items()},
        "actions": {name: dict(a) for name, a in per_action.items()},
        "approvals": {"decided": len(decided), "approved": sum(a.status == "approved" for a in decided),
                      "rejected": sum(a.status == "rejected" for a in decided),
                      "pending": sum(a.status == "pending" for a in approvals),
                      "avg_seconds_to_decision": _avg(waits)},
        "recommendations": recommendations,
    }
