"""Centralized risk score.

risk = 100 * sum(weight_i * signal_i) / sum(weight_i over the signals that are available)

Each signal is in [0, 1]. A signal that cannot be computed (e.g. no threat-intel result yet) is
reported as unavailable and excluded from BOTH sums, so missing evidence neither raises nor lowers
the score; it lowers `confidence` instead (the fraction of total weight that was available).

The weights below are expert-chosen defaults. They have NOT been validated against labeled
incidents and should be tuned once real analyst outcomes are available (see docs/AI_MODELS.md).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

WEIGHTS: dict[str, float] = {
    "ml": 0.25,           # ML triage: probability the activity is malicious
    "severity": 0.20,     # highest detection severity among correlated events
    "ioc": 0.15,          # worst threat-intel verdict (score * confidence)
    "asset": 0.15,        # criticality of the most critical affected asset
    "correlation": 0.10,  # how many events were correlated into this incident
    "anomaly": 0.05,      # deviation from the host's baseline behavior
    "mitre": 0.05,        # impact of the most severe mapped ATT&CK tactic
    "history": 0.05,      # prior incidents involving the same entities
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

# Relative impact of an ATT&CK tactic (later kill-chain stages weigh more).
TACTIC_IMPACT = {
    "impact": 1.0, "exfiltration": 1.0, "command-and-control": 0.9, "lateral-movement": 0.85,
    "privilege-escalation": 0.8, "credential-access": 0.7, "persistence": 0.7, "execution": 0.7,
    "defense-evasion": 0.6, "initial-access": 0.6, "collection": 0.6, "discovery": 0.4,
    "reconnaissance": 0.3, "resource-development": 0.3,
}

SEVERITY_CUTOFFS = ((80.0, 4), (60.0, 3), (35.0, 2))  # score >= cutoff -> severity


def severity_from_score(score: float) -> int:
    for cutoff, sev in SEVERITY_CUTOFFS:
        if score >= cutoff:
            return sev
    return 1


def correlation_signal(event_count: int) -> float:
    """0 for a single event, saturating at 20 correlated events."""
    return 0.0 if event_count <= 1 else min(1.0, math.log(event_count) / math.log(20))


def history_signal(prior_incidents: int) -> float:
    return min(1.0, max(0, prior_incidents) / 5)


def severity_signal(max_event_severity: int) -> float:
    return (max(1, min(4, max_event_severity)) - 1) / 3


def tactic_signal(tactics: list[str]) -> float | None:
    vals = [TACTIC_IMPACT.get(t.strip().lower().replace(" ", "-")) for t in tactics]
    vals = [v for v in vals if v is not None]
    return max(vals) if vals else None


@dataclass
class RiskResult:
    score: float
    severity: int
    confidence: float
    breakdown: dict[str, dict] = field(default_factory=dict)


def compute_risk(signals: dict[str, float | None]) -> RiskResult:
    available = {k: min(1.0, max(0.0, float(v))) for k, v in signals.items()
                 if k in WEIGHTS and v is not None}
    total_w = sum(WEIGHTS[k] for k in available)
    breakdown: dict[str, dict] = {}
    for name, w in WEIGHTS.items():
        v = available.get(name)
        breakdown[name] = {"weight": w, "value": None if v is None else round(v, 3),
                           "available": v is not None}
    if total_w == 0:
        return RiskResult(0.0, 1, 0.0, breakdown)
    score = 100.0 * sum(WEIGHTS[k] * v for k, v in available.items()) / total_w
    for name, v in available.items():
        breakdown[name]["points"] = round(100.0 * WEIGHTS[name] * v / total_w, 2)
    score = round(score, 1)
    return RiskResult(score, severity_from_score(score), round(total_w, 2), breakdown)
