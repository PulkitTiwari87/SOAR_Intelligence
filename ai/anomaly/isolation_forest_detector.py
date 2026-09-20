"""Anomaly detection: Isolation Forest over per-host behavior metrics.

Threshold: `is_anomaly` is true when the raw isolation score exceeds the 99th percentile of the
scores the model assigns to its own training baseline (so ~1% of baseline windows alarm by
construction). `anomaly_score` is the percentile rank of the raw score within that baseline
(0-100), which is comparable across retrains. There is no `contamination` guess.

The shipped baseline is SYNTHETIC (three normal-behavior profiles). Evaluation figures reported in
metadata come from held-out synthetic normal data and the synthetic attack profiles below, so
they show the mechanism works, not how it performs on your environment. Call `train_model(df)`
with metrics aggregated from real events to build a real baseline.
"""
from __future__ import annotations

import json
import logging
import sys
import threading

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from ai import common

log = logging.getLogger("ai.anomaly")

NAME = "anomaly"
SCHEMA_VERSION = "2"
BUNDLE = "bundle.joblib"
FEATURES = ["events_per_minute", "unique_src_ips", "failed_auth_count", "bytes_transferred",
            "unique_dst_ports", "hour_of_day", "new_process_count", "dns_query_count",
            "outbound_connections", "file_changes"]
DEFAULTS = {"events_per_minute": 15, "unique_src_ips": 3, "failed_auth_count": 0,
            "bytes_transferred": 50000, "unique_dst_ports": 2, "hour_of_day": 12,
            "new_process_count": 1, "dns_query_count": 20, "outbound_connections": 5,
            "file_changes": 0}
THRESHOLD_PERCENTILE = 99.0
# Isolation scores saturate for points far outside the training range (an 80x-baseline spike
# scores about the same as a slight outlier), so a robust rule is combined with the forest:
# any single feature >= Z_LIMIT baseline standard deviations away is anomalous.
Z_LIMIT = 6.0


def _n(rng, mu, sd, n):
    return np.clip(rng.normal(mu, sd, n), 0, None)


def generate_baseline(n: int = 1500, seed: int = 42) -> pd.DataFrame:
    """Synthetic normal behavior: business hours, off-hours maintenance, quiet weekend."""
    rng = np.random.default_rng(seed)
    k = n // 3
    def prof(epm, ips, fa, by, ports, hours, procs, dns, out, files):
        return pd.DataFrame({
            "events_per_minute": _n(rng, *epm, k), "unique_src_ips": rng.integers(*ips, k),
            "failed_auth_count": rng.choice(fa, k), "bytes_transferred": _n(rng, *by, k),
            "unique_dst_ports": rng.integers(*ports, k), "hour_of_day": hours(k),
            "new_process_count": rng.integers(*procs, k), "dns_query_count": _n(rng, *dns, k),
            "outbound_connections": rng.integers(*out, k), "file_changes": rng.choice(files, k)})
    return pd.concat([
        prof((18, 6), (2, 10), [0, 0, 0, 0, 1, 1, 2], (60000, 20000), (1, 6), lambda m: rng.integers(9, 17, m),
             (0, 5), (25, 10), (2, 12), [0, 0, 0, 1, 1, 2]),
        prof((8, 3), (1, 4), [0, 0, 0, 1], (30000, 10000), (1, 4),
             lambda m: rng.choice([*range(0, 7), *range(19, 24)], m), (0, 3), (10, 5), (1, 6), [0, 0, 1]),
        prof((5, 2), (1, 3), [0], (15000, 5000), (1, 3), lambda m: rng.integers(0, 24, m),
             (0, 2), (5, 3), (1, 4), [0]),
    ], ignore_index=True)[FEATURES]


# attack profile -> (feature: (mean, sd) or (low, high) for ints)
_ATTACKS = {
    "brute_force": dict(events_per_minute=(200, 60), failed_auth_count=(30, 150), bytes_transferred=(5000, 2000), hour_of_day=(0, 6)),
    "data_exfiltration": dict(bytes_transferred=(5_000_000, 1_500_000), file_changes=(5, 25), hour_of_day=(1, 5)),
    "c2_beacon": dict(bytes_transferred=(500, 150), dns_query_count=(100, 30), outbound_connections=(50, 120)),
    "port_scan": dict(events_per_minute=(50, 15), unique_dst_ports=(10, 40), outbound_connections=(15, 50), hour_of_day=(0, 6)),
    "ransomware": dict(events_per_minute=(300, 80), new_process_count=(10, 30), file_changes=(50, 200)),
    "cryptomining": dict(events_per_minute=(25, 5), outbound_connections=(20, 60), dns_query_count=(50, 15)),
    "dns_tunneling": dict(dns_query_count=(200, 50), bytes_transferred=(10000, 3000)),
    "privilege_escalation": dict(failed_auth_count=(2, 8), new_process_count=(8, 20), file_changes=(5, 15), hour_of_day=(0, 6)),
}


def generate_attacks(per_type: int = 40, seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    base = generate_baseline(per_type * 3, seed + 1).sample(per_type, random_state=seed, replace=True)
    rows = []
    for kind, over in _ATTACKS.items():
        df = base.copy().reset_index(drop=True)
        for feat, (a, b) in over.items():
            if feat in ("failed_auth_count", "unique_dst_ports", "outbound_connections", "new_process_count",
                        "file_changes", "hour_of_day"):
                df[feat] = rng.integers(int(a), int(b) + 1, per_type)
            else:
                df[feat] = np.clip(rng.normal(a, b, per_type), 0, None)
        df["attack_type"] = kind
        rows.append(df)
    return pd.concat(rows, ignore_index=True)


def _raw_scores(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    return -model.score_samples(X)  # higher = more anomalous


def train_model(baseline: pd.DataFrame | None = None, seed: int = 42, source: str = "synthetic_baseline") -> dict:
    df = (baseline if baseline is not None else generate_baseline(seed=seed))[FEATURES].astype(float)
    scaler = StandardScaler().fit(df)
    model = IsolationForest(n_estimators=200, random_state=seed, n_jobs=1).fit(scaler.transform(df))
    train_scores = np.sort(_raw_scores(model, scaler.transform(df)))
    threshold = float(np.percentile(train_scores, THRESHOLD_PERCENTILE))

    held = generate_baseline(1500, seed + 1000) if baseline is None else df.sample(min(500, len(df)), random_state=seed)
    atk = generate_attacks()
    mean, std = df.mean(), df.std().replace(0, 1)
    def flags(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        s = _raw_scores(model, scaler.transform(frame[FEATURES]))
        extreme = ((frame[FEATURES] - mean).abs() / std).max(axis=1).to_numpy() >= Z_LIMIT
        return s, (s >= threshold) | extreme
    s_norm, f_norm = flags(held)
    s_atk, f_atk = flags(atk)
    per_type = {k: round(float(f_atk[(atk["attack_type"] == k).to_numpy()].mean()), 3) for k in _ATTACKS}
    evaluation = {
        "kind": "synthetic_holdout", "threshold_percentile": THRESHOLD_PERCENTILE, "z_limit": Z_LIMIT,
        "false_positive_rate_on_holdout_baseline": round(float(f_norm.mean()), 4),
        "detection_rate_by_synthetic_attack": per_type,
        "detection_rate_overall": round(float(f_atk.mean()), 3),
        "isolation_forest_only": {
            "false_positive_rate": round(float((s_norm >= threshold).mean()), 4),
            "detection_rate_overall": round(float((s_atk >= threshold).mean()), 3)},
        "roc_auc_baseline_vs_attacks": round(float(roc_auc_score(
            np.r_[np.zeros(len(s_norm)), np.ones(len(s_atk))], np.r_[s_norm, s_atk])), 4),
        "note": "Attack profiles are synthetic and hand-specified; they are not real intrusions.",
    }
    common.save_joblib(NAME, BUNDLE, {
        "model": model, "scaler": scaler, "threshold": threshold, "quantiles": train_scores[::max(1, len(train_scores) // 200)],
        "mean": df.mean().to_dict(), "std": df.std().replace(0, 1).to_dict()})
    meta = common.write_meta(NAME, {
        "name": NAME, "schema_version": SCHEMA_VERSION, "algorithm": "IsolationForest(200) + StandardScaler",
        "features": FEATURES, "seed": seed,
        "training_data": {"source": source, "n_samples": int(len(df)), "real_data": source != "synthetic_baseline"},
        "threshold": {"raw_score": round(threshold, 4), "rule": f"{THRESHOLD_PERCENTILE}th percentile of training-baseline scores"},
        "evaluation": evaluation,
        "limitations": ["Default baseline is synthetic; retrain on observed events for real use.",
                        "threat_type is a rule-of-thumb hint, not a classifier output."],
    }, [BUNDLE])
    _cache.clear()
    return meta


_cache: dict = {}
_lock = threading.Lock()


def _load() -> tuple[dict, dict]:
    with _lock:
        if "bundle" not in _cache:
            if common.read_meta(NAME) is None:
                log.warning("no anomaly model found; training the default synthetic baseline")
                train_model()
            _cache.update(bundle=common.load_joblib(NAME, BUNDLE), meta=common.read_meta(NAME))
        return _cache["bundle"], _cache["meta"]


def model_info() -> dict:
    return common.read_meta(NAME) or {"name": NAME, "status": "not_trained"}


def _pattern_hint(m: dict) -> str:
    if m["failed_auth_count"] > 20:
        return "Brute force pattern"
    if m["bytes_transferred"] > 1_000_000:
        return "Possible data exfiltration pattern"
    if m["outbound_connections"] > 30 or m["dns_query_count"] > 80:
        return "C2 beacon / DNS tunneling pattern"
    if m["unique_dst_ports"] > 10:
        return "Port scan / lateral movement pattern"
    if m["file_changes"] > 40:
        return "Mass file modification pattern"
    return "Unclassified anomaly"


def detect_anomaly(metrics: dict) -> dict:
    bundle, meta = _load()
    provided = [f for f in FEATURES if metrics.get(f) is not None]
    row = {f: float(metrics.get(f) if metrics.get(f) is not None else DEFAULTS[f]) for f in FEATURES}
    X = bundle["scaler"].transform(pd.DataFrame([row])[FEATURES])
    raw = float(_raw_scores(bundle["model"], X)[0])
    pct = float(np.searchsorted(bundle["quantiles"], raw) / len(bundle["quantiles"]) * 100)
    z = {f: round((row[f] - bundle["mean"][f]) / bundle["std"][f], 2) for f in FEATURES}
    # Only features the caller actually supplied can trigger the extreme-deviation rule.
    extreme = any(abs(z[f]) >= Z_LIMIT for f in provided)
    is_anom = raw >= bundle["threshold"] or extreme
    deviating = dict(sorted(((f, v) for f, v in z.items() if abs(v) >= 3 and f in provided),
                            key=lambda kv: -abs(kv[1]))[:5])
    return {"is_anomaly": bool(is_anom), "anomaly_score": round(min(pct, 100.0), 1),
            "trigger": "extreme_deviation" if extreme else "isolation_forest" if is_anom else None,
            "raw_score": round(raw, 4), "threshold": round(bundle["threshold"], 4),
            "threat_type": _pattern_hint(row) if is_anom else "Normal behavior",
            "deviating_features": deviating, "features_provided": provided,
            "features_defaulted": [f for f in FEATURES if f not in provided],
            "model_version": meta["version"], "trained_on": meta["training_data"]["source"]}


def baseline_deviation(current: dict, history: list[dict]) -> dict:
    """Per-feature z-scores of `current` against a host's own history (needs >= 10 samples)."""
    if len(history) < 10:
        return {}
    h = pd.DataFrame(history)
    out = {}
    for f in FEATURES:
        if f in h and f in current and current[f] is not None:
            sd = float(h[f].std()) or 1.0
            out[f] = round((float(current[f]) - float(h[f].mean())) / sd, 2)
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        print(json.dumps(train_model()["evaluation"], indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(detect_anomaly({"events_per_minute": 250, "failed_auth_count": 80,
                                         "bytes_transferred": 3000, "hour_of_day": 3}), indent=2))
    else:
        print("Usage: python -m ai.anomaly.isolation_forest_detector --train | --test")
