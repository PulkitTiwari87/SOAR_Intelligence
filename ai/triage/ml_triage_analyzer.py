"""ML triage: probability that a correlated alert set is actionable (malicious).

WHAT THIS MODEL IS (read before trusting it)
--------------------------------------------
No labeled Wazuh incident data ships with this repository, so the model is trained on a
*scenario generator* (`generate_scenarios`): hand-specified attack and benign families with
overlapping feature distributions and 3% label noise. Its metrics therefore measure how well it
recovers those scenario assumptions on a held-out, distribution-shifted sample. They say nothing
about production accuracy. Real analyst outcomes are collected in `analyst_actions` and
`ai.feedback_loop.retrain_from_feedback` retrains on them once enough exist.

The earlier version derived features such as `src_ip_reputation` directly from the label, which
is why it reported 100% accuracy; that leakage is removed here (features never depend on the
label except through the scenario family's overlapping distributions).

Model format: XGBoost native JSON (no pickle). Explanations: exact TreeSHAP values via
`pred_contribs` (log-odds contribution per feature).
"""
from __future__ import annotations

import json
import logging
import sys
import threading
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score

from ai import common

log = logging.getLogger("ai.triage")

NAME = "triage"
SCHEMA_VERSION = "2"
MODEL_FILE = "model.json"
FEATURES = ["rule_level", "failed_logins", "src_ip_is_internal", "ioc_score", "ioc_known",
            "event_count", "is_fim_event", "has_mitre_tag", "off_hours"]
LABEL_NOISE = 0.03
THRESH_MALICIOUS, THRESH_BENIGN = 0.7, 0.3


# ─── scenario generator (synthetic; see module docstring) ───
def _fam(rng, n, *, rule, failed=(0, 0), internal=0.5, ioc_known=0.0, ioc=(0, 0), count=(1, 1),
         fim=0.0, mitre=0.5, off_hours=0.3, label=1):
    f = pd.DataFrame({
        "rule_level": rng.integers(rule[0], rule[1] + 1, n),
        "failed_logins": rng.integers(failed[0], failed[1] + 1, n),
        "src_ip_is_internal": (rng.random(n) < internal).astype(int),
        "event_count": np.round(np.exp(rng.uniform(np.log(count[0]), np.log(count[1] + 1), n))).astype(int),
        "is_fim_event": (rng.random(n) < fim).astype(int),
        "has_mitre_tag": (rng.random(n) < mitre).astype(int),
        "off_hours": (rng.random(n) < off_hours).astype(int),
    })
    known = rng.random(n) < ioc_known
    f["ioc_known"] = known.astype(int)
    f["ioc_score"] = np.where(known, rng.integers(ioc[0], ioc[1] + 1, n), 0)
    f["label"] = label
    return f


# (family builder args, share of that class)
_MAL = [
    (dict(rule=(8, 12), failed=(8, 200), internal=0.05, ioc_known=0.6, ioc=(40, 100), count=(5, 200), mitre=0.8, off_hours=0.6), 0.28),
    (dict(rule=(5, 9), failed=(4, 12), internal=0.05, ioc_known=0.3, ioc=(20, 90), count=(4, 20), mitre=0.6, off_hours=0.55), 0.14),
    (dict(rule=(10, 14), failed=(0, 1), internal=0.5, ioc_known=0.4, ioc=(30, 100), count=(1, 6), mitre=0.9, off_hours=0.5), 0.20),
    (dict(rule=(6, 11), failed=(0, 0), internal=0.05, ioc_known=0.4, ioc=(20, 90), count=(3, 100), mitre=0.7, off_hours=0.5), 0.16),
    (dict(rule=(7, 13), failed=(0, 0), internal=0.7, ioc_known=0.5, ioc=(30, 95), count=(1, 10), fim=1.0, mitre=0.5, off_hours=0.5), 0.12),
    (dict(rule=(7, 12), failed=(0, 0), internal=0.9, ioc_known=0.4, ioc=(30, 90), count=(1, 15), mitre=0.5, off_hours=0.6), 0.10),
]
_BEN = [
    (dict(rule=(3, 8), failed=(1, 6), internal=0.9, ioc_known=0.05, ioc=(0, 20), count=(1, 6), mitre=0.3, off_hours=0.2), 0.25),
    (dict(rule=(5, 10), failed=(0, 2), internal=1.0, ioc_known=0.0, count=(20, 400), mitre=0.4, off_hours=0.3), 0.15),
    (dict(rule=(3, 8), failed=(0, 0), internal=0.95, ioc_known=0.05, ioc=(0, 15), count=(1, 30), fim=1.0, mitre=0.1, off_hours=0.3), 0.20),
    (dict(rule=(3, 8), failed=(0, 5), internal=0.02, ioc_known=0.5, ioc=(5, 60), count=(1, 40), mitre=0.2, off_hours=0.4), 0.22),
    (dict(rule=(1, 5), failed=(0, 0), internal=0.9, ioc_known=0.0, count=(1, 5), mitre=0.05, off_hours=0.25), 0.15),
    (dict(rule=(10, 12), failed=(0, 3), internal=0.8, ioc_known=0.1, ioc=(0, 25), count=(1, 20), mitre=0.3, off_hours=0.3), 0.03),
]


def generate_scenarios(n: int = 20000, seed: int = 42, shift: float = 0.0,
                       malicious_rate: float = 0.35) -> pd.DataFrame:
    """Synthetic labeled alerts. `shift` perturbs the rule levels/counts to create covariate shift."""
    rng = np.random.default_rng(seed)
    parts = []
    for fams, total, label in ((_MAL, int(n * malicious_rate), 1), (_BEN, n - int(n * malicious_rate), 0)):
        for kw, share in fams:
            kw = dict(kw)
            if shift:
                kw["rule"] = (max(1, kw["rule"][0] - round(shift * 3)), min(15, kw["rule"][1] + round(shift * 2)))
                kw["count"] = (kw["count"][0], max(kw["count"][0], int(kw["count"][1] * (1 + shift))))
            parts.append(_fam(rng, max(1, int(total * share)), label=label, **kw))
    df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    flip = rng.random(len(df)) < LABEL_NOISE
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    return df


# ─── training + evaluation ───
def _classifier(seed: int = 42) -> xgb.XGBClassifier:
    return xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.08, subsample=0.8,
                             colsample_bytree=0.8, min_child_weight=3, reg_lambda=2.0,
                             eval_metric="logloss", random_state=seed, n_jobs=1, tree_method="hist")


def _metrics(y, p) -> dict:
    pred = (p >= 0.5).astype(int)
    return {"accuracy": round(accuracy_score(y, pred), 4), "precision": round(precision_score(y, pred), 4),
            "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
            "roc_auc": round(roc_auc_score(y, p), 4), "pr_auc": round(average_precision_score(y, p), 4),
            "brier": round(brier_score_loss(y, p), 4)}


def train_model(seed: int = 42, n_train: int = 20000, n_test: int = 6000) -> dict:
    """Train on scenarios, evaluate on an independently seeded, distribution-shifted hold-out."""
    train = generate_scenarios(n_train, seed=seed)
    test = generate_scenarios(n_test, seed=seed + 1000, shift=0.15)
    X, y = train[FEATURES], train["label"]
    clf = _classifier(seed).fit(X, y)
    p_test = clf.predict_proba(test[FEATURES])[:, 1]
    xgb_metrics = _metrics(test["label"], p_test)

    heuristic = (test["rule_level"] >= 10).astype(int)  # what a level threshold alone would do
    logreg = LogisticRegression(max_iter=2000).fit(X, y)
    p_lr = logreg.predict_proba(test[FEATURES])[:, 1]
    cv = cross_val_score(_classifier(seed), X, y, scoring="roc_auc",
                         cv=StratifiedKFold(5, shuffle=True, random_state=seed))
    evaluation = {
        "kind": "synthetic_holdout", "n_test": n_test, "shift": 0.15,
        "xgboost": xgb_metrics,
        "baseline_rule_level_ge_10": {"accuracy": round(accuracy_score(test["label"], heuristic), 4),
                                      "f1": round(f1_score(test["label"], heuristic), 4)},
        "baseline_logistic_regression": _metrics(test["label"], p_lr),
        "cv_roc_auc_5fold": {"mean": round(float(cv.mean()), 4), "std": round(float(cv.std()), 4)},
        "note": "Measured on generator-produced data only; not a production accuracy estimate.",
    }
    return persist(clf, evaluation, {"source": "synthetic_scenarios", "n_samples": n_train, "label_noise": LABEL_NOISE,
                                     "malicious_rate": 0.35, "real_data": False}, seed)


def persist(clf: xgb.XGBClassifier, evaluation: dict, training_data: dict, seed: int = 42) -> dict:
    """Write the classifier + metadata (version, provenance, evaluation) and drop the inference cache."""
    d = common.model_path(NAME)
    d.mkdir(parents=True, exist_ok=True)
    clf.save_model(str(d / MODEL_FILE))
    meta = common.write_meta(NAME, {
        "name": NAME, "schema_version": SCHEMA_VERSION, "algorithm": "XGBClassifier (TreeSHAP explanations)",
        "features": FEATURES, "seed": seed, "training_data": training_data, "evaluation": evaluation,
        "limitations": ["Synthetic scenarios are the bulk of the training data unless analyst feedback was mixed in.",
                        "ioc_score is 0 with ioc_known=0 when no threat intel result exists.",
                        "Label means 'actionable incident', not merely 'attack traffic'."],
    }, [MODEL_FILE])
    _cache.clear()
    log.info("triage model saved: %s", meta["version"])
    return meta


# ─── inference ───
_cache: dict = {}
_lock = threading.Lock()


def _load() -> tuple[xgb.XGBClassifier, dict]:
    with _lock:
        if "clf" not in _cache:
            if common.read_meta(NAME) is None:
                log.warning("no triage model found; training the default scenario model")
                train_model()
            path = common.verify_file(NAME, MODEL_FILE)
            clf = xgb.XGBClassifier()
            clf.load_model(str(path))
            _cache.update(clf=clf, meta=common.read_meta(NAME))
        return _cache["clf"], _cache["meta"]


def model_info() -> dict:
    meta = common.read_meta(NAME)
    return meta or {"name": NAME, "status": "not_trained"}


def build_features(*, rule_level: int = 0, failed_logins: int = 0, src_ip_is_internal: int = 0,
                   ioc_score: float | None = None, event_count: int = 1, is_fim_event: int = 0,
                   has_mitre_tag: int = 0, off_hours: int = 0) -> dict:
    return {"rule_level": int(rule_level), "failed_logins": int(failed_logins),
            "src_ip_is_internal": int(src_ip_is_internal), "ioc_score": float(ioc_score or 0),
            "ioc_known": int(ioc_score is not None), "event_count": int(event_count),
            "is_fim_event": int(is_fim_event), "has_mitre_tag": int(has_mitre_tag),
            "off_hours": int(off_hours)}


def predict_threat(features: dict) -> dict:
    """Return probability, label, model version and the top feature contributions (log-odds)."""
    started = time.perf_counter()
    missing = [f for f in FEATURES if f not in features]
    if missing:
        raise ValueError(f"missing features: {missing}")
    clf, meta = _load()
    row = pd.DataFrame([{f: float(features[f]) for f in FEATURES}])
    p = float(clf.predict_proba(row)[0, 1])
    contribs = clf.get_booster().predict(xgb.DMatrix(row, feature_names=FEATURES), pred_contribs=True)[0]
    top = sorted(({"feature": f, "value": float(row.iloc[0][f]), "contribution": round(float(c), 4)}
                  for f, c in zip(FEATURES, contribs[:-1])), key=lambda t: -abs(t["contribution"]))[:5]
    label = "malicious" if p >= THRESH_MALICIOUS else "benign" if p <= THRESH_BENIGN else "uncertain"
    return {"probability": round(p, 4), "confidence_score": round(p * 100, 2), "label": label,
            "model_version": meta["version"], "features_used": {f: features[f] for f in FEATURES},
            "top_features": top, "base_value": round(float(contribs[-1]), 4),
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "trained_on": meta["training_data"]["source"]}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        print(json.dumps(train_model()["evaluation"], indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(predict_threat(build_features(rule_level=12, failed_logins=50, ioc_score=85,
                                                       event_count=120, has_mitre_tag=1)), indent=2))
    else:
        print("Usage: python -m ai.triage.ml_triage_analyzer --train | --test")
