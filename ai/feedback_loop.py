"""Analyst feedback -> labeled data -> guarded retraining of the triage model.

Labels are taken only from explicit human signals stored in the database:
  0  the analyst marked the incident false_positive
  1  a human approved a remediation action (block_ip / isolate_host / disable_account)
Investigating, monitoring or resolving without either signal is NOT used as a label.

Retraining mixes the labeled rows (weighted x5) into the synthetic scenario data, then PROMOTES the
candidate only if, on a held-out slice of the real labels, its ROC-AUC beats the current model's, and
its synthetic hold-out ROC-AUC has not dropped by more than 0.02. Otherwise the current model stays.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai.triage import ml_triage_analyzer as triage
from soar.models import AnalystAction, Approval, ModelPrediction

MIN_LABELED, MIN_PER_CLASS = 50, 10
REMEDIATION = ("block_ip", "isolate_host", "disable_account")


def labeled_rows(db: Session) -> list[dict]:
    """One row per incident that has both a triage prediction and an explicit label."""
    fp = {a.incident_id for a in db.scalars(select(AnalystAction).where(AnalystAction.action == "false_positive"))}
    tp = {a.incident_id for a in db.scalars(select(Approval).where(Approval.status == "approved",
                                                                   Approval.action.in_(REMEDIATION)))}
    rows: dict[str, dict] = {}
    for p in db.scalars(select(ModelPrediction).where(ModelPrediction.kind == "triage")
                        .order_by(ModelPrediction.created_at)):
        label = 0 if p.incident_id in fp else 1 if p.incident_id in tp else None
        feats = (p.result or {}).get("features_used")
        if label is not None and feats and all(f in feats for f in triage.FEATURES):
            rows[p.incident_id] = {**{f: feats[f] for f in triage.FEATURES}, "label": label,
                                   "model_probability": p.confidence, "incident_id": p.incident_id}
    return list(rows.values())  # latest prediction per incident


def feedback_stats(db: Session) -> dict:
    rows = labeled_rows(db)
    n1 = sum(r["label"] for r in rows)
    agree = sum(1 for r in rows if ((r["model_probability"] or 0) >= 0.5) == bool(r["label"]))
    return {"labeled_incidents": len(rows), "malicious_labels": n1, "benign_labels": len(rows) - n1,
            "model_agreement_with_analysts": round(agree / len(rows), 3) if rows else None,
            "retrain_ready": len(rows) >= MIN_LABELED and min(n1, len(rows) - n1) >= MIN_PER_CLASS,
            "requirement": f">= {MIN_LABELED} labeled incidents with >= {MIN_PER_CLASS} of each class"}


def retrain_from_feedback(db: Session, seed: int = 42) -> dict:
    rows = labeled_rows(db)
    n1 = sum(r["label"] for r in rows)
    if len(rows) < MIN_LABELED or min(n1, len(rows) - n1) < MIN_PER_CLASS:
        return {"status": "insufficient_feedback", **feedback_stats(db)}
    real = pd.DataFrame(rows)[triage.FEATURES + ["label"]]
    r_train, r_test = train_test_split(real, test_size=0.3, random_state=seed, stratify=real["label"])
    synth = triage.generate_scenarios(10000, seed=seed)
    synth_test = triage.generate_scenarios(4000, seed=seed + 1000, shift=0.15)
    train = pd.concat([synth, r_train], ignore_index=True)
    weights = np.r_[np.ones(len(synth)), np.full(len(r_train), 5.0)]
    cand = triage._classifier(seed).fit(train[triage.FEATURES], train["label"], sample_weight=weights)
    cur, _ = triage._load()

    def auc(model, df: pd.DataFrame) -> float:
        return float(roc_auc_score(df["label"], model.predict_proba(df[triage.FEATURES])[:, 1]))

    cand_real, cur_real = auc(cand, r_test), auc(cur, r_test)
    cand_syn, cur_syn = auc(cand, synth_test), auc(cur, synth_test)
    promote = cand_real > cur_real and cand_syn >= cur_syn - 0.02
    result = {"status": "promoted" if promote else "kept_current", "labeled_incidents": len(rows),
              "real_holdout_auc": {"current": round(cur_real, 4), "candidate": round(cand_real, 4)},
              "synthetic_holdout_auc": {"current": round(cur_syn, 4), "candidate": round(cand_syn, 4)}}
    if promote:
        meta = triage.persist(cand, {"kind": "mixed_holdout", **result},
                              {"source": "synthetic_scenarios+analyst_feedback", "n_samples": int(len(train)),
                               "n_analyst_labels": int(len(r_train)), "real_data": True}, seed)
        result["model_version"] = meta["version"]
    return result
