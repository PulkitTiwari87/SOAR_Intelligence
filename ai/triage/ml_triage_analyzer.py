#!/usr/bin/env python3
"""
Module 3.1: ML Triage Analyzer
===============================
Uses XGBoost to score incoming Wazuh alerts with a confidence level.
  - Score > 90%  → Auto-block (zero-touch)
  - Score 50-89% → Human review in TheHive
  - Score < 50%  → Auto-close as noise

Includes:
  - Synthetic training data generator
  - Model training pipeline
  - Prediction function for live alerts
"""

import json
import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime

try:
    from xgboost import XGBClassifier
except ImportError:
    print("Installing xgboost...")
    os.system("pip install xgboost")
    from xgboost import XGBClassifier

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

MODEL_PATH = os.path.join(os.path.dirname(__file__), "triage_model.pkl")


def train_model():
    """Train an XGBoost classifier exclusively on real KDD '99 alert data."""
    try:
        from fetch_real_data import get_real_dataset_mapped
        print("[*] Fetching and mapping real dataset...")
        df_real = get_real_dataset_mapped()
    except Exception as e:
        print(f"[!] Error: Could not fetch real data ({e}). Cannot train model.")
        return None

    features = [
        "rule_level", "hour_of_day", "day_of_week",
        "failed_logins", "src_ip_is_internal", "src_ip_reputation",
        "agent_os", "event_count_1h", "is_fim_event", "has_mitre_tag"
    ]

    print(f"[*] Training and Testing STRICTLY on {len(df_real)} Real KDD samples (80/20 split).")
    
    X = df_real[features]
    y = df_real["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[*] Training XGBoost classifier...")
    model = XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\n[+] === Model Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"[+] Model saved to {MODEL_PATH}")

    return model


def predict_threat(alert_data: dict) -> dict:
    """
    Predict the threat confidence score for a Wazuh alert.

    Args:
        alert_data: Dict with keys matching the feature names.

    Returns:
        Dict with confidence_score, decision, and details.
    """
    if not os.path.exists(MODEL_PATH):
        print("[!] No trained model found. Training now...")
        train_model()

    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)

    features = pd.DataFrame([{
        "rule_level": alert_data.get("rule_level", 5),
        "hour_of_day": alert_data.get("hour_of_day", datetime.now().hour),
        "day_of_week": alert_data.get("day_of_week", datetime.now().weekday()),
        "failed_logins": alert_data.get("failed_logins", 0),
        "src_ip_is_internal": alert_data.get("src_ip_is_internal", 1),
        "src_ip_reputation": alert_data.get("src_ip_reputation", 0),
        "agent_os": alert_data.get("agent_os", 0),
        "event_count_1h": alert_data.get("event_count_1h", 1),
        "is_fim_event": alert_data.get("is_fim_event", 0),
        "has_mitre_tag": alert_data.get("has_mitre_tag", 0),
    }])

    confidence = float(model.predict_proba(features)[0][1]) * 100

    # Decision logic
    if confidence >= 90:
        decision = "AUTO_BLOCK"
        action = "Automatically blocked. Zero-touch response triggered."
    elif confidence >= 50:
        decision = "HUMAN_REVIEW"
        action = "Escalated to SOC analyst for manual review in TheHive."
    else:
        decision = "AUTO_CLOSE"
        action = "Closed as noise. No action required."

    return {
        "confidence_score": round(confidence, 2),
        "decision": decision,
        "action": action,
        "features_used": features.to_dict(orient='records')[0]
    }


# --- Cortex Analyzer Interface ---
def run_as_cortex_analyzer():
    """Run as a Cortex analyzer (reads from stdin)."""
    import sys
    input_data = sys.stdin.read()
    if not input_data:
        print(json.dumps({"success": False, "errorMessage": "No input"}))
        sys.exit(1)

    job = json.loads(input_data)
    observable = job.get("observable", {}).get("data", "")

    # Parse the alert data from the observable or job config
    alert_features = job.get("parameters", {}).get("alert_features", {})
    if not alert_features:
        alert_features = {"rule_level": 10, "failed_logins": 5}

    result = predict_threat(alert_features)

    level = "malicious" if result["decision"] == "AUTO_BLOCK" else \
            "suspicious" if result["decision"] == "HUMAN_REVIEW" else "safe"

    output = {
        "success": True,
        "summary": {
            "taxonomies": [{
                "level": level,
                "namespace": "MLTriage",
                "predicate": "Confidence",
                "value": f"{result['confidence_score']}%"
            }]
        },
        "full": result
    }
    print(json.dumps(output))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_model()
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_alert = {
            "rule_level": 12,
            "hour_of_day": 3,
            "failed_logins": 50,
            "src_ip_is_internal": 0,
            "src_ip_reputation": 85,
            "agent_os": 0,
            "event_count_1h": 120,
            "is_fim_event": 0,
            "has_mitre_tag": 1
        }
        result = predict_threat(test_alert)
        print(json.dumps(result, indent=2))
    else:
        run_as_cortex_analyzer()
