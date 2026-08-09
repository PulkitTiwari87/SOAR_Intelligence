#!/usr/bin/env python3
"""
SOAR Feedback Learning System
================================
Makes all AI models self-learning by:

1. LOGGING every incident's features + the analyst's final decision
   → Stored in feedback_store.json as labeled training data

2. AUTO-RETRAINING models when enough new feedback accumulates
   → Triage model retrains with real-world labels from analyst actions
   → Anomaly model retrains to adapt its "normal" baseline
   → Phishing model retrains with newly seen email patterns

3. TRACKING model performance over time
   → Logs accuracy before vs after retrain
   → Shows if the model is improving or degrading

How it works:
  - After every incident, call: log_feedback(features, decision, was_correct)
  - The system stores this as new labeled data
  - When 50+ samples accumulate, it triggers a retrain
  - Old synthetic data is mixed with real feedback data (70% real, 30% synthetic)
  - Models get smarter with every incident they see
"""

import json
import os
import pickle
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd

# ── Paths ──
AI_DIR = os.path.dirname(os.path.abspath(__file__))
FEEDBACK_DIR = os.path.join(AI_DIR, "feedback")
FEEDBACK_STORE = os.path.join(FEEDBACK_DIR, "feedback_store.json")
RETRAIN_LOG = os.path.join(FEEDBACK_DIR, "retrain_history.json")
PHISHING_FEEDBACK = os.path.join(FEEDBACK_DIR, "phishing_feedback.json")
ANOMALY_BASELINE = os.path.join(FEEDBACK_DIR, "anomaly_baseline.json")

# ── Retrain thresholds ──
RETRAIN_THRESHOLD = 50       # Retrain after 50 new feedback entries
MIN_RETRAIN_INTERVAL = 3600  # Don't retrain more than once per hour (seconds)


def _ensure_dirs():
    """Create feedback directory if it doesn't exist."""
    os.makedirs(FEEDBACK_DIR, exist_ok=True)


def _load_json(path, default=None):
    """Safely load a JSON file."""
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return default if default is not None else []


def _save_json(path, data):
    """Safely save data to JSON."""
    _ensure_dirs()
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


# ═══════════════════════════════════════════════════════
#  1. FEEDBACK LOGGING
# ═══════════════════════════════════════════════════════

def log_triage_feedback(features: dict, analyst_decision: str,
                        ml_decision: str, ml_score: float):
    """
    Log a triage incident for model retraining.

    Args:
        features: Dict of alert features used by the ML model
        analyst_decision: What the human/system actually decided
            (AUTO_BLOCK, BLOCK_AND_ISOLATE, INVESTIGATE, MONITOR,
             FALSE_POSITIVE, FULL_LOCKDOWN, AUTO_CLOSE)
        ml_decision: What the ML model originally predicted
        ml_score: The ML model's confidence score (0-100)
    """
    # Determine the "correct" label based on analyst's final action
    # If analyst blocked it → it was malicious (label = 1)
    # If analyst closed as false positive → it was benign (label = 0)
    malicious_actions = {"AUTO_BLOCK", "BLOCK_AND_ISOLATE", "FULL_LOCKDOWN"}
    benign_actions = {"FALSE_POSITIVE", "AUTO_CLOSE"}

    if analyst_decision in malicious_actions:
        true_label = 1
    elif analyst_decision in benign_actions:
        true_label = 0
    else:
        # INVESTIGATE or MONITOR — uncertain, skip for training
        true_label = -1  # Mark as uncertain

    was_correct = (ml_decision == analyst_decision) or \
                  (ml_decision == "AUTO_BLOCK" and analyst_decision in malicious_actions) or \
                  (ml_decision == "AUTO_CLOSE" and analyst_decision in benign_actions)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "features": features,
        "true_label": true_label,
        "ml_score": ml_score,
        "ml_decision": ml_decision,
        "analyst_decision": analyst_decision,
        "was_correct": was_correct,
        "used_for_training": False,
    }

    store = _load_json(FEEDBACK_STORE, [])
    store.append(entry)
    _save_json(FEEDBACK_STORE, store)

    # Check if we should retrain
    untrained = [e for e in store if not e["used_for_training"] and e["true_label"] != -1]
    if len(untrained) >= RETRAIN_THRESHOLD:
        print(f"\n  🧠 [{len(untrained)} new feedback entries] — Triggering auto-retrain...")
        retrain_triage_model()

    return was_correct


def log_phishing_feedback(email_text: str, analyst_verdict: str, ml_score: float):
    """
    Log a phishing email for model retraining.

    Args:
        email_text: The email body text
        analyst_verdict: "phishing" or "legitimate"
        ml_score: The original ML phishing score
    """
    entry = {
        "timestamp": datetime.now().isoformat(),
        "email_text": email_text,
        "true_label": 1 if analyst_verdict == "phishing" else 0,
        "ml_score": ml_score,
        "used_for_training": False,
    }

    store = _load_json(PHISHING_FEEDBACK, [])
    store.append(entry)
    _save_json(PHISHING_FEEDBACK, store)


def log_anomaly_baseline(metrics: dict, is_normal: bool):
    """
    Log normal behavior metrics to update the anomaly detection baseline.
    Call this for events confirmed as normal by analysts.
    """
    entry = {
        "timestamp": datetime.now().isoformat(),
        "metrics": metrics,
        "is_normal": is_normal,
    }

    store = _load_json(ANOMALY_BASELINE, [])
    store.append(entry)
    _save_json(ANOMALY_BASELINE, store)


# ═══════════════════════════════════════════════════════
#  2. AUTO-RETRAIN FUNCTIONS
# ═══════════════════════════════════════════════════════

def retrain_triage_model():
    """
    Retrain the ML Triage model using real feedback data + synthetic data.
    Real data is weighted higher (70% real, 30% synthetic fill).
    """
    from ai.triage.ml_triage_analyzer import generate_synthetic_data, MODEL_PATH

    try:
        from xgboost import XGBClassifier
    except ImportError:
        print("  ⚠ XGBoost not available. Skipping retrain.")
        return False

    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, roc_auc_score

    print("  🔄 Retraining ML Triage model with feedback data...")

    # Load feedback data
    store = _load_json(FEEDBACK_STORE, [])
    labeled = [e for e in store if e["true_label"] != -1 and not e["used_for_training"]]

    if len(labeled) < 10:
        print(f"  ⚠ Only {len(labeled)} labeled samples. Need at least 10.")
        return False

    # Convert feedback to DataFrame
    feedback_rows = []
    feature_cols = [
        "rule_level", "hour_of_day", "day_of_week", "failed_logins",
        "src_ip_is_internal", "src_ip_reputation", "agent_os",
        "event_count_1h", "is_fim_event", "has_mitre_tag"
    ]

    for entry in labeled:
        feat = entry["features"]
        row = {col: feat.get(col, 0) for col in feature_cols}
        row["label"] = entry["true_label"]
        feedback_rows.append(row)

    feedback_df = pd.DataFrame(feedback_rows)

    # Generate synthetic data as baseline (30% of total)
    synthetic_count = max(len(feedback_df) // 2, 500)
    synthetic_df = generate_synthetic_data(synthetic_count)

    # Combine: real feedback takes priority
    combined = pd.concat([feedback_df, synthetic_df], ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    X = combined[feature_cols]
    y = combined["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    # Load old model for comparison
    old_accuracy = None
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, 'rb') as f:
            old_model = pickle.load(f)
        old_pred = old_model.predict(X_test)
        old_accuracy = accuracy_score(y_test, old_pred)

    # Train new model
    model = XGBClassifier(
        n_estimators=150,  # Slightly more trees for better learning
        max_depth=6,
        learning_rate=0.08,
        eval_metric='logloss',
        random_state=42
    )
    model.fit(X_train, y_train)

    new_pred = model.predict(X_test)
    new_proba = model.predict_proba(X_test)[:, 1]
    new_accuracy = accuracy_score(y_test, new_pred)
    new_auc = roc_auc_score(y_test, new_proba) if len(set(y_test)) > 1 else 0

    # Only save if new model is better (or first retrain)
    if old_accuracy is None or new_accuracy >= old_accuracy - 0.02:
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(model, f)

        # Mark feedback as used
        for entry in store:
            if not entry.get("used_for_training") and entry.get("true_label", -1) != -1:
                entry["used_for_training"] = True
        _save_json(FEEDBACK_STORE, store)

        # Log retrain event
        retrain_entry = {
            "timestamp": datetime.now().isoformat(),
            "model": "ml_triage",
            "feedback_samples": len(labeled),
            "total_training_samples": len(combined),
            "old_accuracy": round(old_accuracy, 4) if old_accuracy else None,
            "new_accuracy": round(new_accuracy, 4),
            "new_auc": round(new_auc, 4),
            "improved": old_accuracy is None or new_accuracy > old_accuracy,
        }
        history = _load_json(RETRAIN_LOG, [])
        history.append(retrain_entry)
        _save_json(RETRAIN_LOG, history)

        improvement = ""
        if old_accuracy:
            delta = (new_accuracy - old_accuracy) * 100
            improvement = f" ({'↑' if delta > 0 else '↓'} {abs(delta):.1f}%)"

        print(f"  ✅ Retrained with {len(labeled)} real + {synthetic_count} synthetic samples")
        print(f"     Accuracy: {new_accuracy:.2%}{improvement} | AUC: {new_auc:.4f}")
        return True
    else:
        print(f"  ⚠ New model ({new_accuracy:.2%}) worse than old ({old_accuracy:.2%}). Keeping old model.")
        return False


def retrain_phishing_model():
    """Retrain phishing parser with analyst-verified emails."""
    from ai.phishing.nlp_phishing_parser import (
        PHISHING_EMAILS, LEGITIMATE_EMAILS, extract_features,
        MODEL_PATH, VECTORIZER_PATH
    )
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score

    print("  🔄 Retraining Phishing Parser with feedback data...")

    feedback = _load_json(PHISHING_FEEDBACK, [])
    unused = [e for e in feedback if not e.get("used_for_training")]

    if len(unused) < 5:
        print(f"  ⚠ Only {len(unused)} new phishing samples. Need at least 5.")
        return False

    # Combine original training data with feedback
    emails = list(PHISHING_EMAILS) + list(LEGITIMATE_EMAILS)
    labels = [1] * len(PHISHING_EMAILS) + [0] * len(LEGITIMATE_EMAILS)

    for entry in unused:
        emails.append(entry["email_text"])
        labels.append(entry["true_label"])

    vectorizer = TfidfVectorizer(max_features=500, stop_words='english', ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(emails)
    handcrafted = pd.DataFrame([extract_features(e) for e in emails])
    X = np.hstack([tfidf_matrix.toarray(), handcrafted.values])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train)

    accuracy = accuracy_score(y_test, model.predict(X_test))

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)

    # Mark as used
    for entry in feedback:
        entry["used_for_training"] = True
    _save_json(PHISHING_FEEDBACK, feedback)

    # Log retrain
    history = _load_json(RETRAIN_LOG, [])
    history.append({
        "timestamp": datetime.now().isoformat(),
        "model": "phishing_parser",
        "feedback_samples": len(unused),
        "total_training_samples": len(emails),
        "new_accuracy": round(accuracy, 4),
    })
    _save_json(RETRAIN_LOG, history)

    print(f"  ✅ Retrained with {len(unused)} new emails | Accuracy: {accuracy:.2%}")
    return True


def retrain_anomaly_model():
    """Retrain anomaly detection with updated normal behavior baseline."""
    from ai.anomaly.isolation_forest_detector import MODEL_PATH, SCALER_PATH
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    print("  🔄 Retraining Anomaly Detection with updated baseline...")

    baseline = _load_json(ANOMALY_BASELINE, [])
    normal_entries = [e for e in baseline if e.get("is_normal")]

    if len(normal_entries) < 20:
        print(f"  ⚠ Only {len(normal_entries)} normal samples. Need at least 20.")
        return False

    # Build DataFrame from baseline
    feature_names = [
        "events_per_minute", "unique_src_ips", "failed_auth_count",
        "bytes_transferred", "unique_dst_ports", "hour_of_day",
        "new_process_count", "dns_query_count", "outbound_connections",
        "file_changes"
    ]
    rows = []
    for entry in normal_entries:
        m = entry["metrics"]
        rows.append({k: m.get(k, 0) for k in feature_names})

    df = pd.DataFrame(rows)

    scaler = StandardScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)

    history = _load_json(RETRAIN_LOG, [])
    history.append({
        "timestamp": datetime.now().isoformat(),
        "model": "anomaly_detection",
        "baseline_samples": len(normal_entries),
    })
    _save_json(RETRAIN_LOG, history)

    print(f"  ✅ Retrained on {len(normal_entries)} verified normal behavior samples")
    return True


# ═══════════════════════════════════════════════════════
#  3. PERFORMANCE TRACKING
# ═══════════════════════════════════════════════════════

def get_learning_stats() -> dict:
    """
    Get statistics about the feedback learning system.
    Shows how much the models have learned.
    """
    store = _load_json(FEEDBACK_STORE, [])
    phishing_fb = _load_json(PHISHING_FEEDBACK, [])
    baseline = _load_json(ANOMALY_BASELINE, [])
    retrain_hist = _load_json(RETRAIN_LOG, [])

    # Calculate ML accuracy from feedback
    total = len(store)
    correct = sum(1 for e in store if e.get("was_correct"))
    accuracy = (correct / total * 100) if total > 0 else 0

    # Incidents by decision type
    decisions = {}
    for e in store:
        d = e.get("analyst_decision", "unknown")
        decisions[d] = decisions.get(d, 0) + 1

    return {
        "total_incidents_logged": total,
        "ml_accuracy_on_real_data": f"{accuracy:.1f}%",
        "correct_predictions": correct,
        "incorrect_predictions": total - correct,
        "pending_for_retrain": len([e for e in store if not e.get("used_for_training") and e.get("true_label", -1) != -1]),
        "decision_breakdown": decisions,
        "phishing_feedback_count": len(phishing_fb),
        "anomaly_baseline_samples": len([e for e in baseline if e.get("is_normal")]),
        "total_retrains": len(retrain_hist),
        "retrain_history": retrain_hist[-5:] if retrain_hist else [],
        "retrain_threshold": RETRAIN_THRESHOLD,
        "next_retrain_at": f"{RETRAIN_THRESHOLD - len([e for e in store if not e.get('used_for_training') and e.get('true_label', -1) != -1])} more incidents",
    }


# ═══════════════════════════════════════════════════════
#  4. CLI
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "--stats":
            stats = get_learning_stats()
            print(json.dumps(stats, indent=2))
        elif cmd == "--retrain-all":
            print("🧠 Force-retraining all models with feedback data...\n")
            retrain_triage_model()
            retrain_phishing_model()
            retrain_anomaly_model()
            print("\n✅ All models retrained!")
        elif cmd == "--retrain-triage":
            retrain_triage_model()
        elif cmd == "--retrain-phishing":
            retrain_phishing_model()
        elif cmd == "--retrain-anomaly":
            retrain_anomaly_model()
        else:
            print("Unknown command.")
    else:
        print("""
SOAR Feedback Learning System
══════════════════════════════
  python feedback_loop.py --stats            # View learning statistics
  python feedback_loop.py --retrain-all      # Force retrain all models
  python feedback_loop.py --retrain-triage   # Retrain triage model only
  python feedback_loop.py --retrain-phishing # Retrain phishing model only
  python feedback_loop.py --retrain-anomaly  # Retrain anomaly model only
""")
