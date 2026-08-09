#!/usr/bin/env python3
"""
Module 3.4: Anomaly Detection
===============================
Uses Isolation Forest to learn normal network/system behavior
from Wazuh log exports and flag anomalous deviations.

No labeled data required — this is unsupervised learning.
The model detects "Differences" rather than "Attacks".
"""

import json
import os
import pickle
import sys
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "anomaly_scaler.pkl")


def generate_synthetic_logs(n_normal=1000, n_anomalous=80) -> pd.DataFrame:
    """
    Generate comprehensive synthetic Wazuh log metrics for training.
    Covers 8 attack types + varied normal behavior.
    """
    np.random.seed(42)
    data = []

    # --- NORMAL BEHAVIOR (varied patterns) ---
    for _ in range(n_normal // 3):
        # Business hours (peak)
        data.append({
            "events_per_minute": np.random.normal(18, 6),
            "unique_src_ips": np.random.randint(2, 10),
            "failed_auth_count": np.random.choice([0, 0, 0, 0, 1, 1, 2]),
            "bytes_transferred": np.random.normal(60000, 20000),
            "unique_dst_ports": np.random.randint(1, 6),
            "hour_of_day": np.random.randint(9, 17),
            "new_process_count": np.random.randint(0, 5),
            "dns_query_count": np.random.normal(25, 10),
            "outbound_connections": np.random.randint(2, 12),
            "file_changes": np.random.choice([0, 0, 0, 1, 1, 2]),
        })
    for _ in range(n_normal // 3):
        # Off-hours admin / maintenance
        data.append({
            "events_per_minute": np.random.normal(8, 3),
            "unique_src_ips": np.random.randint(1, 4),
            "failed_auth_count": np.random.choice([0, 0, 0, 1]),
            "bytes_transferred": np.random.normal(30000, 10000),
            "unique_dst_ports": np.random.randint(1, 4),
            "hour_of_day": np.random.choice([*range(0,7), *range(19,24)]),
            "new_process_count": np.random.randint(0, 3),
            "dns_query_count": np.random.normal(10, 5),
            "outbound_connections": np.random.randint(1, 6),
            "file_changes": np.random.choice([0, 0, 1]),
        })
    for _ in range(n_normal // 3):
        # Weekend / low activity
        data.append({
            "events_per_minute": np.random.normal(5, 2),
            "unique_src_ips": np.random.randint(1, 3),
            "failed_auth_count": 0,
            "bytes_transferred": np.random.normal(15000, 5000),
            "unique_dst_ports": np.random.randint(1, 3),
            "hour_of_day": np.random.randint(0, 24),
            "new_process_count": np.random.randint(0, 2),
            "dns_query_count": np.random.normal(5, 3),
            "outbound_connections": np.random.randint(1, 4),
            "file_changes": 0,
        })

    # --- ATTACK PATTERNS ---
    per_type = max(n_anomalous // 8, 10)

    for _ in range(per_type):
        # 1. Brute Force
        data.append({
            "events_per_minute": np.random.normal(200, 60),
            "unique_src_ips": np.random.randint(1, 3),
            "failed_auth_count": np.random.randint(30, 150),
            "bytes_transferred": np.random.normal(5000, 2000),
            "unique_dst_ports": 1,
            "hour_of_day": np.random.randint(0, 6),
            "new_process_count": 0,
            "dns_query_count": np.random.normal(5, 2),
            "outbound_connections": 1,
            "file_changes": 0,
        })
    for _ in range(per_type):
        # 2. Data Exfiltration
        data.append({
            "events_per_minute": np.random.normal(8, 3),
            "unique_src_ips": 1,
            "failed_auth_count": 0,
            "bytes_transferred": np.random.normal(5000000, 1500000),
            "unique_dst_ports": 1,
            "hour_of_day": np.random.randint(1, 5),
            "new_process_count": 1,
            "dns_query_count": np.random.normal(3, 1),
            "outbound_connections": np.random.randint(1, 3),
            "file_changes": np.random.randint(5, 25),
        })
    for _ in range(per_type):
        # 3. C2 Beacon
        data.append({
            "events_per_minute": np.random.normal(12, 3),
            "unique_src_ips": 1,
            "failed_auth_count": 0,
            "bytes_transferred": np.random.normal(500, 150),
            "unique_dst_ports": 1,
            "hour_of_day": np.random.randint(0, 24),
            "new_process_count": 1,
            "dns_query_count": np.random.normal(100, 30),
            "outbound_connections": np.random.randint(50, 120),
            "file_changes": 0,
        })
    for _ in range(per_type):
        # 4. Lateral Movement / Port Scan
        data.append({
            "events_per_minute": np.random.normal(50, 15),
            "unique_src_ips": 1,
            "failed_auth_count": np.random.randint(3, 12),
            "bytes_transferred": np.random.normal(100000, 30000),
            "unique_dst_ports": np.random.randint(10, 40),
            "hour_of_day": np.random.randint(0, 6),
            "new_process_count": np.random.randint(5, 15),
            "dns_query_count": np.random.normal(40, 12),
            "outbound_connections": np.random.randint(15, 50),
            "file_changes": np.random.randint(3, 10),
        })
    for _ in range(per_type):
        # 5. Ransomware (mass file encryption)
        data.append({
            "events_per_minute": np.random.normal(300, 80),
            "unique_src_ips": 1,
            "failed_auth_count": 0,
            "bytes_transferred": np.random.normal(200000, 50000),
            "unique_dst_ports": np.random.randint(1, 3),
            "hour_of_day": np.random.randint(0, 24),
            "new_process_count": np.random.randint(10, 30),
            "dns_query_count": np.random.normal(15, 5),
            "outbound_connections": np.random.randint(2, 8),
            "file_changes": np.random.randint(50, 200),
        })
    for _ in range(per_type):
        # 6. Cryptomining
        data.append({
            "events_per_minute": np.random.normal(25, 5),
            "unique_src_ips": 1,
            "failed_auth_count": 0,
            "bytes_transferred": np.random.normal(80000, 20000),
            "unique_dst_ports": np.random.randint(1, 4),
            "hour_of_day": np.random.randint(0, 24),
            "new_process_count": np.random.randint(2, 5),
            "dns_query_count": np.random.normal(50, 15),
            "outbound_connections": np.random.randint(20, 60),
            "file_changes": 0,
        })
    for _ in range(per_type):
        # 7. DNS Tunneling (exfil over DNS)
        data.append({
            "events_per_minute": np.random.normal(10, 3),
            "unique_src_ips": 1,
            "failed_auth_count": 0,
            "bytes_transferred": np.random.normal(10000, 3000),
            "unique_dst_ports": 1,
            "hour_of_day": np.random.randint(0, 24),
            "new_process_count": 1,
            "dns_query_count": np.random.normal(200, 50),
            "outbound_connections": np.random.randint(1, 5),
            "file_changes": 0,
        })
    for _ in range(per_type):
        # 8. Privilege Escalation
        data.append({
            "events_per_minute": np.random.normal(30, 8),
            "unique_src_ips": 1,
            "failed_auth_count": np.random.randint(2, 8),
            "bytes_transferred": np.random.normal(40000, 10000),
            "unique_dst_ports": np.random.randint(1, 3),
            "hour_of_day": np.random.randint(0, 6),
            "new_process_count": np.random.randint(8, 20),
            "dns_query_count": np.random.normal(15, 5),
            "outbound_connections": np.random.randint(3, 10),
            "file_changes": np.random.randint(5, 15),
        })

    return pd.DataFrame(data)


def train_model():
    """Train the Isolation Forest anomaly detection model."""
    print("[*] Training Isolation Forest model...")
    df = generate_synthetic_logs(n_normal=500, n_anomalous=0)  # Train on NORMAL data only

    scaler = StandardScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # Expect ~5% anomalies
        random_state=42
    )
    model.fit(X)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"[+] Model saved to {MODEL_PATH}")

    # Test with mixed data
    test_df = generate_synthetic_logs(n_normal=50, n_anomalous=10)
    X_test = scaler.transform(test_df)
    predictions = model.predict(X_test)
    anomaly_count = sum(1 for p in predictions if p == -1)
    print(f"[+] Test: {anomaly_count}/{len(predictions)} detected as anomalies")

    return model, scaler


def detect_anomaly(metrics: dict) -> dict:
    """Detect if a set of log metrics is anomalous."""
    if not os.path.exists(MODEL_PATH):
        train_model()

    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)

    features = pd.DataFrame([{
        "events_per_minute": metrics.get("events_per_minute", 15),
        "unique_src_ips": metrics.get("unique_src_ips", 3),
        "failed_auth_count": metrics.get("failed_auth_count", 0),
        "bytes_transferred": metrics.get("bytes_transferred", 50000),
        "unique_dst_ports": metrics.get("unique_dst_ports", 2),
        "hour_of_day": metrics.get("hour_of_day", 12),
        "new_process_count": metrics.get("new_process_count", 1),
        "dns_query_count": metrics.get("dns_query_count", 20),
        "outbound_connections": metrics.get("outbound_connections", 5),
        "file_changes": metrics.get("file_changes", 0),
    }])

    X = scaler.transform(features)
    prediction = model.predict(X)[0]
    anomaly_score = float(-model.score_samples(X)[0])  # Higher = more anomalous
    normalized_score = min(round(anomaly_score * 100, 2), 100)

    is_anomaly = bool(prediction == -1)

    # Identify which features deviated most
    deviations = {}
    feature_names = features.columns.tolist()
    for i, name in enumerate(feature_names):
        z_score = abs(X[0][i])
        if z_score > 2:
            deviations[name] = round(float(z_score), 2)

    if is_anomaly:
        if metrics.get("failed_auth_count", 0) > 20:
            threat_type = "Brute Force Attack"
        elif metrics.get("bytes_transferred", 0) > 1000000:
            threat_type = "Potential Data Exfiltration"
        elif metrics.get("outbound_connections", 0) > 30:
            threat_type = "C2 Beacon / DNS Tunneling"
        elif metrics.get("unique_dst_ports", 0) > 10:
            threat_type = "Lateral Movement / Port Scan"
        else:
            threat_type = "Unknown Anomaly"
    else:
        threat_type = "Normal Behavior"

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": float(normalized_score),
        "threat_type": threat_type,
        "deviating_features": deviations,
        "action": "ALERT — Escalate to SOAR pipeline" if is_anomaly else "NORMAL — No action needed"
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        train_model()
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Simulate a brute force attack
        result = detect_anomaly({
            "events_per_minute": 250,
            "unique_src_ips": 1,
            "failed_auth_count": 80,
            "bytes_transferred": 3000,
            "unique_dst_ports": 1,
            "hour_of_day": 3,
            "new_process_count": 0,
            "dns_query_count": 5,
            "outbound_connections": 1,
            "file_changes": 0,
        })
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python isolation_forest_detector.py --train | --test")
