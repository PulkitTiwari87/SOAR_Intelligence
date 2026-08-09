#!/usr/bin/env python3
"""
Module 3.5: Semantic Log Clustering
=====================================
Converts raw Wazuh alerts into TF-IDF vector embeddings and
uses K-Means clustering to group related alerts into single cases.

Result: 100 related alerts → 1 consolidated TheHive case.
Reduces analyst workload by up to 90%.
"""

import json
import os
import sys
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from collections import defaultdict


def generate_sample_alerts() -> list:
    """Generate sample Wazuh alerts that should be clustered together."""
    return [
        # Cluster 1: SSH Brute Force (should group together)
        {"id": 1, "description": "Failed SSH login from 192.168.1.50 for user root", "rule_id": "5716", "src_ip": "192.168.1.50"},
        {"id": 2, "description": "Multiple SSH authentication failures from 192.168.1.50", "rule_id": "100001", "src_ip": "192.168.1.50"},
        {"id": 3, "description": "SSH login failure from 192.168.1.50 for user admin", "rule_id": "5716", "src_ip": "192.168.1.50"},
        {"id": 4, "description": "SSH brute force attack detected from 192.168.1.50", "rule_id": "5720", "src_ip": "192.168.1.50"},
        {"id": 5, "description": "Failed password for root from 192.168.1.50 port 22", "rule_id": "5716", "src_ip": "192.168.1.50"},
        {"id": 6, "description": "PAM authentication failure from 192.168.1.50", "rule_id": "5503", "src_ip": "192.168.1.50"},
        # Cluster 2: File Integrity Monitoring (should group together)
        {"id": 7, "description": "File /etc/passwd was modified", "rule_id": "550", "src_ip": ""},
        {"id": 8, "description": "Integrity checksum changed for /etc/shadow", "rule_id": "550", "src_ip": ""},
        {"id": 9, "description": "File modification detected in /etc/sudoers", "rule_id": "550", "src_ip": ""},
        {"id": 10, "description": "Critical system file /etc/passwd has been altered", "rule_id": "554", "src_ip": ""},
        # Cluster 3: Malware / Suspicious Process (should group together)
        {"id": 11, "description": "Suspicious process execution: nc -e /bin/bash", "rule_id": "100002", "src_ip": ""},
        {"id": 12, "description": "Reverse shell detected using netcat", "rule_id": "100002", "src_ip": ""},
        {"id": 13, "description": "Suspicious network utility usage: netcat listener", "rule_id": "100002", "src_ip": ""},
        {"id": 14, "description": "Possible reverse shell: bash connected to remote IP", "rule_id": "100002", "src_ip": ""},
        # Cluster 4: Web Attack (should group together)
        {"id": 15, "description": "SQL injection attempt detected in web application", "rule_id": "31103", "src_ip": "10.0.0.5"},
        {"id": 16, "description": "Cross-site scripting XSS attack attempt blocked", "rule_id": "31104", "src_ip": "10.0.0.5"},
        {"id": 17, "description": "Web application attack: SQL injection from 10.0.0.5", "rule_id": "31103", "src_ip": "10.0.0.5"},
        {"id": 18, "description": "Directory traversal attempt in HTTP request", "rule_id": "31105", "src_ip": "10.0.0.5"},
    ]


def cluster_alerts(alerts: list, n_clusters: int = None, max_clusters: int = 10) -> dict:
    """
    Cluster a list of Wazuh alerts by semantic similarity.

    Args:
        alerts: List of dicts with at least an 'id' and 'description' field.
        n_clusters: Fixed number of clusters (auto-detect if None).
        max_clusters: Maximum clusters when auto-detecting.

    Returns:
        Dict with cluster assignments and summaries.
    """
    if len(alerts) < 2:
        return {"clusters": {0: alerts}, "total_clusters": 1}

    descriptions = [a["description"] for a in alerts]

    # Vectorize alert descriptions
    vectorizer = TfidfVectorizer(
        max_features=300,
        stop_words='english',
        ngram_range=(1, 2)
    )
    tfidf_matrix = vectorizer.fit_transform(descriptions)

    # Auto-detect optimal cluster count using simple heuristic
    if n_clusters is None:
        n_clusters = min(max(2, len(alerts) // 4), max_clusters)

    # K-Means clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = kmeans.fit_predict(tfidf_matrix)

    # Group alerts by cluster
    clusters = defaultdict(list)
    for i, label in enumerate(labels):
        alerts[i]["cluster_id"] = int(label)
        clusters[int(label)].append(alerts[i])

    # Generate cluster summaries
    cluster_summaries = {}
    for cluster_id, cluster_alerts_list in clusters.items():
        alert_ids = [a["id"] for a in cluster_alerts_list]
        descriptions_in_cluster = [a["description"] for a in cluster_alerts_list]

        # Find most representative description (closest to centroid)
        cluster_indices = [i for i, l in enumerate(labels) if l == cluster_id]
        centroid = kmeans.cluster_centers_[cluster_id]
        distances = [np.linalg.norm(tfidf_matrix[i].toarray() - centroid) for i in cluster_indices]
        representative_idx = cluster_indices[np.argmin(distances)]

        cluster_summaries[cluster_id] = {
            "representative_alert": descriptions[representative_idx],
            "alert_count": len(cluster_alerts_list),
            "alert_ids": alert_ids,
            "sample_descriptions": descriptions_in_cluster[:3],
            "suggested_title": f"Cluster #{cluster_id}: {descriptions[representative_idx][:60]}..."
        }

    return {
        "total_alerts": len(alerts),
        "total_clusters": n_clusters,
        "reduction_ratio": f"{round((1 - n_clusters / len(alerts)) * 100, 1)}%",
        "clusters": cluster_summaries
    }


def create_consolidated_cases(alerts: list, thehive_url: str = None, api_key: str = None) -> list:
    """
    Cluster alerts and create consolidated TheHive cases.
    Returns the cluster result for dashboard display.
    """
    result = cluster_alerts(alerts)

    if thehive_url and api_key:
        import requests
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        for cluster_id, summary in result["clusters"].items():
            case_payload = {
                "title": summary["suggested_title"],
                "description": (
                    f"**Consolidated Case** — {summary['alert_count']} related alerts grouped by AI.\n\n"
                    f"**Representative Alert:** {summary['representative_alert']}\n\n"
                    f"**Alert IDs:** {summary['alert_ids']}"
                ),
                "severity": 2,
                "tags": ["ai-clustered", f"cluster:{cluster_id}", f"count:{summary['alert_count']}"],
                "tlp": 2,
                "pap": 2,
            }
            try:
                resp = requests.post(f"{thehive_url}/api/v1/case", headers=headers, json=case_payload, verify=False)
                if resp.status_code in (200, 201):
                    print(f"[+] Created case for cluster {cluster_id}")
            except Exception as e:
                print(f"[!] Failed to create case: {e}")

    return result


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        alerts = generate_sample_alerts()
        result = cluster_alerts(alerts, n_clusters=4)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python log_clusterer.py --test")
