"""Log intelligence: group similar events, surface unusual groups, link groups to incidents.

Steps
  1. template   variable parts (IPs, numbers, hex ids, paths, users) are replaced by placeholders so
                "Failed password for root from 1.2.3.4" and "... for admin from 5.6.7.8" become one template
  2. vectorize  TF-IDF (1-2 grams) over the templates
  3. cluster    KMeans; k is chosen by silhouette score (no fixed k, no guessed reduction claims)
  4. flag       a cluster is UNUSUAL when it holds <= 5% of the events, or when it contains
                high-severity events; these are the ones worth an analyst's attention

TF-IDF is a lexical representation, not semantic embeddings. That is a deliberate choice: it is
fast, dependency-free and explainable, and adequate for the templated text security logs contain.
"""
from __future__ import annotations

import re
from collections import Counter

from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.models import Event, Incident

_SUBS = [(re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
         (re.compile(r"\b[0-9a-f]{32,64}\b", re.I), "<hash>"),
         (re.compile(r"(?:/[\w.\-]+){2,}"), "<path>"),
         (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
         (re.compile(r"\b(?:for|user|by)\s+(?:invalid user\s+)?[\w.\-]+", re.I),
          lambda m: m.group(0).split()[0] + " <user>"),
         (re.compile(r"\b\d+\b"), "<n>")]


def to_template(text: str) -> str:
    out = text or ""
    for pat, rep in _SUBS:
        out = pat.sub(rep, out)
    return re.sub(r"\s+", " ", out).strip().lower()


def cluster_texts(texts: list[str], severities: list[int] | None = None, max_k: int = 10, seed: int = 42) -> dict:
    n = len(texts)
    if n < 4:
        return {"status": "too_few_events", "n_events": n, "clusters": []}
    templates = [to_template(t) for t in texts]
    distinct = len(set(templates))
    if distinct < 2:  # every event has the same template: there is nothing to separate
        return {"status": "no_structure", "n_events": n, "clusters": []}
    X = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True).fit_transform(templates)
    best_k, best_score, best_labels = None, -1.0, None
    for k in range(2, min(max_k, n - 1, distinct) + 1):  # never ask for more clusters than distinct templates
        labels = KMeans(n_clusters=k, random_state=seed, n_init=10).fit_predict(X)
        if len(set(labels)) < 2:
            continue
        score = float(silhouette_score(X, labels))
        if score > best_score:
            best_k, best_score, best_labels = k, score, labels
    if best_labels is None:
        return {"status": "no_structure", "n_events": n, "clusters": []}
    sev = severities or [1] * n
    clusters = []
    for c in sorted(set(best_labels)):
        idx = [i for i, lab in enumerate(best_labels) if lab == c]
        common = Counter(templates[i] for i in idx).most_common(1)[0][0]
        share = len(idx) / n
        small, high = share <= 0.05, any(sev[i] >= 3 for i in idx)
        clusters.append({
            "cluster": int(c), "size": len(idx), "share": round(share, 3), "template": common,
            "sample": texts[idx[0]][:200], "indices": idx, "max_severity": max(sev[i] for i in idx),
            "unusual": small or high,
            "reason": " and ".join(r for r in ("small cluster (<=5% of events)" if small else "",
                                               "contains high-severity events" if high else "") if r)})
    clusters.sort(key=lambda c: (not c["unusual"], -c["size"]))
    return {"status": "ok", "n_events": n, "k": best_k, "silhouette": round(best_score, 3),
            "clusters": clusters, "events_per_cluster": round(n / best_k, 1)}


def cluster_recent_events(db: Session, limit: int = 2000) -> dict:
    """Cluster the newest stored events and attach each cluster's incident numbers."""
    rows = list(db.scalars(select(Event).order_by(Event.timestamp.desc()).limit(limit)))
    res = cluster_texts([e.title or e.event_type for e in rows], [e.severity for e in rows])
    incident_ids = {e.incident_id for e in rows if e.incident_id}
    numbers = {i.id: i.number for i in db.scalars(select(Incident).where(Incident.id.in_(incident_ids)))} \
        if incident_ids else {}
    for c in res["clusters"]:
        events = [rows[i] for i in c.pop("indices")]
        c["event_ids"] = [e.id for e in events][:50]
        c["incidents"] = sorted({numbers[e.incident_id] for e in events if e.incident_id in numbers})
        c["unattached_events"] = sum(1 for e in events if not e.incident_id)
    return res
