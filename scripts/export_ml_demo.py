"""Export the trained models' real metadata and real sample predictions for the static ML demo page.

The Vercel deployment is a static frontend, so it cannot run the Python models. This script runs them
locally and writes what they actually output to dashboard/frontend/public/ml-data/. Nothing here is typed
in by hand except the *inputs* to the samples; every number shown on the page comes from the models.

    python -m scripts.export_ml_demo        (needs trained models: python -m soar.cli train-models)
"""
from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from ai import common
from ai.anomaly import isolation_forest_detector as anomaly
from ai.phishing import nlp_phishing_parser as phishing
from ai.triage import ml_triage_analyzer as triage

OUT = Path(__file__).resolve().parents[1] / "dashboard" / "frontend" / "public" / "ml-data"

TRIAGE_SAMPLES = [
    ("SSH brute force from a known-bad external IP", dict(rule_level=10, failed_logins=120, src_ip_is_internal=0,
     ioc_score=85, event_count=150, is_fim_event=0, has_mitre_tag=1, off_hours=1)),
    ("Internal backup job, high volume, business hours", dict(rule_level=6, failed_logins=0, src_ip_is_internal=1,
     ioc_score=None, event_count=300, is_fim_event=0, has_mitre_tag=0, off_hours=0)),
    ("File integrity change on an internal host", dict(rule_level=7, failed_logins=0, src_ip_is_internal=1,
     ioc_score=None, event_count=2, is_fim_event=1, has_mitre_tag=0, off_hours=0)),
    ("Internet background scanner, low IOC score", dict(rule_level=5, failed_logins=2, src_ip_is_internal=0,
     ioc_score=30, event_count=10, is_fim_event=0, has_mitre_tag=0, off_hours=1)),
    ("Low-volume internal alert with MITRE tag, off-hours", dict(rule_level=12, failed_logins=0, src_ip_is_internal=1,
     ioc_score=60, event_count=3, is_fim_event=0, has_mitre_tag=1, off_hours=1)),
]

PHISHING_SAMPLES = [
    ("Credential lure with look-alike link and failed SPF", {
        "subject": "Action required: verify your account", "from": "Security Team <support@paypa1-secure.top>",
        "reply_to": "helpdesk@mail-verify.xyz",
        "body": "Your account has been suspended. Verify your password immediately at "
                "http://paypa1-secure.top/login or your account will be closed within 24 hours.",
        "headers": {"Authentication-Results": "spf=fail dkim=fail dmarc=fail"}}),
    ("Routine internal notice", {
        "subject": "Team lunch on Friday", "from": "Alex <alex@example.com>", "reply_to": None,
        "body": "Hi all, we are getting lunch on Friday at noon. Let me know if you have dietary requirements.",
        "headers": {}}),
    ("Payment-change request with no links", {
        "subject": "Urgent wire transfer", "from": "CEO <ceo@example.com>", "reply_to": None,
        "body": "I need you to process an urgent wire transfer today. Keep this confidential and reply "
                "with the amount you can send. I am in a meeting and cannot take calls.",
        "headers": {}}),
]

ANOMALY_SAMPLES = [
    ("Typical business-hours host", dict(events_per_minute=15, unique_src_ips=3, failed_auth_count=0,
     bytes_transferred=50000, unique_dst_ports=2, hour_of_day=11, new_process_count=1,
     dns_query_count=20, outbound_connections=5, file_changes=0)),
    ("Brute-force profile", dict(events_per_minute=400, unique_src_ips=2, failed_auth_count=300,
     bytes_transferred=60000, unique_dst_ports=2, hour_of_day=3, new_process_count=1,
     dns_query_count=20, outbound_connections=5, file_changes=0)),
    ("Large outbound transfer at night", dict(events_per_minute=30, unique_src_ips=3, failed_auth_count=0,
     bytes_transferred=900_000_000, unique_dst_ports=3, hour_of_day=2, new_process_count=2,
     dns_query_count=25, outbound_connections=60, file_changes=0)),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    metas = {n: common.read_meta(n) for n in ("triage", "anomaly", "phishing")}
    if not all(metas.values()):
        raise SystemExit("models missing; run: python -m soar.cli train-models")

    triage_out = []
    for title, kw in TRIAGE_SAMPLES:
        feats = triage.build_features(**kw)
        out = triage.predict_threat(feats)
        out.pop("latency_ms")  # machine-dependent, not meaningful in a static export
        triage_out.append({"title": title, "input": feats, "output": out})

    phishing_out = [{"title": t, "input": e, "output": phishing.analyze_email(e)} for t, e in PHISHING_SAMPLES]
    anomaly_out = [{"title": t, "input": m, "output": anomaly.detect_anomaly(m)} for t, m in ANOMALY_SAMPLES]

    data = {"generated_at": datetime.now(UTC).isoformat(), "models": metas,
            "samples": {"triage": triage_out, "phishing": phishing_out, "anomaly": anomaly_out}}
    (OUT / "demo-data.json").write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    # The real XGBoost artifact (native JSON, no pickle) so the browser can run genuine inference.
    shutil.copyfile(common.verify_file("triage", triage.MODEL_FILE), OUT / "triage_model.json")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
