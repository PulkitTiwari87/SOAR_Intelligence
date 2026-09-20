"""ML modules: triage, anomaly, phishing, blast radius, model integrity, feedback loop."""
import json

import pytest
from sklearn.metrics import roc_auc_score

from ai import common, feedback_loop
from ai.anomaly import isolation_forest_detector as anomaly
from ai.blast_radius import blast_radius_predictor as blast
from ai.phishing import nlp_phishing_parser as phishing
from ai.triage import ml_triage_analyzer as triage
from soar.cli import DEMO_ASSETS, DEMO_LINKS
from soar.models import AnalystAction, Asset, AssetLink
from soar.pipeline.ingest import ingest
from soar.simulate import brute_force


# ─────────── triage ───────────
MAL = triage.build_features(rule_level=12, failed_logins=80, ioc_score=90, event_count=60, has_mitre_tag=1, off_hours=1)
BEN = triage.build_features(rule_level=4, failed_logins=1, src_ip_is_internal=1, event_count=2)


def test_triage_separates_obvious_cases_and_explains_itself():
    m, b = triage.predict_threat(MAL), triage.predict_threat(BEN)
    assert m["probability"] > 0.8 and m["label"] == "malicious"
    assert b["probability"] < 0.3 and b["label"] == "benign"
    assert len(m["top_features"]) == 5
    contribs = [abs(t["contribution"]) for t in m["top_features"]]
    assert contribs == sorted(contribs, reverse=True)
    assert m["model_version"] and m["trained_on"] == "synthetic_scenarios"


def test_triage_rejects_missing_features():
    with pytest.raises(ValueError, match="missing features"):
        triage.predict_threat({"rule_level": 5})


def test_no_single_feature_leaks_the_label():
    """The old dataset derived features from the label (=> 100% accuracy). No feature alone may separate classes."""
    df = triage.generate_scenarios(8000, seed=1)
    assert set(df["label"]) == {0, 1}
    for f in triage.FEATURES:
        auc = roc_auc_score(df["label"], df[f])
        assert 0.1 < auc < 0.93, f"{f} alone gives AUC {auc:.3f}: looks label-derived"


def test_recorded_evaluation_is_real_not_perfect():
    meta = triage.model_info()
    ev = meta["evaluation"]
    assert ev["kind"] == "synthetic_holdout" and meta["training_data"]["real_data"] is False
    assert 0.8 < ev["xgboost"]["accuracy"] < 0.99 and ev["xgboost"]["roc_auc"] < 0.995
    assert ev["xgboost"]["roc_auc"] > ev["baseline_rule_level_ge_10"]["accuracy"] - 0.3
    assert "limitations" in meta and meta["files"]["model.json"]


def test_training_is_reproducible():
    v1 = triage.train_model(seed=7, n_train=3000, n_test=1000)["version"]
    v2 = triage.train_model(seed=7, n_train=3000, n_test=1000)["version"]
    assert v1 == v2
    triage.train_model()  # restore the standard model for other tests


def test_tampered_model_file_is_refused():
    triage.predict_threat(BEN)  # ensure trained
    path = common.model_path("triage") / "model.json"
    original = path.read_bytes()
    try:
        path.write_bytes(original + b" ")
        triage._cache.clear()
        with pytest.raises(common.ModelIntegrityError):
            triage.predict_threat(BEN)
    finally:
        path.write_bytes(original)
        triage._cache.clear()


# ─────────── anomaly ───────────
def test_extreme_brute_force_is_flagged_with_reason():
    r = anomaly.detect_anomaly({"events_per_minute": 250, "failed_auth_count": 80, "hour_of_day": 3})
    assert r["is_anomaly"] and r["trigger"] == "extreme_deviation"
    assert "failed_auth_count" in r["deviating_features"] and r["threat_type"] == "Brute force pattern"
    assert "unique_dst_ports" in r["features_defaulted"]  # defaults are reported, not hidden


def test_normal_behavior_is_not_flagged():
    r = anomaly.detect_anomaly({"events_per_minute": 18, "failed_auth_count": 0, "bytes_transferred": 60000,
                                "unique_dst_ports": 3, "hour_of_day": 11})
    assert not r["is_anomaly"] and r["threat_type"] == "Normal behavior"


def test_anomaly_evaluation_is_recorded_with_fpr_near_target():
    ev = anomaly.model_info()["evaluation"]
    assert ev["false_positive_rate_on_holdout_baseline"] < 0.03
    assert ev["isolation_forest_only"]["detection_rate_overall"] < ev["detection_rate_overall"]
    assert "synthetic" in ev["note"]


def test_baseline_deviation_needs_history():
    assert anomaly.baseline_deviation({"events_per_minute": 50}, [{"events_per_minute": 10}] * 3) == {}
    hist = [{"events_per_minute": 10 + (i % 3)} for i in range(20)]
    assert anomaly.baseline_deviation({"events_per_minute": 50}, hist)["events_per_minute"] > 10


# ─────────── phishing ───────────
def test_phishing_link_email_is_flagged_with_indicators():
    r = phishing.analyze_email({"subject": "Action required", "from": "PayPal <help@paypa1-secure-login.top>",
                                "reply_to": "x@evil.test",
                                "body": "Your account is limited. Verify: http://paypa1-secure-login.top/verify"})
    names = {i["name"] for i in r["indicators"]}
    assert r["verdict"] == "phishing" and {"url:risky_tld", "url:brand_in_domain", "reply_to_mismatch"} <= names
    assert "paypa1-secure-login.top" in r["domains"]
    assert {"type": "domain", "value": "paypa1-secure-login.top"} in r["iocs"]
    assert r["top_terms"] and r["evidence_sha256"]


def test_legitimate_email_with_link_is_not_flagged():
    r = phishing.analyze_email({"subject": "Build passed", "from": "CI <ci@acme.com>",
                                "body": "Build #1834 passed. Details: https://ci.acme.com/builds/1834"})
    assert r["verdict"] == "legitimate" and r["phishing_score"] < 30


def test_bec_text_without_links_is_escalated_for_review():
    r = phishing.analyze_email("Hi, I'm the new CFO. Please process this urgent wire transfer of $40,000 today. Keep this confidential.")
    assert r["verdict"] in ("suspicious", "phishing") and r["urls"] == []


@pytest.mark.parametrize("url,flag", [
    ("http://185.234.72.19/login", "ip_host"), ("https://bit.ly/3xYz", "shortener"),
    ("https://xn--pypal-4ve.com/", "punycode"), ("https://login.account.example.co.uk.evil.com.x.y", "many_subdomains"),
    ("https://paypai.com/signin", "lookalike_domain"), ("https://paypa1.com/signin", "brand_in_domain"), ("https://evil.test@good.com/", "at_symbol"),
    ("https://free-gift.top/", "risky_tld")])
def test_url_indicators(url, flag):
    assert flag in phishing.analyze_url(url)["flags"]


def test_official_domains_are_not_flagged_as_brand_abuse():
    assert phishing.analyze_url("https://www.paypal.com/signin")["flags"] == []
    assert phishing.analyze_url("https://login.microsoftonline.com/")["flags"] == []


def test_link_text_mismatch_in_html():
    html = '<a href="http://evil.test/x">https://www.paypal.com/verify</a>'
    urls = phishing.extract_urls(html)
    assert phishing.analyze_url(urls[0]["url"], urls[0]["text"])["flags"].count("link_text_mismatch") == 1


def test_evidence_hash_changes_with_input():
    a = phishing.analyze_email("hello there")["evidence_sha256"]
    assert a == phishing.analyze_email("hello there")["evidence_sha256"] != phishing.analyze_email("hello there!")["evidence_sha256"]


def test_phishing_corpus_has_links_on_both_sides():
    from ai.phishing.corpus import LEGITIMATE_EMAILS, PHISHING_EMAILS
    assert any("http" in t for t in LEGITIMATE_EMAILS) and any("http" in t for t in PHISHING_EMAILS)
    assert phishing.model_info()["evaluation"]["kind"] == "5fold_cross_validation"


# ─────────── blast radius ───────────
@pytest.fixture
def topology(db):
    by = {}
    for host, ip, os_, role, crit in DEMO_ASSETS:
        by[host] = Asset(hostname=host, ip=ip, os=os_, role=role, criticality=crit)
        db.add(by[host])
    db.flush()
    for s, d, proto, port in DEMO_LINKS:
        db.add(AssetLink(src_id=by[s].id, dst_id=by[d].id, protocol=proto, port=port))
    db.commit()


def test_blast_radius_without_inventory_says_so(db):
    r = blast.predict_blast_radius("x", blast.build_graph(db))
    assert r["status"] == "no_asset_inventory"


def test_blast_radius_paths_and_ranking(db, topology):
    g = blast.build_graph(db)
    r = blast.predict_blast_radius("kali-vm-01", g, db=db)
    assert r["status"] == "ok" and r["total_at_risk"] >= 5
    hosts = {h["hostname"]: h for h in r["at_risk_hosts"]}
    assert hosts["file-server-01"]["hop_distance"] == 1 and hosts["file-server-01"]["access"] == "smb/445"
    assert hosts["dc-01"]["hop_distance"] == 2 and hosts["dc-01"]["attack_path"].startswith("kali-vm-01 → file-server-01")
    assert hosts["db-server-01"]["hop_distance"] == 2 and "web-server-01" in hosts["db-server-01"]["attack_path"]
    scores = [h["risk_score"] for h in r["at_risk_hosts"]]
    assert scores == sorted(scores, reverse=True)
    assert {h["hostname"] for h in r["recommendations"]["review_first"]} == {"web-server-01", "file-server-01"}
    assert blast.predict_blast_radius("ghost", g)["status"] == "unknown_host"


def test_blast_radius_respects_max_hops(db, topology):
    r = blast.predict_blast_radius("kali-vm-01", blast.build_graph(db), max_hops=1)
    assert all(h["hop_distance"] == 1 for h in r["at_risk_hosts"])


def test_blast_radius_feeds_incident_analysis(db, topology):
    inc = None
    for src, p in brute_force(host="kali-vm-01"):
        inc = ingest(db, src, p).incident
    db.commit()
    assert any(p.kind == "blast_radius" for p in inc.predictions)
    assert inc.risk_breakdown["asset"]["available"]


# ─────────── feedback loop ───────────
def test_feedback_labels_come_only_from_explicit_analyst_signals(db):
    inc = None
    for src, p in brute_force():
        inc = ingest(db, src, p).incident
    db.commit()
    assert feedback_loop.labeled_rows(db) == []  # analysis alone is not a label
    db.add(AnalystAction(incident_id=inc.id, username="a1", action="monitor"))
    db.commit()
    assert feedback_loop.labeled_rows(db) == []  # monitoring is not a label either
    db.add(AnalystAction(incident_id=inc.id, username="a1", action="false_positive"))
    db.commit()
    rows = feedback_loop.labeled_rows(db)
    assert len(rows) == 1 and rows[0]["label"] == 0 and set(triage.FEATURES) <= set(rows[0])


def test_retrain_refuses_without_enough_feedback(db):
    r = feedback_loop.retrain_from_feedback(db)
    assert r["status"] == "insufficient_feedback" and r["retrain_ready"] is False


def test_model_metadata_is_valid_json_with_hashes():
    for name in ("triage", "anomaly", "phishing"):
        meta = json.loads((common.model_path(name) / "metadata.json").read_text())
        assert meta["version"] and meta["files"] and meta["training_data"]["source"] and meta["evaluation"]
