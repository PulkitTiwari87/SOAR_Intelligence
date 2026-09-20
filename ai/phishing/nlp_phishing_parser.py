"""Phishing analysis: text model + URL/domain/header indicators, with an explanation.

score = 0.5 * text_probability + 0.5 * indicator_score
  text_probability  TF-IDF + logistic regression trained on ai/phishing/corpus.py (small, hand-
                    written, template-like: its cross-validation numbers are inflated by that
                    similarity and are NOT a real-world accuracy estimate)
  indicator_score   deterministic, transparent checks: lookalike/brand domains, IP-literal hosts,
                    punycode, risky TLDs, URL shorteners, '@' in URL, link text != link target,
                    Reply-To mismatch, SPF/DKIM/DMARC failures, display-name brand impersonation.

The equal split is a design choice, not a tuned value; the indicators are given real weight because
the text model has little training data. The raw email is never modified: `evidence_sha256`
identifies the exact input analyzed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import sys
import threading
from html import unescape
from urllib.parse import urlparse

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline

from ai import common
from ai.phishing.corpus import LEGITIMATE_EMAILS, PHISHING_EMAILS

log = logging.getLogger("ai.phishing")

NAME = "phishing"
SCHEMA_VERSION = "2"
BUNDLE = "bundle.joblib"
PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD = 0.7, 0.4

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
HREF_RE = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

RISKY_TLDS = {"top", "xyz", "click", "tk", "ml", "ga", "cf", "gq", "work", "zip", "mov", "support",
              "loan", "country", "kim", "men", "party", "review", "stream", "science"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "tiny.cc", "shorturl.at"}
BRANDS = {"paypal": {"paypal.com"}, "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"},
          "google": {"google.com", "gmail.com", "googleapis.com"}, "apple": {"apple.com", "icloud.com"},
          "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"}, "netflix": {"netflix.com"},
          "facebook": {"facebook.com", "fb.com"}, "dhl": {"dhl.com"}, "fedex": {"fedex.com"},
          "docusign": {"docusign.com", "docusign.net"}, "dropbox": {"dropbox.com"},
          "linkedin": {"linkedin.com"}, "bankofamerica": {"bankofamerica.com"}, "wellsfargo": {"wellsfargo.com"},
          "chase": {"chase.com"}, "coinbase": {"coinbase.com"}}
TWO_LEVEL = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.mx"}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "@": "a", "$": "s"})


def registered_domain(host: str) -> str:
    """Approximate eTLD+1 (no public-suffix list: handles the common two-level suffixes)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_flag(host: str) -> str | None:
    reg = registered_domain(host)
    label = reg.split(".")[0].translate(_LEET)
    if any(reg in official for official in BRANDS.values()):
        return None
    for brand in BRANDS:
        if brand in label:
            return "brand_in_domain"
        if len(label) >= 5 and _edit_distance(label, brand) <= 1:
            return "lookalike_domain"
    subs = host.lower().translate(_LEET)
    if any(f"{b}." in subs.replace(registered_domain(host), "") for b in BRANDS):
        return "brand_in_subdomain"
    return None


URL_FLAG_WEIGHTS = {"ip_host": 0.4, "punycode": 0.3, "risky_tld": 0.25, "shortener": 0.2, "at_symbol": 0.3,
                    "lookalike_domain": 0.45, "brand_in_domain": 0.4, "brand_in_subdomain": 0.3,
                    "plain_http": 0.1, "many_subdomains": 0.15, "link_text_mismatch": 0.35}


def extract_urls(text: str) -> list[dict]:
    """URLs from plain text and HTML anchors; anchors record the visible link text."""
    found: dict[str, str | None] = {}
    for href, label in HREF_RE.findall(text or ""):
        found.setdefault(unescape(href).strip(), re.sub(r"<[^>]+>", "", label).strip())
    for u in URL_RE.findall(text or ""):
        found.setdefault(u.rstrip(".,;:"), None)
    return [{"url": u, "text": t} for u, t in found.items()]


def analyze_url(url: str, link_text: str | None = None) -> dict:
    parsed = urlparse(url if "://" in url else f"//{url}")
    host = (parsed.hostname or "").lower()
    flags: list[str] = []
    try:
        ipaddress.ip_address(host)
        flags.append("ip_host")
    except ValueError:
        pass
    if host:
        if "xn--" in host:
            flags.append("punycode")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            flags.append("risky_tld")
        if registered_domain(host) in SHORTENERS:
            flags.append("shortener")
        if len(host.split(".")) >= 5:
            flags.append("many_subdomains")
        if not flags or "ip_host" not in flags:
            b = _brand_flag(host)
            if b:
                flags.append(b)
    if "@" in (parsed.netloc or ""):
        flags.append("at_symbol")
    if parsed.scheme == "http":
        flags.append("plain_http")
    if link_text and re.search(r"[\w-]+\.[a-z]{2,}", link_text, re.I):
        shown = urlparse(link_text if "://" in link_text else f"//{link_text.split()[0]}").hostname
        if shown and host and registered_domain(shown) != registered_domain(host):
            flags.append("link_text_mismatch")
    score = min(1.0, sum(URL_FLAG_WEIGHTS[f] for f in flags))
    return {"url": url, "domain": host, "flags": flags, "score": round(score, 2)}


def analyze_headers(headers: dict, sender: str | None, reply_to: str | None) -> list[dict]:
    out = []
    s_dom = (EMAIL_RE.search(sender or "") or [None, None])[1]
    r_dom = (EMAIL_RE.search(reply_to or "") or [None, None])[1]
    if s_dom and r_dom and registered_domain(s_dom) != registered_domain(r_dom):
        out.append({"name": "reply_to_mismatch", "weight": 0.25,
                    "detail": f"From domain {s_dom} differs from Reply-To domain {r_dom}"})
    auth = " ".join(str(v) for k, v in (headers or {}).items() if k.lower() in ("authentication-results", "received-spf"))
    if re.search(r"\b(spf|dkim|dmarc)=(fail|softfail|none)\b", auth, re.I) or re.search(r"\bfail\b", auth, re.I):
        out.append({"name": "authentication_failed", "weight": 0.3, "detail": "SPF/DKIM/DMARC did not pass"})
    display = re.match(r'\s*"?([^"<]+?)"?\s*<', sender or "")
    if display and s_dom:
        name = display.group(1).lower().translate(_LEET).replace(" ", "")
        for brand, official in BRANDS.items():
            if brand in name and registered_domain(s_dom) not in official:
                out.append({"name": "display_name_impersonation", "weight": 0.3,
                            "detail": f"Display name mentions {brand} but sender domain is {s_dom}"})
                break
    return out


# ─── text model ───
def _pipeline() -> "make_pipeline":
    return make_pipeline(TfidfVectorizer(max_features=800, stop_words="english", ngram_range=(1, 2), sublinear_tf=True),
                         LogisticRegression(max_iter=1000, C=2.0, random_state=42))


def train_model(extra: list[tuple[str, int]] | None = None) -> dict:
    texts = PHISHING_EMAILS + LEGITIMATE_EMAILS + [t for t, _ in (extra or [])]
    y = np.array([1] * len(PHISHING_EMAILS) + [0] * len(LEGITIMATE_EMAILS) + [lbl for _, lbl in (extra or [])])
    pred = cross_val_predict(_pipeline(), texts, y, cv=StratifiedKFold(5, shuffle=True, random_state=42))
    evaluation = {"kind": "5fold_cross_validation", "n_samples": int(len(y)),
                  "accuracy": round(accuracy_score(y, pred), 4), "precision": round(precision_score(y, pred), 4),
                  "recall": round(recall_score(y, pred), 4), "f1": round(f1_score(y, pred), 4),
                  "note": "Small, hand-written, template-like corpus; scores are optimistic and not a real-world estimate."}
    pipe = _pipeline().fit(texts, y)
    common.save_joblib(NAME, BUNDLE, pipe)
    meta = common.write_meta(NAME, {
        "name": NAME, "schema_version": SCHEMA_VERSION, "algorithm": "TfidfVectorizer + LogisticRegression",
        "features": "tf-idf unigrams+bigrams", "training_data": {
            "source": "hand_written_corpus", "n_samples": int(len(y)), "n_phishing": int(y.sum()), "real_data": False},
        "evaluation": evaluation,
        "limitations": ["Tiny corpus; text model alone is weak. Indicator checks carry half the score.",
                        "No public-suffix list: registered-domain extraction is approximate.",
                        "Does not fetch URLs or check live reputation (that is threat-intel enrichment)."]}, [BUNDLE])
    _cache.clear()
    return meta


_cache: dict = {}
_lock = threading.Lock()


def _load():
    with _lock:
        if "pipe" not in _cache:
            if common.read_meta(NAME) is None:
                log.warning("no phishing model found; training from the bundled corpus")
                train_model()
            _cache.update(pipe=common.load_joblib(NAME, BUNDLE), meta=common.read_meta(NAME))
        return _cache["pipe"], _cache["meta"]


def model_info() -> dict:
    return common.read_meta(NAME) or {"name": NAME, "status": "not_trained"}


def _top_terms(pipe, text: str, k: int = 6) -> list[dict]:
    vec, clf = pipe.steps[0][1], pipe.steps[1][1]
    row = vec.transform([text])
    names = vec.get_feature_names_out()
    contrib = row.multiply(clf.coef_[0]).tocoo()
    items = sorted(((names[c], float(v)) for c, v in zip(contrib.col, contrib.data)), key=lambda t: -abs(t[1]))[:k]
    return [{"term": t, "contribution": round(v, 3)} for t, v in items]


def analyze_email(email: dict | str) -> dict:
    """`email`: raw text/body string, or a dict with subject/from/reply_to/body/headers."""
    if isinstance(email, str):
        email = {"body": email}
    body = str(email.get("body") or email.get("text") or "")
    subject = str(email.get("subject") or "")
    text = f"{subject}\n{body}".strip()
    evidence = hashlib.sha256(json.dumps(email, sort_keys=True, default=str).encode()).hexdigest()
    pipe, meta = _load()
    text_p = float(pipe.predict_proba([re.sub(r"<[^>]+>", " ", text)])[0, 1]) if text else 0.0

    urls = [analyze_url(u["url"], u["text"]) for u in extract_urls(f"{subject}\n{body}")]
    indicators = [{"name": f"url:{f}", "weight": URL_FLAG_WEIGHTS[f], "detail": u["url"]}
                  for u in urls for f in u["flags"] if f != "plain_http" or len(u["flags"]) > 1]
    header_ind = analyze_headers(email.get("headers") or {}, email.get("from"), email.get("reply_to"))
    url_score = 0.0
    if urls:
        ranked = sorted((u["score"] for u in urls), reverse=True)
        url_score = min(1.0, ranked[0] + 0.1 * sum(1 for s in ranked[1:] if s >= 0.3))
    indicator_score = min(1.0, url_score + sum(h["weight"] for h in header_ind))
    score = 0.5 * text_p + 0.5 * indicator_score

    domains = sorted({u["domain"] for u in urls if u["domain"]})
    iocs = [{"type": "url", "value": u["url"]} for u in urls] + [{"type": "domain", "value": d} for d in domains]
    for ip in set(IP_RE.findall(body)):
        try:
            if ipaddress.ip_address(ip).is_global:
                iocs.append({"type": "ip", "value": ip})
        except ValueError:
            pass
    verdict = "phishing" if score >= PHISHING_THRESHOLD else "suspicious" if score >= SUSPICIOUS_THRESHOLD else "legitimate"
    if verdict == "legitimate" and text_p >= 0.7:
        # BEC-style mail has no links, so indicators stay at 0 and halve the score; a strong
        # text-only signal still deserves an analyst's look.
        verdict = "suspicious"
        indicators.append({"name": "text_only_signal", "weight": 0.0,
                           "detail": f"Text model probability {text_p:.0%} with no URL/header indicators"})
    return {
        "phishing_score": round(score * 100, 1), "verdict": verdict, "text_score": round(text_p * 100, 1),
        "indicator_score": round(indicator_score * 100, 1),
        "indicators": indicators + header_ind, "urls": urls, "domains": domains, "iocs": iocs,
        "top_terms": _top_terms(pipe, text) if text else [],
        "threat_type": ("Phishing (links)" if verdict != "legitimate" and urls else
                        "Phishing / BEC (text only)" if verdict != "legitimate" else "Legitimate email"),
        "action": {"phishing": "Quarantine and open an incident", "suspicious": "Flag for analyst review",
                   "legitimate": "No action"}[verdict],
        "model_version": meta["version"], "evidence_sha256": evidence,
        "trained_on": meta["training_data"]["source"],
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train":
        print(json.dumps(train_model()["evaluation"], indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(analyze_email({"subject": "Verify now", "from": "PayPal <x@paypa1-secure.top>",
                                        "body": "URGENT verify at http://paypa1-secure.top/login"}), indent=2)[:1500])
    else:
        print("Usage: python -m ai.phishing.nlp_phishing_parser --train | --test")
