"""Threat-intelligence enrichment.

IOC -> providers -> verdict/score/confidence -> stored in `threat_intel` (cached for
INTEL_CACHE_HOURS). Providers:

  local_scope  private / loopback / reserved addresses are benign by definition (high confidence)
  local_feed   newline-delimited IOC files placed in <DATA_DIR>/intel/*.txt (one indicator per line,
               '#' comments allowed); a hit is "malicious" with the feed name as context
  misp         MISP `attributes/restSearch` when MISP_URL + MISP_API_KEY are set

There is no built-in "known bad" list. With no provider able to speak to an indicator the verdict
is `unknown` and the risk score treats it as missing evidence, not as evidence of safety.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from datetime import timedelta
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.config import get_settings
from soar.models import IOC, ThreatIntel, utcnow
from soar.observability import metrics

log = logging.getLogger("soar.intel")
MISP_TYPES = {"ip": ["ip-src", "ip-dst"], "domain": ["domain", "hostname"], "url": ["url"],
              "hash": ["md5", "sha1", "sha256"]}
RANK = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}


def _local_scope(ioc: IOC) -> dict | None:
    if ioc.type != "ip":
        return None
    try:
        a = ipaddress.ip_address(ioc.value)
    except ValueError:
        return {"verdict": "unknown", "score": 0.0, "confidence": 0.0, "tags": ["invalid-ip"], "context": {}}
    if not a.is_global:
        return {"verdict": "benign", "score": 0.0, "confidence": 0.95, "tags": ["non-routable"],
                "context": {"reason": "private/loopback/reserved address"}}
    return None


def _local_feed(ioc: IOC) -> dict | None:
    feeds = get_settings().data_dir / "intel"
    if not feeds.is_dir():
        return None
    needle = ioc.value.strip().lower()
    hits = []
    for f in sorted(feeds.glob("*.txt")):
        try:
            lines = {ln.strip().lower() for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines()
                     if ln.strip() and not ln.startswith("#")}
        except OSError:
            continue
        if needle in lines:
            hits.append(f.name)
    if not hits:
        return None
    return {"verdict": "malicious", "score": 85.0, "confidence": min(0.9, 0.6 + 0.15 * len(hits)),
            "tags": ["local-feed"], "context": {"feeds": hits}}


def _misp(ioc: IOC, client: httpx.Client | None = None) -> dict | None:
    s = get_settings()
    if not (s.misp_url and s.misp_api_key):
        return None
    body = {"returnFormat": "json", "value": ioc.value, "type": MISP_TYPES.get(ioc.type, []), "limit": 25,
            "includeEventTags": True, "includeContext": True}
    try:
        post = client.post if client else httpx.post
        r = post(f"{s.misp_url.rstrip('/')}/attributes/restSearch", json=body, timeout=10,
                 headers={"Authorization": s.misp_api_key, "Accept": "application/json"},
                 **({} if client else {"verify": s.misp_verify_tls}))
        r.raise_for_status()
        attrs = (r.json().get("response") or {}).get("Attribute", [])
    except (httpx.HTTPError, ValueError) as e:
        log.warning("MISP lookup failed: %s", type(e).__name__)
        metrics.count("intel_misp_errors")
        return {"verdict": "unknown", "score": 0.0, "confidence": 0.0, "tags": ["misp-error"],
                "context": {"error": type(e).__name__}}
    if not attrs:
        return None
    to_ids = sum(1 for a in attrs if a.get("to_ids"))
    events = {a.get("event_id") for a in attrs}
    tags = sorted({t.get("name", "") for a in attrs for t in a.get("Tag", [])} - {""})[:15]
    verdict = "malicious" if to_ids else "suspicious"
    return {"verdict": verdict, "score": 90.0 if to_ids else 55.0,
            "confidence": round(min(0.95, 0.5 + 0.1 * len(events) + (0.2 if to_ids else 0)), 2), "tags": tags,
            "context": {"misp_events": sorted(str(e) for e in events)[:10], "attributes": len(attrs),
                        "to_ids": to_ids}}


PROVIDERS = (("local_scope", _local_scope), ("local_feed", _local_feed), ("misp", _misp))


def enrich_ioc(db: Session, ioc: IOC, force: bool = False) -> list[ThreatIntel]:
    """Return stored/fresh results for the IOC (one row per provider that had something to say)."""
    now = utcnow()
    cached = list(db.scalars(select(ThreatIntel).where(ThreatIntel.ioc_id == ioc.id, ThreatIntel.expires_at > now)))
    if cached and not force:
        return cached
    for row in db.scalars(select(ThreatIntel).where(ThreatIntel.ioc_id == ioc.id)):
        db.delete(row)
    out = []
    for name, fn in PROVIDERS:
        started = time.perf_counter()
        res = fn(ioc)
        metrics.observe(f"intel_{name}_ms", (time.perf_counter() - started) * 1000)
        if res is None:
            continue
        row = ThreatIntel(ioc_id=ioc.id, provider=name, verdict=res["verdict"], score=res["score"],
                          confidence=res["confidence"], tags=res["tags"], context=res["context"],
                          fetched_at=now, expires_at=now + timedelta(hours=get_settings().intel_cache_hours))
        db.add(row)
        out.append(row)
    if not out:  # nobody knows this indicator: record that, so we do not re-query on every event
        row = ThreatIntel(ioc_id=ioc.id, provider="none", verdict="unknown", score=0.0, confidence=0.0,
                          tags=[], context={"reason": "no provider had data"}, fetched_at=now,
                          expires_at=now + timedelta(hours=1))
        db.add(row)
        out.append(row)
    db.flush()
    return out


def best_verdict(rows: list[ThreatIntel]) -> ThreatIntel | None:
    known = [r for r in rows if r.verdict != "unknown"]
    return max(known, key=lambda r: (RANK[r.verdict], r.score, r.confidence), default=None) if known else None


def ioc_risk_signal(rows_by_ioc: dict[str, list[ThreatIntel]]) -> float | None:
    """0..1 for the risk score: worst known verdict, weighted by confidence. None if nothing known."""
    best = [best_verdict(rows) for rows in rows_by_ioc.values()]
    best = [b for b in best if b]
    if not best:
        return None
    return max((b.score / 100.0) * (0.5 + 0.5 * b.confidence) if b.verdict != "benign" else 0.0 for b in best)


def feed_dir() -> Path:
    d = get_settings().data_dir / "intel"
    d.mkdir(parents=True, exist_ok=True)
    return d
