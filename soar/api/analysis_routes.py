"""Ad-hoc analysis (triage/phishing/anomaly/certificate), model info, threat intel and assets."""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai.anomaly import isolation_forest_detector as anomaly
from ai.blast_radius import blast_radius_predictor as blast
from ai.llm_commander import providers
from ai.phishing import nlp_phishing_parser as phishing
from ai.triage import ml_triage_analyzer as triage
from soar import audit
from soar.api.deps import Principal, client_ip, require
from soar.db import get_db
from soar.domain import Perm
from soar.intel import enrich
from soar.models import IOC, Asset, AssetLink, ModelPrediction, ThreatIntel

router = APIRouter(tags=["analysis"])


# ─── ad-hoc ML ───
class TriageBody(BaseModel):
    rule_level: int = Field(0, ge=0, le=15)
    failed_logins: int = Field(0, ge=0, le=100000)
    src_ip_is_internal: int = Field(0, ge=0, le=1)
    ioc_score: float | None = Field(None, ge=0, le=100)
    event_count: int = Field(1, ge=1, le=10_000_000)
    is_fim_event: int = Field(0, ge=0, le=1)
    has_mitre_tag: int = Field(0, ge=0, le=1)
    off_hours: int = Field(0, ge=0, le=1)


@router.post("/ai/triage")
def ai_triage(body: TriageBody, _: Principal = Depends(require(Perm.ANALYZE_ADHOC))):
    return triage.predict_threat(triage.build_features(**body.model_dump()))


class PhishingBody(BaseModel):
    emailText: str | None = Field(None, max_length=200_000)
    subject: str | None = Field(None, max_length=1000)
    sender: str | None = Field(None, max_length=500, alias="from")
    reply_to: str | None = Field(None, max_length=500)
    headers: dict[str, str] | None = None

    model_config = {"populate_by_name": True}


@router.post("/ai/phishing")
def ai_phishing(body: PhishingBody, _: Principal = Depends(require(Perm.ANALYZE_ADHOC))):
    if not (body.emailText or body.subject):
        raise HTTPException(422, "emailText is required")
    return phishing.analyze_email({"subject": body.subject, "from": body.sender, "reply_to": body.reply_to,
                                   "body": body.emailText or "", "headers": body.headers or {}})


class AnomalyBody(BaseModel):
    metrics: dict[str, float] = Field(max_length=20)


@router.post("/ai/anomaly")
def ai_anomaly(body: AnomalyBody, _: Principal = Depends(require(Perm.ANALYZE_ADHOC))):
    unknown = set(body.metrics) - set(anomaly.FEATURES)
    if unknown:
        raise HTTPException(422, f"unknown metrics: {sorted(unknown)}; allowed: {anomaly.FEATURES}")
    return anomaly.detect_anomaly(body.metrics)


_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


class CertBody(BaseModel):
    url: str = Field(max_length=500)


@router.post("/ai/certificate")
def ai_certificate(body: CertBody, _: Principal = Depends(require(Perm.ANALYZE_ADHOC))):
    """TLS certificate check. SSRF-hardened: strict hostname syntax, and every resolved address must be
    public (private/loopback/link-local targets are refused), then we connect to the vetted address."""
    host = re.sub(r"^https?://", "", body.url.strip()).split("/")[0].split(":")[0]
    if not _HOST_RE.match(host):
        raise HTTPException(422, "Enter a valid public hostname")
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return {"valid": False, "hostname": host, "error": "hostname does not resolve"}
    addrs = [i[4][0] for i in infos]
    if not all(ipaddress.ip_address(a).is_global for a in addrs):
        raise HTTPException(422, "Refusing to connect to a non-public address")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((addrs[0], 443), timeout=5) as sock, ctx.wrap_socket(sock, server_hostname=host) as s:
            cert = s.getpeercert()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Z").replace(tzinfo=UTC)
            days = (exp - datetime.now(UTC)).days
            return {"valid": True, "hostname": host, "subject": dict(x[0] for x in cert["subject"]).get("commonName"),
                    "issuer": dict(x[0] for x in cert["issuer"]).get("commonName"), "expires": cert["notAfter"],
                    "days_left": days, "protocol": s.version(), "expired": days < 0}
    except (OSError, ssl.SSLError, KeyError, ValueError) as e:
        return {"valid": False, "hostname": host, "error": type(e).__name__}


@router.get("/ai/clusters")
def log_clusters(limit: int = 1000, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    from ai.clustering.log_clusterer import cluster_recent_events
    return cluster_recent_events(db, limit=max(10, min(limit, 5000)))


@router.get("/ai/models")
def models(_: Principal = Depends(require(Perm.VIEW))):
    return {"triage": triage.model_info(), "anomaly": anomaly.model_info(), "phishing": phishing.model_info(),
            "llm": providers.status()}


@router.get("/ai/stats")
def ai_stats(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    from ai import feedback_loop
    counts = {k: n for k, n in db.execute(select(ModelPrediction.kind, func.count()).group_by(ModelPrediction.kind))}
    return {"predictions_by_kind": counts, "feedback": feedback_loop.feedback_stats(db)}


@router.post("/ai/retrain")
def ai_retrain(request: Request, user: Principal = Depends(require(Perm.USER_ADMIN)), db: Session = Depends(get_db)):
    from ai import feedback_loop
    res = feedback_loop.retrain_from_feedback(db)
    audit.record(db, actor=user.username, actor_role=user.role, action="model_retrain", target_type="model",
                 target_id="triage", ip=client_ip(request), data=res)
    return res


# ─── threat intel ───
@router.get("/intel/iocs")
def list_iocs(verdict: str | None = None, type: str | None = None, limit: int = 100,
              _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    q = select(IOC).order_by(IOC.last_seen.desc()).limit(max(1, min(limit, 500)))
    if type:
        q = q.where(IOC.type == type)
    out = []
    for ioc in db.scalars(q):
        rows = db.scalars(select(ThreatIntel).where(ThreatIntel.ioc_id == ioc.id)).all()
        best = enrich.best_verdict(rows)
        v = best.verdict if best else "unknown" if rows else "not_enriched"
        if verdict and v != verdict:
            continue
        out.append({"id": ioc.id, "type": ioc.type, "value": ioc.value, "verdict": v,
                    "score": best.score if best else None, "confidence": best.confidence if best else None,
                    "provider": best.provider if best else None, "tags": best.tags if best else [],
                    "context": best.context if best else {}, "first_seen": ioc.first_seen, "last_seen": ioc.last_seen,
                    "incidents": [i.number for i in ioc.incidents][:5]})
    return {"iocs": out}


class EnrichBody(BaseModel):
    type: str = Field(pattern="^(ip|domain|url|hash)$")
    value: str = Field(min_length=1, max_length=1000)
    force: bool = False


@router.post("/intel/enrich")
def enrich_now(body: EnrichBody, request: Request, user: Principal = Depends(require(Perm.ANALYZE_ADHOC)),
               db: Session = Depends(get_db)):
    ioc = db.scalar(select(IOC).where(IOC.type == body.type, IOC.value == body.value))
    if not ioc:
        ioc = IOC(type=body.type, value=body.value.strip())
        db.add(ioc)
        db.flush()
    rows = enrich.enrich_ioc(db, ioc, force=body.force)
    audit.record(db, actor=user.username, actor_role=user.role, action="ioc_enrich", target_type="ioc",
                 target_id=ioc.id, ip=client_ip(request), data={"type": body.type})
    return {"ioc": {"type": ioc.type, "value": ioc.value},
            "results": [{"provider": r.provider, "verdict": r.verdict, "score": r.score, "confidence": r.confidence,
                         "tags": r.tags, "context": r.context} for r in rows]}


# ─── assets ───
class AssetBody(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip: str | None = Field(None, max_length=64)
    os: str | None = Field(None, max_length=64)
    role: str | None = Field(None, max_length=64)
    criticality: int = Field(3, ge=1, le=10)


class LinkBody(BaseModel):
    src: str
    dst: str
    protocol: str = Field("tcp", max_length=32)
    port: int = Field(0, ge=0, le=65535)


@router.get("/assets")
def list_assets(_: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return {"assets": [{"id": a.id, "hostname": a.hostname, "ip": a.ip, "os": a.os, "role": a.role,
                        "criticality": a.criticality, "source": a.source} for a in db.scalars(select(Asset).order_by(Asset.hostname))]}


@router.post("/assets", status_code=201)
def upsert_asset(body: AssetBody, request: Request, user: Principal = Depends(require(Perm.ASSET_WRITE)),
                 db: Session = Depends(get_db)):
    a = db.scalar(select(Asset).where(Asset.hostname == body.hostname))
    created = a is None
    if created:
        a = Asset(hostname=body.hostname)
        db.add(a)
    a.ip, a.os, a.role, a.criticality = body.ip, body.os, body.role, body.criticality
    db.flush()
    audit.record(db, actor=user.username, actor_role=user.role, action="asset_upsert", target_type="asset",
                 target_id=a.id, ip=client_ip(request), data=body.model_dump())
    return {"id": a.id, "created": created}


@router.post("/assets/links", status_code=201)
def add_link(body: LinkBody, request: Request, user: Principal = Depends(require(Perm.ASSET_WRITE)),
             db: Session = Depends(get_db)):
    s = db.scalar(select(Asset).where(Asset.hostname == body.src))
    d = db.scalar(select(Asset).where(Asset.hostname == body.dst))
    if not (s and d):
        raise HTTPException(404, "Both assets must exist first")
    if not db.scalar(select(AssetLink).where(AssetLink.src_id == s.id, AssetLink.dst_id == d.id,
                                             AssetLink.protocol == body.protocol, AssetLink.port == body.port)):
        db.add(AssetLink(src_id=s.id, dst_id=d.id, protocol=body.protocol, port=body.port))
    audit.record(db, actor=user.username, actor_role=user.role, action="asset_link", target_type="asset",
                 target_id=s.id, ip=client_ip(request), data=body.model_dump())
    return {"ok": True}


@router.get("/assets/graph")
def graph(highlight: str | None = None, _: Principal = Depends(require(Perm.VIEW)), db: Session = Depends(get_db)):
    return blast.export_graph_data(blast.build_graph(db), highlight)
