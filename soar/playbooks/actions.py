"""Response actions. Each action reports what it REALLY did.

  succeeded  the effect was applied (and `data` says exactly where)
  skipped    nothing was done (no data, or no connector configured) and `detail` says why
  failed     an error occurred

Only actions that can be executed and verified locally are fully implemented:
  enrich_ioc, notify_analyst, collect_evidence, block_ip (SOAR blocklist + optional Wazuh AR),
  create_case (TheHive, when configured).
isolate_host / disable_account need an environment-specific connector: they dispatch a custom
Wazuh active-response command named by WAZUH_ISOLATE_COMMAND / WAZUH_DISABLE_ACCOUNT_COMMAND and
are reported as `skipped` when that is not configured. No action ever pretends success.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.config import get_settings
from soar.intel import enrich
from soar.models import BlocklistEntry, Incident, Notification, ThreatIntel, utcnow
from soar.observability import metrics

log = logging.getLogger("soar.actions")


@dataclass
class Ctx:
    db: Session
    incident: Incident
    actor: str = "system"


@dataclass
class ActionResult:
    status: str  # succeeded | skipped | failed
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Verification:
    verified: bool | None  # None = cannot be verified from here
    detail: str


@dataclass
class Action:
    name: str
    risk: str
    description: str
    execute: Callable[[Ctx, dict], ActionResult]
    verify: Callable[[Ctx, dict, ActionResult], Verification]
    rollback: Callable[[Ctx, dict, ActionResult], ActionResult] | None = None


# ─── Wazuh helpers (active response) ───
def _wazuh_configured() -> bool:
    s = get_settings()
    return bool(s.wazuh_api_url and s.wazuh_api_user and s.wazuh_api_pass)


def _wazuh_call(method: str, path: str, **kw) -> dict:
    s = get_settings()
    base = s.wazuh_api_url.rstrip("/")
    auth = httpx.post(f"{base}/security/user/authenticate", auth=(s.wazuh_api_user, s.wazuh_api_pass),
                      verify=s.wazuh_verify_tls, timeout=10)
    auth.raise_for_status()
    token = auth.json()["data"]["token"]
    r = httpx.request(method, f"{base}{path}", headers={"Authorization": f"Bearer {token}"},
                      verify=s.wazuh_verify_tls, timeout=15, **kw)
    r.raise_for_status()
    return r.json()


def _wazuh_agent_id(host: str | None) -> str | None:
    if not host:
        return None
    items = _wazuh_call("GET", "/agents", params={"name": host}).get("data", {}).get("affected_items", [])
    return items[0]["id"] if items else None


def _wazuh_dispatch(command: str, host: str | None, arguments: list[str]) -> tuple[str, str]:
    """Return (state, detail). Never raises: connector problems are reported, not fatal."""
    if not _wazuh_configured():
        return "not_configured", "Wazuh API is not configured"
    try:
        agent = _wazuh_agent_id(host)
        if not agent:
            return "skipped", f"no Wazuh agent found for host {host!r}"
        _wazuh_call("PUT", "/active-response", params={"agents_list": agent},
                    json={"command": command, "arguments": arguments, "alert": {"data": {"srcip": arguments[0]}}
                          if arguments else {}})
        return "dispatched", f"command {command} accepted by Wazuh for agent {agent}"
    except (httpx.HTTPError, KeyError, ValueError) as e:
        return "failed", f"Wazuh call failed: {type(e).__name__}"


# ─── enrich_ioc ───
def _enrich(ctx: Ctx, params: dict) -> ActionResult:
    iocs = list(ctx.incident.iocs)
    if not iocs:
        return ActionResult("skipped", "incident has no indicators to enrich")
    verdicts = {}
    for ioc in iocs:
        rows = enrich.enrich_ioc(ctx.db, ioc, force=bool(params.get("force")))
        b = enrich.best_verdict(rows)
        verdicts[ioc.value] = b.verdict if b else "unknown"
    return ActionResult("succeeded", f"enriched {len(iocs)} indicator(s)", {"verdicts": verdicts})


def _verify_enrich(ctx: Ctx, params: dict, res: ActionResult) -> Verification:
    missing = [i.value for i in ctx.incident.iocs
               if not ctx.db.scalar(select(ThreatIntel.id).where(ThreatIntel.ioc_id == i.id).limit(1))]
    return Verification(not missing, "all indicators have stored intel" if not missing else f"missing: {missing[:3]}")


# ─── notify_analyst ───
def _notify(ctx: Ctx, params: dict) -> ActionResult:
    inc = ctx.incident
    msg = params.get("message") or f"{inc.number}: {inc.title} (risk {inc.risk_score})"
    n = Notification(incident_id=inc.id, severity=inc.severity, message=msg[:1000])
    ctx.db.add(n)
    ctx.db.flush()
    channels = ["in_app"]
    hook = get_settings().notify_webhook_url
    detail = "in-app notification created"
    if hook:
        try:
            httpx.post(hook, json={"text": msg[:1000]}, timeout=5).raise_for_status()
            channels.append("webhook")
            detail += "; webhook delivered"
        except httpx.HTTPError as e:
            detail += f"; webhook failed ({type(e).__name__})"
    return ActionResult("succeeded", detail, {"notification_id": n.id, "channels": channels})


def _verify_notify(ctx: Ctx, params: dict, res: ActionResult) -> Verification:
    ok = ctx.db.get(Notification, res.data.get("notification_id")) is not None
    return Verification(ok, "notification row present" if ok else "notification row missing")


# ─── collect_evidence ───
def _evidence_doc(inc: Incident) -> dict:
    return {
        "incident": {"number": inc.number, "title": inc.title, "status": inc.status, "severity": inc.severity,
                     "risk_score": inc.risk_score, "entities": inc.entities},
        "events": [{"event_id": e.event_id, "timestamp": e.timestamp.isoformat(), "source": e.source,
                    "type": e.event_type, "raw_event": e.raw_event} for e in sorted(inc.events, key=lambda e: e.timestamp)],
        "iocs": [{"type": i.type, "value": i.value} for i in inc.iocs],
        "predictions": [{"kind": p.kind, "model": p.model_name, "version": p.model_version,
                         "prediction": p.prediction, "result": p.result} for p in inc.predictions],
        "mitre": [{"id": m.technique_id, "source": m.source, "confidence": m.confidence} for m in inc.mitre],
        "timeline": [{"time": t.timestamp.isoformat(), "kind": t.kind, "title": t.title} for t in inc.timeline],
    }


def _collect(ctx: Ctx, params: dict) -> ActionResult:
    inc = ctx.incident
    out_dir = get_settings().evidence_dir / inc.number
    out_dir.mkdir(parents=True, exist_ok=True)
    body = json.dumps(_evidence_doc(inc), indent=2, sort_keys=True, default=str).encode()
    digest = hashlib.sha256(body).hexdigest()
    path = out_dir / f"{utcnow().strftime('%Y%m%dT%H%M%S%fZ')}.json"
    path.write_bytes(body)
    return ActionResult("succeeded", f"evidence snapshot written ({len(body)} bytes)",
                        {"path": str(path), "sha256": digest, "bytes": len(body)})


def _verify_collect(ctx: Ctx, params: dict, res: ActionResult) -> Verification:
    from pathlib import Path
    p = Path(res.data.get("path", ""))
    if not p.is_file():
        return Verification(False, "evidence file missing")
    ok = hashlib.sha256(p.read_bytes()).hexdigest() == res.data.get("sha256")
    return Verification(ok, "file hash matches" if ok else "file hash mismatch")


# ─── create_case ───
def _create_case(ctx: Ctx, params: dict) -> ActionResult:
    s, inc = get_settings(), ctx.incident
    if not (s.thehive_url and s.thehive_api_key):
        return ActionResult("skipped", "TheHive is not configured; the incident record is the case")
    body = {"type": "soar", "source": "soar-intelligence", "sourceRef": inc.number, "title": inc.title,
            "description": f"Risk {inc.risk_score}; {inc.event_count} events; category {inc.category}",
            "severity": inc.severity, "tags": [f"soar:{inc.number}"]}
    try:
        r = httpx.post(f"{s.thehive_url.rstrip('/')}/api/v1/alert", json=body, timeout=10,
                       headers={"Authorization": f"Bearer {s.thehive_api_key}"})
        if r.status_code == 409:
            return ActionResult("succeeded", "alert already exists in TheHive", {"existing": True})
        r.raise_for_status()
        return ActionResult("succeeded", "alert created in TheHive", {"thehive_id": r.json().get("_id")})
    except (httpx.HTTPError, ValueError) as e:
        return ActionResult("failed", f"TheHive call failed: {type(e).__name__}")


def _verify_case(ctx: Ctx, params: dict, res: ActionResult) -> Verification:
    if res.data.get("thehive_id") or res.data.get("existing"):
        return Verification(True, "TheHive returned an identifier")
    return Verification(None, "no external id to verify")


# ─── block_ip ───
def _block(ctx: Ctx, params: dict) -> ActionResult:
    ip = params.get("ip") or params.get("target")
    ttl = int(params.get("ttl_hours") or 24)
    entry = ctx.db.scalar(select(BlocklistEntry).where(BlocklistEntry.ip == ip))
    exp = utcnow() + timedelta(hours=ttl)
    if entry is None:
        entry = BlocklistEntry(ip=ip)
        ctx.db.add(entry)
    entry.reason, entry.incident_id, entry.created_by = f"incident {ctx.incident.number}", ctx.incident.id, ctx.actor
    entry.created_at, entry.expires_at, entry.active, entry.removed_at, entry.removed_by = utcnow(), exp, True, None, None
    ctx.db.flush()
    state, wz = _wazuh_dispatch("firewall-drop", ctx.incident.primary_host, [ip])
    enforcement = ["soar_blocklist"] + (["wazuh_active_response"] if state == "dispatched" else [])
    detail = f"{ip} added to the SOAR blocklist until {exp:%Y-%m-%d %H:%M} UTC (feed: /api/blocklist); Wazuh: {wz}"
    metrics.count("blocked_ips")
    # The blocklist entry is the durable effect, so the action succeeded even if the optional
    # Wazuh dispatch did not; the Wazuh outcome is reported separately in `data`.
    return ActionResult("succeeded", detail,
                        {"ip": ip, "expires_at": exp.isoformat(), "enforcement": enforcement,
                         "wazuh": state, "wazuh_detail": wz})


def _verify_block(ctx: Ctx, params: dict, res: ActionResult) -> Verification:
    ip = res.data.get("ip")
    e = ctx.db.scalar(select(BlocklistEntry).where(BlocklistEntry.ip == ip, BlocklistEntry.active.is_(True)))
    if not e:
        return Verification(False, "blocklist entry not active")
    net = "Wazuh accepted the active-response command (enforcement on the agent is not confirmed here)" \
        if res.data.get("wazuh") == "dispatched" else "recorded in the SOAR blocklist only; a firewall/agent must consume /api/blocklist to enforce"
    return Verification(True, f"blocklist entry active; {net}")


def _unblock(ctx: Ctx, params: dict, res: ActionResult) -> ActionResult:
    ip = res.data.get("ip") or params.get("ip") or params.get("target")
    e = ctx.db.scalar(select(BlocklistEntry).where(BlocklistEntry.ip == ip))
    if not e or not e.active:
        return ActionResult("skipped", f"{ip} is not on the blocklist")
    e.active, e.removed_at, e.removed_by = False, utcnow(), ctx.actor
    return ActionResult("succeeded", f"{ip} removed from the SOAR blocklist "
                        "(any Wazuh active-response block expires on its own timeout)", {"ip": ip})


# ─── connector-backed high-impact actions ───
def _connector_action(setting: str, label: str, arg_from: tuple[str, ...]):
    def run(ctx: Ctx, params: dict) -> ActionResult:
        command = getattr(get_settings(), setting)
        target = next((params[k] for k in arg_from if params.get(k)), None)
        if not command:
            return ActionResult("skipped", f"no connector configured for {label}: set {setting.upper()} to a "
                                "custom Wazuh active-response command")
        state, detail = _wazuh_dispatch(command, ctx.incident.primary_host, [str(target)])
        if state == "dispatched":
            return ActionResult("succeeded", detail, {"target": target, "command": command, "wazuh": state})
        return ActionResult("failed" if state == "failed" else "skipped", detail, {"target": target, "wazuh": state})
    return run


def _no_verify(ctx: Ctx, params: dict, res: ActionResult) -> Verification:
    return Verification(None, "effect cannot be verified from SOAR; confirm on the endpoint")


ACTIONS: dict[str, Action] = {a.name: a for a in (
    Action("enrich_ioc", "low", "Look up incident indicators in threat intelligence", _enrich, _verify_enrich),
    Action("notify_analyst", "low", "Notify the SOC (in-app, optional webhook)", _notify, _verify_notify),
    Action("collect_evidence", "low", "Snapshot events, analysis and timeline with a SHA-256", _collect, _verify_collect),
    Action("create_case", "low", "Create a TheHive alert for the incident (when configured)", _create_case, _verify_case),
    Action("block_ip", "medium", "Add the source IP to the SOAR blocklist (+ Wazuh active response if configured)",
           _block, _verify_block, _unblock),
    Action("isolate_host", "high", "Isolate a host via a configured Wazuh active-response command",
           _connector_action("wazuh_isolate_command", "host isolation", ("host", "target")), _no_verify),
    Action("disable_account", "high", "Disable a user account via a configured Wazuh active-response command",
           _connector_action("wazuh_disable_account_command", "account disable", ("user", "target")), _no_verify),
)}
