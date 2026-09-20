"""Response policy: the single gate every action passes through, whether it comes from a
playbook, an analyst, or an LLM recommendation.

Outcomes
  auto      may execute without a human
  approval  must be approved by a person first (recorded in `approvals`)
  deny      never executes (invalid target, protected asset, ...)

Rules
  * Every action has a fixed risk tier (ACTION_RISK). Tiers above AUTO_EXECUTE_MAX_RISK need approval;
    `high` always needs approval regardless of configuration.
  * Protected targets (private/loopback/link-local/multicast ranges and PROTECTED_IPS) can never be
    blocked: blocking your own gateway or DNS is an outage, not a response.
  * A playbook step may ask for `approval: required`, which can only tighten the outcome.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sqlalchemy.orm import Session

from soar.config import get_settings
from soar.domain import RISK_ORDER

ACTION_RISK = {"enrich_ioc": "low", "notify_analyst": "low", "collect_evidence": "low",
               "create_case": "low", "block_ip": "medium", "isolate_host": "high", "disable_account": "high"}


@dataclass
class Decision:
    outcome: str  # auto | approval | deny
    risk: str
    reason: str


def _protected_networks() -> list[ipaddress._BaseNetwork]:
    nets = []
    for raw in (get_settings().protected_ips or "").split(","):
        raw = raw.strip()
        if raw:
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
    return nets


def is_protected_ip(value: str | None) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return True, "not a valid IP address"
    # Explicit checks as well as is_global: some multicast ranges (e.g. 224.0.0.1) report is_global.
    if (not ip.is_global or ip.is_multicast or ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_unspecified):
        return True, "private, loopback, link-local, multicast or reserved address"
    if any(ip in n for n in _protected_networks()):
        return True, "listed in PROTECTED_IPS"
    return False, ""


def evaluate(db: Session | None, action: str, params: dict, incident=None,
             approval_mode: str = "policy") -> Decision:
    risk = ACTION_RISK.get(action)
    if risk is None:
        return Decision("deny", "high", f"unknown action '{action}'")
    if action == "block_ip":
        target = params.get("ip") or params.get("target")
        protected, why = is_protected_ip(target)
        if protected:
            return Decision("deny", risk, f"cannot block {target!r}: {why}")
    if action in ("isolate_host", "disable_account") and not (params.get("host") or params.get("user")
                                                               or params.get("target")):
        return Decision("deny", risk, "no target given")
    if approval_mode == "approved":  # a human already approved; deny rules above still applied
        return Decision("auto", risk, "approved by a human")
    if approval_mode == "required":
        return Decision("approval", risk, "playbook step requires approval")
    if risk == "high":
        return Decision("approval", risk, "high-impact actions always require human approval")
    ceiling = get_settings().auto_execute_max_risk
    if RISK_ORDER[risk] <= RISK_ORDER[ceiling]:
        return Decision("auto", risk, f"{risk}-risk action within auto-execute ceiling '{ceiling}'")
    return Decision("approval", risk, f"{risk}-risk action exceeds auto-execute ceiling '{ceiling}'")
