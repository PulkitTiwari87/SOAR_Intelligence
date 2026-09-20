"""Blast radius: which assets an attacker who controls one host could reach next.

The graph comes from the asset inventory (`assets` + `asset_links` tables, populated manually,
from Wazuh agents, or by `python -m soar.cli seed-demo` in development). There is no built-in
topology: with no inventory the result says so instead of inventing one.

Reachability is a bounded breadth-first search over directed links ("src can reach dst").
risk_score = 100 * (criticality / 10) / hop_distance  -- closer and more critical assets rank
higher. This is a prioritization heuristic, not a probability of compromise.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from soar.models import Asset, AssetLink, Event


def build_graph(db: Session) -> nx.DiGraph:
    g = nx.DiGraph()
    assets = {a.id: a for a in db.scalars(select(Asset))}
    for a in assets.values():
        g.add_node(a.hostname, ip=a.ip, os=a.os, role=a.role, criticality=a.criticality,
                   agent_id=a.agent_id)
    for link in db.scalars(select(AssetLink)):
        s, d = assets.get(link.src_id), assets.get(link.dst_id)
        if s and d:
            g.add_edge(s.hostname, d.hostname, protocol=link.protocol, port=link.port)
    return g


def resolve_host(db: Session, host_or_ip: str | None) -> str | None:
    if not host_or_ip:
        return None
    a = db.scalar(select(Asset).where(Asset.hostname == host_or_ip)) or \
        db.scalar(select(Asset).where(Asset.ip == host_or_ip))
    return a.hostname if a else None


def predict_blast_radius(compromised_host: str, network: nx.DiGraph, max_hops: int = 3,
                         db: Session | None = None) -> dict:
    if network.number_of_nodes() == 0:
        return {"status": "no_asset_inventory",
                "message": "No assets are registered; add assets and links to enable blast-radius analysis."}
    if compromised_host not in network:
        return {"status": "unknown_host", "message": f"Host '{compromised_host}' is not in the asset inventory."}

    dist = nx.single_source_shortest_path_length(network, compromised_host, cutoff=max_hops)
    reachable = {h: d for h, d in dist.items() if h != compromised_host}
    at_risk = []
    for host, hops in reachable.items():
        n = network.nodes[host]
        path = nx.shortest_path(network, compromised_host, host)
        edge = network.get_edge_data(path[-2], host) or {}
        at_risk.append({
            "hostname": host, "ip": n.get("ip"), "os": n.get("os"), "role": n.get("role"),
            "criticality": n.get("criticality", 0), "hop_distance": hops,
            "access": f"{edge.get('protocol', '?')}/{edge.get('port', '?')}",
            "attack_path": " → ".join(path),
            "risk_score": round(100 * (n.get("criticality", 0) / 10) / hops, 1)})
    at_risk.sort(key=lambda h: -h["risk_score"])

    services = defaultdict(set)
    for host in list(reachable) + [compromised_host]:
        for _, _, e in network.in_edges(host, data=True):
            services[host].add(f"{e.get('protocol', '?')}/{e.get('port', '?')}")
    hosts = list(reachable) + [compromised_host]
    users: dict[str, list[str]] = {}
    if db is not None:
        for h in hosts:
            names = {u for (u,) in db.execute(select(Event.username).where(
                (Event.source_host == h) | (Event.destination_host == h), Event.username.is_not(None)).distinct())}
            if names:
                users[h] = sorted(names)

    info = network.nodes[compromised_host]
    return {
        "status": "ok",
        "compromised_host": {"hostname": compromised_host, "ip": info.get("ip"), "os": info.get("os"),
                             "role": info.get("role"), "criticality": info.get("criticality")},
        "total_at_risk": len(at_risk), "at_risk_hosts": at_risk,
        "related_hosts": sorted(set(network.predecessors(compromised_host)) | set(network.successors(compromised_host))),
        "services": {h: sorted(s) for h, s in services.items()},
        "users_seen": users,
        "recommendations": {
            "review_first": [{"hostname": h["hostname"], "ip": h["ip"], "reason": f"directly reachable via {h['access']} (criticality {h['criticality']}/10)"}
                             for h in at_risk if h["hop_distance"] == 1],
            "monitor_closely": [{"hostname": h["hostname"], "ip": h["ip"]} for h in at_risk if h["hop_distance"] == 2]},
        "highest_risk_path": at_risk[0]["attack_path"] if at_risk else None,
        "method": "bounded BFS over directed asset links; risk = criticality/hop heuristic",
    }


def export_graph_data(network: nx.DiGraph, highlight: str | None = None) -> dict:
    nodes = [{"id": n, **d, "compromised": n == highlight} for n, d in network.nodes(data=True)]
    edges = [{"source": s, "target": t, **d} for s, t, d in network.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


if __name__ == "__main__":
    from soar.db import session_scope
    host = sys.argv[1] if len(sys.argv) > 1 else ""
    with session_scope() as s:
        print(json.dumps(predict_blast_radius(host, build_graph(s), db=s), indent=2, default=str))
