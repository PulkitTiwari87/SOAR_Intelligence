#!/usr/bin/env python3
"""
Module 3.6: Blast Radius Predictor
=====================================
Models the network topology as a graph and predicts lateral
movement risk when a host is compromised.

Uses NetworkX for graph analysis with BFS traversal and
PageRank-based risk scoring to identify high-value targets.
"""

import json
import os
import sys
from collections import defaultdict

try:
    import networkx as nx
except ImportError:
    os.system("pip install networkx")
    import networkx as nx


def build_sample_network() -> nx.DiGraph:
    """
    Build a sample enterprise network topology graph.
    In production, this would be populated from:
      - Wazuh agent list (API: GET /agents)
      - Network flow logs
      - Asset inventory / CMDB
    """
    G = nx.DiGraph()

    # Add hosts with attributes
    hosts = {
        "kali-vm-01":     {"ip": "192.168.64.9",  "os": "Linux",   "role": "workstation", "criticality": 3},
        "web-server-01":  {"ip": "192.168.64.10", "os": "Linux",   "role": "web_server",  "criticality": 7},
        "db-server-01":   {"ip": "192.168.64.11", "os": "Linux",   "role": "database",    "criticality": 9},
        "file-server-01": {"ip": "192.168.64.12", "os": "Windows", "role": "file_server",  "criticality": 8},
        "dc-01":          {"ip": "192.168.64.13", "os": "Windows", "role": "domain_ctrl",  "criticality": 10},
        "dev-laptop-01":  {"ip": "192.168.64.14", "os": "macOS",   "role": "workstation", "criticality": 4},
        "dev-laptop-02":  {"ip": "192.168.64.15", "os": "macOS",   "role": "workstation", "criticality": 4},
        "mail-server-01": {"ip": "192.168.64.16", "os": "Linux",   "role": "mail_server",  "criticality": 7},
        "backup-srv-01":  {"ip": "192.168.64.17", "os": "Linux",   "role": "backup",      "criticality": 8},
    }

    for hostname, attrs in hosts.items():
        G.add_node(hostname, **attrs)

    # Add connections (edges) — representing network flows / access patterns
    connections = [
        ("kali-vm-01",     "web-server-01",  {"protocol": "HTTP",  "port": 80}),
        ("kali-vm-01",     "file-server-01", {"protocol": "SMB",   "port": 445}),
        ("kali-vm-01",     "dc-01",          {"protocol": "LDAP",  "port": 389}),
        ("web-server-01",  "db-server-01",   {"protocol": "MySQL", "port": 3306}),
        ("web-server-01",  "mail-server-01", {"protocol": "SMTP",  "port": 25}),
        ("file-server-01", "backup-srv-01",  {"protocol": "rsync", "port": 873}),
        ("file-server-01", "dc-01",          {"protocol": "LDAP",  "port": 389}),
        ("dev-laptop-01",  "web-server-01",  {"protocol": "HTTP",  "port": 80}),
        ("dev-laptop-01",  "file-server-01", {"protocol": "SMB",   "port": 445}),
        ("dev-laptop-02",  "web-server-01",  {"protocol": "HTTP",  "port": 80}),
        ("dev-laptop-02",  "db-server-01",   {"protocol": "SSH",   "port": 22}),
        ("mail-server-01", "dc-01",          {"protocol": "LDAP",  "port": 389}),
        ("dc-01",          "backup-srv-01",  {"protocol": "rsync", "port": 873}),
    ]

    G.add_edges_from(connections)
    return G


def predict_blast_radius(compromised_host: str, network: nx.DiGraph = None, max_hops: int = 3) -> dict:
    """
    Predict the blast radius of a compromised host.

    Args:
        compromised_host: Hostname of the infected machine.
        network: NetworkX graph of the network. Uses sample if None.
        max_hops: Maximum lateral movement depth to analyze.

    Returns:
        Dict with at-risk hosts, attack paths, and isolation recommendations.
    """
    if network is None:
        network = build_sample_network()

    if compromised_host not in network:
        return {"error": f"Host '{compromised_host}' not found in network topology."}

    # BFS from compromised host to find reachable nodes by hop count
    at_risk_hosts = defaultdict(list)
    visited = set()
    queue = [(compromised_host, 0, [compromised_host])]

    while queue:
        current, depth, path = queue.pop(0)
        if depth > max_hops:
            continue
        if current in visited:
            continue
        visited.add(current)

        if current != compromised_host:
            host_data = network.nodes[current]
            edge_data = network.get_edge_data(path[-2], current) or {}
            at_risk_hosts[depth].append({
                "hostname": current,
                "ip": host_data.get("ip"),
                "os": host_data.get("os"),
                "role": host_data.get("role"),
                "criticality": host_data.get("criticality", 0),
                "access_protocol": edge_data.get("protocol", "unknown"),
                "access_port": edge_data.get("port", 0),
                "attack_path": " → ".join(path),
            })

        for neighbor in network.successors(current):
            if neighbor not in visited:
                queue.append((neighbor, depth + 1, path + [neighbor]))

    # Calculate overall risk score using PageRank
    pagerank = nx.pagerank(network)

    # Build risk assessment
    all_at_risk = []
    for hop, hosts in sorted(at_risk_hosts.items()):
        for host in hosts:
            host["hop_distance"] = hop
            host["pagerank"] = round(pagerank.get(host["hostname"], 0), 4)
            # Risk = criticality * (1 / hop_distance) * pagerank_normalized
            host["risk_score"] = round(
                host["criticality"] * (1 / hop) * (host["pagerank"] * 100), 2
            )
            all_at_risk.append(host)

    # Sort by risk score descending
    all_at_risk.sort(key=lambda x: x["risk_score"], reverse=True)

    # Isolation recommendations
    isolate_immediately = [h for h in all_at_risk if h["risk_score"] > 5 and h["hop_distance"] == 1]
    monitor_closely = [h for h in all_at_risk if h["hop_distance"] <= 2 and h not in isolate_immediately]

    compromised_info = network.nodes[compromised_host]

    return {
        "compromised_host": {
            "hostname": compromised_host,
            "ip": compromised_info.get("ip"),
            "os": compromised_info.get("os"),
            "role": compromised_info.get("role"),
        },
        "total_at_risk": len(all_at_risk),
        "at_risk_hosts": all_at_risk,
        "recommendations": {
            "isolate_immediately": [
                {"hostname": h["hostname"], "ip": h["ip"], "reason": f"Direct access via {h['access_protocol']} (criticality: {h['criticality']}/10)"}
                for h in isolate_immediately
            ],
            "monitor_closely": [
                {"hostname": h["hostname"], "ip": h["ip"]}
                for h in monitor_closely
            ],
        },
        "highest_risk_path": all_at_risk[0]["attack_path"] if all_at_risk else "N/A",
    }


def export_graph_data(network: nx.DiGraph = None) -> dict:
    """Export graph data in a format suitable for dashboard visualization."""
    if network is None:
        network = build_sample_network()

    nodes = []
    for node, data in network.nodes(data=True):
        nodes.append({"id": node, **data})

    edges = []
    for src, dst, data in network.edges(data=True):
        edges.append({"source": src, "target": dst, **data})

    return {"nodes": nodes, "edges": edges}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        host = sys.argv[2] if len(sys.argv) > 2 else "kali-vm-01"
        result = predict_blast_radius(host)
        print(json.dumps(result, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "--graph":
        graph_data = export_graph_data()
        print(json.dumps(graph_data, indent=2))
    else:
        print("Usage:")
        print("  python blast_radius_predictor.py --test [hostname]")
        print("  python blast_radius_predictor.py --graph")
