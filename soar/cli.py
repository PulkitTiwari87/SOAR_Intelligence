"""Command line entry points:  python -m soar.cli <command>

  create-user <username> <ROLE>   create a user (prompts for the password; never on the command line)
  train-models                    (re)train triage, anomaly and phishing models and print evaluations
  seed-demo                       DEVELOPMENT ONLY: register a sample asset topology
  simulate <scenario> [--url U]   send a safe synthetic scenario (brute_force | phishing | malware)
  migrate                         apply database migrations
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from soar import security
from soar.bootstrap import run_migrations
from soar.config import get_settings
from soar.db import session_scope
from soar.domain import Role
from soar.models import Asset, AssetLink, User

DEMO_ASSETS = [  # dev-only sample network; never loaded automatically
    ("kali-vm-01", "192.168.64.9", "Linux", "workstation", 3), ("web-server-01", "192.168.64.10", "Linux", "web_server", 7),
    ("db-server-01", "192.168.64.11", "Linux", "database", 9), ("file-server-01", "192.168.64.12", "Windows", "file_server", 8),
    ("dc-01", "192.168.64.13", "Windows", "domain_controller", 10), ("mail-server-01", "192.168.64.16", "Linux", "mail_server", 7),
    ("backup-srv-01", "192.168.64.17", "Linux", "backup", 8)]
DEMO_LINKS = [("kali-vm-01", "web-server-01", "http", 80), ("kali-vm-01", "file-server-01", "smb", 445),
              ("web-server-01", "db-server-01", "mysql", 3306), ("web-server-01", "mail-server-01", "smtp", 25),
              ("file-server-01", "backup-srv-01", "rsync", 873), ("file-server-01", "dc-01", "ldap", 389),
              ("mail-server-01", "dc-01", "ldap", 389), ("dc-01", "backup-srv-01", "rsync", 873)]


def cmd_create_user(a: argparse.Namespace) -> int:
    pw = getpass.getpass("Password (min 10 chars): ")
    if pw != getpass.getpass("Repeat password: "):
        print("Passwords do not match", file=sys.stderr)
        return 1
    run_migrations()
    with session_scope() as db:
        if db.query(User).filter_by(username=a.username).first():
            print("User already exists", file=sys.stderr)
            return 1
        db.add(User(username=a.username, password_hash=security.hash_password(pw), role=Role(a.role).value))
    print(f"Created {a.username} ({a.role})")
    return 0


def cmd_train(_: argparse.Namespace) -> int:
    from ai.anomaly import isolation_forest_detector as an
    from ai.phishing import nlp_phishing_parser as ph
    from ai.triage import ml_triage_analyzer as tr
    out = {n: m.train_model()["evaluation"] for n, m in (("triage", tr), ("anomaly", an), ("phishing", ph))}
    print(json.dumps(out, indent=2))
    return 0


def cmd_seed(_: argparse.Namespace) -> int:
    if get_settings().env == "production":
        print("Refusing to seed demo data in production", file=sys.stderr)
        return 1
    run_migrations()
    with session_scope() as db:
        by_name = {}
        for host, ip, os_, role, crit in DEMO_ASSETS:
            a = db.query(Asset).filter_by(hostname=host).first() or Asset(hostname=host, source="seed")
            a.ip, a.os, a.role, a.criticality = ip, os_, role, crit
            db.add(a)
            by_name[host] = a
        db.flush()
        for s, d, proto, port in DEMO_LINKS:
            if not db.query(AssetLink).filter_by(src_id=by_name[s].id, dst_id=by_name[d].id, protocol=proto, port=port).first():
                db.add(AssetLink(src_id=by_name[s].id, dst_id=by_name[d].id, protocol=proto, port=port))
    print(f"Seeded {len(DEMO_ASSETS)} assets and {len(DEMO_LINKS)} links (development data)")
    return 0


def cmd_simulate(a: argparse.Namespace) -> int:
    import httpx
    from soar.simulate import SCENARIOS
    s = get_settings()
    if not s.ingest_api_key:
        print("Set INGEST_API_KEY (same value the API uses) to send events", file=sys.stderr)
        return 1
    for source, payload in SCENARIOS[a.scenario]():
        r = httpx.post(f"{a.url.rstrip('/')}/api/events", json={"source": source, "payload": payload},
                       headers={"X-API-Key": s.ingest_api_key}, timeout=60)
        res = r.json()["results"][0] if r.status_code == 200 else {"http": r.status_code}
        print(source, "->", res.get("incident_number") or res)
    return 0


def cmd_migrate(_: argparse.Namespace) -> int:
    run_migrations()
    print("Database is up to date")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soar")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("create-user")
    u.add_argument("username")
    u.add_argument("role", choices=[r.value for r in Role])
    u.set_defaults(fn=cmd_create_user)
    sub.add_parser("train-models").set_defaults(fn=cmd_train)
    sub.add_parser("seed-demo").set_defaults(fn=cmd_seed)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    sm = sub.add_parser("simulate")
    sm.add_argument("scenario", choices=["brute_force", "phishing", "malware"])
    sm.add_argument("--url", default="http://localhost:8000")
    sm.set_defaults(fn=cmd_simulate)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
