# Architecture

SOAR Intelligence is one Python service (`soar/` + `ai/`), a React SPA, and PostgreSQL (SQLite for local
development). Wazuh, TheHive, Cortex and MISP are **optional** integrations, not dependencies.

```
 Sources                        soar-api (FastAPI)                                    Humans
 Wazuh alerts ─┐                ┌────────────────────────────────────────────┐
 syslog lines ─┤  POST          │ normalize → dedupe → persist               │        React SPA
 network events┼─ /api/events ─▶│   → correlate (or open) incident           │◀────── (cookie session,
 raw emails   ─┤  (API key or   │   → analyze: intel · ML triage · anomaly · │        RBAC, same-origin
 MISP attrs   ─┘   user token)  │       MITRE · blast radius · risk score    │        nginx proxy)
                                │   → response policy → playbooks            │
                                │        │ auto ─▶ execute → verify          │
                                │        │ approval ─▶ wait ──▶ human decides│
                                │   → timeline + audit log at every step     │
                                └────────────┬───────────────────────────────┘
                                             │ PostgreSQL (SQLite in dev)
                       optional: MISP · Wazuh active response · TheHive · LLM provider · webhook
```

## Modules

| Path | Responsibility |
|---|---|
| `soar/pipeline/normalizer.py` | Common event schema (`event_id`, `timestamp`, `source`, `event_type`, `severity`, IPs, hosts, `username`, `process`, `command`, `file_hash`, `domain`, `url`, `raw_event`, `metadata`). The raw payload is stored unchanged; `event_id` is a hash so re-sending is idempotent. |
| `soar/pipeline/correlation.py` | Weighted entity matching within a time window (see below). |
| `soar/pipeline/analysis.py` | Orchestrates enrichment → ML → MITRE → blast radius → risk → auto-playbooks. A failing stage is logged and skipped. |
| `soar/pipeline/risk.py` | The single risk score (see below). |
| `soar/pipeline/mitre.py` | ATT&CK catalog subset and mapping rules ([MITRE_MAPPING.md](MITRE_MAPPING.md)). |
| `soar/intel/enrich.py` | IOC enrichment: private-scope, local feed files, MISP. Results stored in `threat_intel`. |
| `soar/playbooks/` | Policy gate, actions, engine, built-in playbooks ([PLAYBOOKS.md](PLAYBOOKS.md)). |
| `soar/api/` | Thin routers: transport, RBAC, audit. Business logic lives in the modules above. |
| `ai/` | Models and the LLM commander ([AI_MODELS.md](AI_MODELS.md)). |
| `migrations/` | Alembic. The app applies them at start-up (non-test environments). |

## Correlation

An event joins an open incident when the summed weight of shared entities reaches `CORRELATION_THRESHOLD`
(default 3.0) inside `CORRELATION_WINDOW_MINUTES` (30): file hash 4, external IP 3, domain 3, internal IP 2,
host 2, user 1 (generic accounts such as `root` 0.5), rule id 0.5. IPs mentioned in a command line count, so a
reverse-shell alert and the outbound connection to the same address become one incident. Loopback, unspecified,
multicast and link-local addresses never correlate. Events below severity *medium* are stored (baselines,
context) but do not open incidents. Incidents are never auto-merged. Limitation: incident numbers and matching are
race-safe only for a single API worker (unique-number retry protects numbering).

## Risk score

`risk = 100 · Σ wᵢsᵢ / Σ wᵢ` over the signals that are **available** (each in 0..1): ML 0.25, severity 0.20,
IOC 0.15, asset criticality 0.15, correlation 0.10, anomaly 0.05, MITRE tactic impact 0.05, history 0.05.
A missing signal (no intel yet, unknown asset) is excluded rather than counted as zero; the fraction of weight
that was available is stored as `confidence` ("evidence coverage"). Severity cut-offs: ≥80 critical, ≥60 high,
≥35 medium. **The weights are expert defaults and have not been validated against labelled incidents.**

## State machines

Incident, execution, step and approval statuses are explicit (`soar/domain.py`); invalid transitions raise.
`closed` is terminal. Approvals are claimed with a conditional `UPDATE … WHERE status='pending'`, so a retry or a
double click cannot run a step twice. Steps that are not `pending` are never re-run (at-most-once per step).

## Data model

`users`, `assets`/`asset_links`, `events`, `incidents` (+ `incident_iocs`), `iocs`, `threat_intel`,
`mitre_mappings`, `model_predictions` (triage, anomaly, blast_radius, llm_commander), `playbooks`,
`playbook_executions`, `execution_steps`, `approvals`, `analyst_actions`, `timeline_entries`, `blocklist`,
`notifications`, `audit_logs`, `revoked_tokens`. Datetimes are UTC.

## Deliberate non-goals

* Redis is not used by the platform (only by MISP in the SIEM overlay). Login throttling is derived from the
  audit log in the shared database, so workers and containers see the same failure counts. Running more than
  one API worker has not been load-tested beyond that; the default is one.
* No message queue: ingestion is synchronous; the LLM commander is the only step that can be deferred.
* No full asset discovery: assets come from you, `seed-demo` (dev only) or future Wazuh sync.
