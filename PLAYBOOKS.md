# Playbooks, response policy and approvals

## Flow

```
trigger + conditions match ─▶ create execution ─▶ for each step:
   response policy ─┬─ deny ──▶ step skipped (reason recorded), continue
                    ├─ auto ──▶ execute ─▶ verify ─▶ record
                    └─ approval ─▶ approval row + execution pauses (incident: awaiting_approval)
                                    └─ human decides ─▶ approved: execute, verify, continue │ rejected: stop
```

Everything (approval requested, decision, action result, verification) is written to the incident timeline;
approval decisions and rollbacks are also audit-logged.

## Response policy (`soar/playbooks/policy.py`)

| Action | Risk | Real effect |
|---|---|---|
| `enrich_ioc` | low | Threat-intel lookup, results stored. |
| `notify_analyst` | low | In-app notification; optional `NOTIFY_WEBHOOK_URL`. |
| `collect_evidence` | low | JSON snapshot in `data/evidence/<incident>/` with SHA-256; verification re-hashes the file. |
| `create_case` | low | TheHive alert **if configured**; otherwise `skipped` (the incident is the case). |
| `block_ip` | medium | Adds to the SOAR blocklist (feed at `/api/blocklist.txt`); dispatches Wazuh `firewall-drop` if configured. **It does not enforce a network block by itself**: a firewall/agent must consume the feed. Reversible. |
| `isolate_host` | high | Dispatches the Wazuh active-response command named in `WAZUH_ISOLATE_COMMAND`; `skipped` when not configured. |
| `disable_account` | high | Same, via `WAZUH_DISABLE_ACCOUNT_COMMAND`. |

* Auto-execution ceiling: `AUTO_EXECUTE_MAX_RISK` (`none|low|medium`, default **low**, so `block_ip` waits for approval). `high` always needs a human.
* Protected targets can never be blocked: private/loopback/link-local/multicast/reserved addresses and `PROTECTED_IPS`.
* A step may set `"approval": "required"`, which can only tighten the outcome; deny rules still apply after approval.
* Permissions: `SOC_ANALYST` may decide medium-risk approvals; high-risk needs `INCIDENT_RESPONDER` or `ADMIN`.
* An action never reports success it did not achieve: results are `succeeded`, `skipped` (no data / no connector) or `failed`, and verification is `yes`, `FAILED` or `n/a` (cannot be checked from here).

## Built-in playbooks

`ssh_brute_force_response` (auth failures, risk ≥ 50, external source IP): enrich, evidence, notify, block, case ·
`phishing_response` (risk ≥ 40): enrich, evidence, notify, case · `suspicious_process_response` (risk ≥ 60): evidence,
enrich, notify, **isolate (approval always required)**, case · `high_risk_triage` (risk ≥ 75): evidence, notify.
Each auto-runs at most once per incident.

## Writing your own

Drop JSON into `<DATA_DIR>/playbooks/*.json` (loaded at start-up, validated, invalid files logged and ignored):

```json
{ "name": "my_playbook", "version": 1, "description": "…",
  "trigger": {"event_types": ["authentication_failure"], "min_risk": 50, "min_severity": 3, "mitre": ["T1110"]},
  "conditions": [{"field": "has_external_source_ip", "op": "eq", "value": true}],
  "steps": [{"id": "block", "action": "block_ip", "params": {"ip": "$incident.primary_source_ip"}, "approval": "policy"}] }
```

Condition fields: `risk_score, severity, event_count, category, event_types, primary_source_ip, primary_host,
primary_user, has_external_source_ip, mitre_ids, ioc_malicious`. Operators: `eq ne gt gte lt lte in contains`.
A playbook with an empty trigger never auto-runs but can be started from the incident page.

## Rollback

`POST /api/executions/{id}/rollback` (or the incident page) reverses reversible steps (`block_ip` → unblock).
A Wazuh active-response block expires on its own timeout and is not reversed by SOAR.
