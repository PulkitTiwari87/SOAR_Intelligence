# Deployment

## Core stack (API + UI + PostgreSQL)

```bash
cp .env.example .env
#   set at least: POSTGRES_PASSWORD, JWT_SECRET (>= 32 chars), SOAR_ADMIN_PASSWORD (>= 10 chars), INGEST_API_KEY
#   use URL-safe secrets:  python -c "import secrets; print(secrets.token_urlsafe(32))"
docker compose up -d --build          # first build trains the bundled models (~1-2 min)
docker compose ps                     # postgres, soar-api and soar-ui should become "healthy"
```

UI: <http://localhost:8080> (sign in as `SOAR_ADMIN_USERNAME`). API: <http://localhost:8000/api/health>. Both ports are
bound to 127.0.0.1. Missing required variables abort `docker compose up` with a message naming the variable.

Send a test scenario (needs Python locally, or use the `curl` example in [API.md](API.md)):

```bash
python -m soar.cli simulate brute_force --url http://localhost:8000     # also: phishing, malware
```

The brute-force scenario ends with a pending `block_ip` approval and the reverse-shell scenario with a pending
`isolate_host` approval; decide them under **Approvals**.

## Optional SIEM overlay (Wazuh, TheHive, Cortex, MISP)

Lab-grade, needs roughly 10 GB RAM, and is **not exercised by automated tests**.

```bash
docker compose -f generate-certs.yml up          # once: writes ./wazuh-certificates (git-ignored)
# set WAZUH_INDEXER_ADMIN_PASSWORD, WAZUH_API_PASSWORD, THEHIVE_SECRET, MISP_DB_PASSWORD, MISP_ADMIN_PASSPHRASE in .env
docker compose -f docker-compose.yml -f docker-compose.siem.yml up -d --build
```

Connect Wazuh to SOAR: copy `integrations/custom-soar` into the manager's `/var/ossec/integrations/`, paste
`configs/wazuh/integration.conf` into `ossec.conf` (with your `INGEST_API_KEY` as `<api_key>`), optionally add
`configs/wazuh/rules/custom_rules.xml` to the local rules, and restart the manager. To let SOAR call Wazuh's API set
`WAZUH_API_URL/USER/PASS` (and `WAZUH_VERIFY_TLS=false` only for the lab's self-signed certificate). Enrichment needs
`MISP_URL` + `MISP_API_KEY`; cases need `THEHIVE_URL` + `THEHIVE_API_KEY`. Agents: `scripts/agent_install.sh`.

## Production notes

* `SOAR_ENV=production` (compose default) disables `/api/docs` and demands a strong `JWT_SECRET`. Put a TLS-terminating
  reverse proxy in front and set `COOKIE_SECURE=true`.
* Login rate limiting is stored in the shared database, so it holds across workers and containers
  (`LOGIN_MAX_ATTEMPTS`, `LOGIN_WINDOW_SECONDS`; a blocked login gets HTTP 429 with a `Retry-After` header).
  Multi-worker operation of the rest of the pipeline has not been load-tested; the default is **one** API worker.
* State: named volumes `soar-pg` (PostgreSQL), `soar-data` (evidence, reports, feeds, custom playbooks) and
  `soar-models` (models, seeded from the image, written by retraining). Back up with
  `docker compose exec postgres pg_dump -U soar soar > backup.sql` and archive the volumes.
* Upgrades: rebuild and restart; migrations run automatically at API start.
* Logs are JSON on stdout (`docker compose logs -f soar-api`); `/api/health` (liveness), `/api/ready` (database) and
  `/api/system/metrics` (counters and latencies) are available for monitoring.
* Threat-intel feeds: put one indicator per line in `data/intel/*.txt` (mounted volume). Custom playbooks:
  `data/playbooks/*.json` ([PLAYBOOKS.md](PLAYBOOKS.md)).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `required variable … is missing a value` | Set it in `.env`; the message names it |
| API unhealthy on start | `docker compose logs soar-api`; production refuses a missing/short `JWT_SECRET` |
| Cannot log in on the first start | The admin is created only when the users table is empty; use `docker compose exec soar-api python -m soar.cli create-user <name> ADMIN` |
| `/api` 502 in `npm run dev` | Backend not running on 127.0.0.1:8000 |
| Blocks "do nothing" | Expected: consume `/api/blocklist.txt` or configure Wazuh active response (see [PLAYBOOKS.md](PLAYBOOKS.md)) |
