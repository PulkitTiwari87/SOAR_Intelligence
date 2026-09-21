# SIEM overlay setup (Wazuh, TheHive, Cortex, MISP)

> **Status: NOT VERIFIED. Blocked by environment.** `docker-compose.siem.yml` passes `docker compose config`
> (static validation) but the stack has **never been started**. The commands below are the intended procedure;
> every "expected" result is an expectation, not an observation. The core platform (API, UI, PostgreSQL) does
> not need any of this and *has* been built and started (see `VERIFICATION.md`).

## What it adds

| Service | Purpose | Local address |
|---|---|---|
| `wazuh.manager` | Wazuh manager and API | agents on 1514/1515, syslog 514/udp, API `https://127.0.0.1:55000` |
| `wazuh.indexer` | Wazuh indexer (OpenSearch) | `https://127.0.0.1:9200` |
| `wazuh.dashboard` | Wazuh UI | `https://127.0.0.1:443` |
| `elasticsearch`, `cassandra` | TheHive and Cortex storage | internal |
| `thehive`, `cortex` | Case management, analyzers/responders | `http://127.0.0.1:9000`, `http://127.0.0.1:9001` |
| `misp` (+ `misp-db`, `misp-redis`) | Threat-intel platform | `http://127.0.0.1:8081` |

It is a lab stack, not hardened for exposure beyond localhost.

## Prerequisites

* Docker with Compose v2 and **about 10 GB of RAM available to Docker** (Docker Desktop: Settings → Resources).
* Free host ports: 443, 514/udp, 1514, 1515, 9000, 9001, 9200, 8081, 55000. If another Wazuh stack is already
  running on the machine, stop it or the ports will collide.
* Kernel setting for the indexer and Elasticsearch: `vm.max_map_count >= 262144`.
  Linux: `sudo sysctl -w vm.max_map_count=262144`. Docker Desktop on Windows:
  `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`.
* Wazuh certificates generated locally (see Configuration).

## Configuration

```bash
cp .env.example .env
```

Set, in `.env`, in addition to the core values (`POSTGRES_PASSWORD`, `JWT_SECRET`):

| Variable | Used by |
|---|---|
| `WAZUH_INDEXER_ADMIN_PASSWORD` | manager and dashboard connection to the indexer |
| `WAZUH_API_PASSWORD` | Wazuh API user `wazuh-wui` |
| `THEHIVE_SECRET` | TheHive play secret |
| `MISP_DB_PASSWORD`, `MISP_ADMIN_PASSPHRASE` | MISP |

`docker compose` refuses to start with any of these unset. Generate values with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`. Never commit `.env`.

**Known open item.** `Dockerfile.indexer` does not set the indexer's `admin` password from
`WAZUH_INDEXER_ADMIN_PASSWORD`; it only supplies the value to the manager and dashboard. Unless you also
re-hash the indexer's `internal_users.yml` with the Wazuh password tool, the value must match what the indexer
image ships with, or the manager's Filebeat cannot authenticate. The dashboard's `kibanaserver` account is
likewise the vendor default (`WAZUH_DASHBOARD_PASSWORD`). Resolve this before relying on the stack.

Generate the Wazuh certificates once (writes `./wazuh-certificates/`, which is git-ignored):

```bash
docker compose -f generate-certs.yml run --rm generator
```

## Start

```bash
docker compose -f docker-compose.yml -f docker-compose.siem.yml up -d --build
```

Or let the verification script start it and report each check: `scripts/verify-docker.sh --siem`
(also not yet run by the author).

Static check that works without starting anything:

```bash
docker compose -f docker-compose.yml -f docker-compose.siem.yml config -q
```

## Health verification (expected results)

```bash
docker compose -f docker-compose.yml -f docker-compose.siem.yml ps   # elasticsearch, cassandra, misp-db, misp-redis: healthy
```

Health checks exist for Elasticsearch, Cassandra, MariaDB and Redis, and `thehive`, `cortex` and `misp` wait for
them. The Wazuh services and TheHive/Cortex/MISP themselves have **no** health check; give them several minutes
and read their logs. TheHive and Cortex in particular are slow on first start.

## API verification (expected results)

```bash
curl -k -u "admin:$WAZUH_INDEXER_ADMIN_PASSWORD" https://127.0.0.1:9200/_cluster/health
curl -k -u "wazuh-wui:$WAZUH_API_PASSWORD" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"   # prints a JWT
curl -s http://127.0.0.1:9000/api/status        # TheHive: JSON with versions
curl -s http://127.0.0.1:9001/api/status        # Cortex: JSON with versions
curl -sI http://127.0.0.1:8081/users/login      # MISP: HTTP 200
```

Then connect the platform by setting `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS`, `WAZUH_INDEXER_*`,
`THEHIVE_URL`, `THEHIVE_API_KEY`, `CORTEX_URL`, `MISP_URL` and `MISP_API_KEY` in `.env` (see `.env.example`).
The SOAR UI's System page reports each integration as configured or not. `configs/wazuh/integration.conf`
shows how to forward Wazuh alerts to the SOAR API.

## Shutdown and cleanup

```bash
docker compose -f docker-compose.yml -f docker-compose.siem.yml down       # stop, keep data
docker compose -f docker-compose.yml -f docker-compose.siem.yml down -v    # stop and DELETE all volumes
```

`down -v` also deletes the core platform's PostgreSQL data and evidence volumes.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `bind: address already in use` | Another stack holds 443/9200/1514/55000; stop it or change the mapping |
| Indexer or Elasticsearch exits immediately | `vm.max_map_count` too low, or not enough memory for Docker |
| Manager cannot reach the indexer / Filebeat auth errors | Indexer `admin` password does not match `WAZUH_INDEXER_ADMIN_PASSWORD` (open item above), or certificate names differ from `./wazuh-certificates/` |
| Indexer `Permission denied` on certificates | Regenerate certificates, then rebuild: `docker compose ... build --no-cache wazuh.indexer` (they are copied at build time) |
| TheHive restarts repeatedly | Cassandra/Elasticsearch not healthy yet; wait, then `docker compose ... logs thehive` |
| Anything else | `docker compose -f docker-compose.yml -f docker-compose.siem.yml logs -f <service>` |
