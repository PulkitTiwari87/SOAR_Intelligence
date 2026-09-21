# Verification status

Recorded on 2026-09-21 on a Windows 11 development machine (Python 3.12.6, Node 22.12.0, Docker Desktop with
Docker 29.7.2 / Compose 5.5.1, 8 GB available to the Docker VM). A row is PASS only if the command in the
Evidence column was run and succeeded. Anything else is NOT RUN or NOT REMEDIATED, with the reason.

| Component | Status | Evidence |
|---|---|---|
| Backend tests (unit, API, auth, e2e scenarios, ML, LLM with stubs) | PASS | `python -m pytest`: 211 passed |
| Backend lint | PASS | `ruff check soar ai tests migrations integrations` |
| Backend static security scan | PASS | `bandit -q -r soar ai integrations cortex -ll`, exit 0 |
| Frontend lint | PASS | `npm run lint` in `dashboard/frontend`, 0 errors |
| Frontend tests (login, `useLoad`) | PASS | `npm test`: 9 passed (2 files). The "session not established" test fails when the `auth.jsx` fix is reverted |
| Frontend build | PASS | `npm run build` |
| Frontend dependency audit | PASS | `npm install` reported `found 0 vulnerabilities` |
| Python dependency audit | NOT RUN | `pip-audit` runs in CI only (`pip-audit -r requirements.txt`) |
| Private keys in tree | PASS | `git grep -nE 'BEGIN (RSA \|EC \|OPENSSH \|)PRIVATE KEY' -- . ':!*.md'` printed nothing |
| Secret scan with gitleaks | NOT RUN | Added to CI; not run locally (needs pulling the gitleaks image) |
| Secrets removed from git history | **NOT REMEDIATED** | `ad230ec` is still in history on `main` and origin. See `SECURITY_REMEDIATION.md` |
| Credentials rotated | **NOT DONE** | Only the owner can rotate them. See `SECURITY_REMEDIATION.md` |
| Docker daemon available | PASS | `docker info` returned server 29.7.2 (an earlier note that it would not start no longer applies) |
| Docker Compose static validation (core, and core + SIEM) | PASS | `docker compose config -q`, run by `scripts/verify-docker.sh`; a missing `POSTGRES_PASSWORD` is rejected |
| Docker image build (API, UI) | PASS | `scripts/verify-docker.sh`, step "image build" |
| Core stack startup with health checks | PASS | `scripts/verify-docker.sh` (`up -d --wait`): `/api/health` ok, `/api/ready` reports database up, dashboard serves `/`, unauthenticated `/api/auth/me` returns 401. Run in its own project (`soar-verify`) with throwaway secrets, then torn down |
| SIEM overlay startup (Wazuh, TheHive, Cortex, MISP) | NOT RUN | Needs ~10 GB RAM (Docker has ~8 GB here) and ports 443/9200/1514/55000, which another Wazuh stack on this machine already holds. Static config validation passes. Never started. Command: `scripts/verify-docker.sh --siem` |
| Live LLM provider | NOT RUN | No API key available. To run: set `LLM_PROVIDER` and `LLM_API_KEY` in `.env`, restart the API and request AI analysis of an incident; a rule-based fallback is labelled as such, so a live reply names its provider |
| LLM without a key (missing key, invalid config, HTTP failure, malformed output, retry, injection, redaction) | PASS | `tests/test_llm_commander.py` (part of the 211) |
| Login flow (success, failure, in-flight, no session) | PASS | `dashboard/frontend/src/login.test.jsx`, 5 tests |
| Login rate limiting shared across app instances | PASS | `tests/test_auth.py`: shared-between-instances, retry-after, reset-on-success, window and IP scoping |
| ML metrics on real-world data | NOT AVAILABLE | All reported metrics are computed on synthetic data; they say nothing about real-world detection performance |
| CI workflow (`.github/workflows/ci.yml`) | NOT RUN | Changes (secret scan, frontend tests) have not been executed on GitHub; needs a push |

## Changes this pass that these checks cover

* Login throttling moved from process memory to the shared audit log (`soar/api/auth.py`); `Retry-After`
  is returned with HTTP 429. Redis is not used: it is not part of the core stack, and PostgreSQL is already
  shared by every worker and container.
* Login no longer freezes on "Signing in…" when the password is accepted but the browser keeps no session
  cookie (typically `COOKIE_SECURE=true` over plain HTTP); it now says so.
* SIEM overlay: Wazuh manager paths and variables corrected for the 4.x image (`/var/ossec`, `INDEXER_URL`,
  `SSL_*`), health checks and `depends_on: service_healthy` added for Elasticsearch, Cassandra, MariaDB and Redis.
  These are static fixes; the overlay is still unrun.

## Reproduce

```bash
python -m pytest
ruff check soar ai tests migrations integrations
(cd dashboard/frontend && npm ci && npm run lint && npm test && npm run build)
scripts/verify-docker.sh          # needs a running Docker daemon
```

`scripts/verify-docker.sh` uses `.env` if present, otherwise generates throwaway secrets, and exits non-zero on
the first failed step.
