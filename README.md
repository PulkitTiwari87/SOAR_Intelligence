# SOAR Intelligence

An AI-assisted Security Orchestration, Automation and Response platform you can run entirely on your own machine.
It ingests security events, correlates them into incidents, scores risk, maps MITRE ATT&CK, enriches indicators,
asks (optionally) an LLM for decision support, and runs **policy-gated, human-approved, verified** response playbooks,
with a full timeline and audit trail. Wazuh, TheHive, Cortex and MISP integrate optionally; none is required.

```
sources ─▶ normalize ─▶ correlate ─▶ enrich · ML triage · anomaly · MITRE · blast radius ─▶ risk score
                                                            │
                                    LLM commander (advice only) ─▶ response policy ─┬─▶ auto (low risk)
                                                                                    └─▶ human approval ─▶ playbook ─▶ verify ─▶ report
```

## Quick start (Docker)

```bash
git clone https://github.com/PulkitTiwari87/SOAR_Intelligence.git
cd SOAR_Intelligence
cp .env.example .env
# edit .env: POSTGRES_PASSWORD, JWT_SECRET (>= 32 chars), SOAR_ADMIN_PASSWORD (>= 10 chars), INGEST_API_KEY
docker compose up -d --build
```

Open <http://localhost:8080> and sign in as the admin from `.env`. Then generate incidents from safe synthetic attacks:

```bash
pip install -r requirements.txt      # only for the simulator CLI; the stack itself runs in Docker
python -m soar.cli simulate brute_force --url http://localhost:8000     # also: phishing, malware
```

You will see one correlated incident per scenario with ML, MITRE and timeline populated, low-risk playbook steps already
executed and verified, and a pending approval (`block_ip`, or `isolate_host` for the reverse shell) waiting for you.

## Quick start (no Docker)

```bash
pip install -r requirements-dev.txt && cp .env.example .env     # set SOAR_ADMIN_PASSWORD and INGEST_API_KEY
python -m uvicorn soar.main:app --port 8000                     # SQLite in ./data; migrations run at start-up
cd dashboard/frontend && npm ci && npm run dev                  # http://localhost:5173
```

Details: [DEVELOPMENT.md](DEVELOPMENT.md) · [DEPLOYMENT.md](DEPLOYMENT.md)

## What it does (all implemented and tested)

* **Event normalization** for Wazuh, syslog, network, email, MISP and generic events, raw event always preserved.
* **Correlation** by shared IPs (including IPs inside command lines), hosts, users, hashes, domains within a time window.
* **Risk score** from ML, severity, threat intel, asset criticality, correlation, anomaly, ATT&CK impact and history,
  with missing evidence excluded (not treated as safe) and reported as coverage.
* **ML**: triage (XGBoost + TreeSHAP), anomaly (Isolation Forest + extreme-deviation rule), phishing (text + URL/header
  indicators), log clustering, blast radius. See [AI_MODELS.md](AI_MODELS.md) for exactly what these numbers mean.
* **MITRE ATT&CK** mappings stored with source and confidence; LLM suggestions are validated and marked *inferred*.
* **Threat intel** via MISP and local feed files; results stored per indicator.
* **LLM incident commander** (Gemini, OpenAI, Anthropic, Ollama/local): schema-validated JSON, cannot execute anything.
* **Response**: playbooks with triggers/conditions/approval/verification/rollback; approvals recorded; protected
  targets can never be blocked. See [PLAYBOOKS.md](PLAYBOOKS.md).
* **Security**: bcrypt + JWT cookie sessions, four roles, CSRF header, rate limiting, audit log, non-root read-only
  containers. See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
* **Dashboard**: overview KPIs, filterable incidents, incident detail, approvals, threat intel, asset graph, playbooks,
  models, system health, audit and users.

## Read this honestly

* The ML models are trained on **synthetic or hand-written data** (no labelled real incidents ship with the repo); their
  metrics measure the mechanisms, not production accuracy. Retraining from analyst decisions is built in and guarded.
* `block_ip` records the block and exposes a feed (`/api/blocklist.txt`); something must consume it (or Wazuh active
  response must be configured) for traffic to actually be blocked. `isolate_host` and `disable_account` need a custom
  Wazuh command and are reported as *skipped* when absent; nothing pretends to succeed.
* The LLM path is unit-tested against mock transports; it has not been run against a live provider here (no key).
* **Verified** (see [docs/VERIFICATION.md](docs/VERIFICATION.md)): backend and frontend tests, lint, the frontend build,
  and the core Docker stack (image build, `docker compose up`, health/readiness, dashboard, auth enforced).
  **Statically validated only:** the optional SIEM overlay (`docker compose config`); it has never been started.
  **Not verified:** the SIEM overlay at runtime, a live LLM provider, and the CI workflow on GitHub.
* **Secrets from the original import remain in git history and must be rotated**
  (see [docs/SECURITY_REMEDIATION.md](docs/SECURITY_REMEDIATION.md)); nothing has been rotated by this repository.

## Documentation

[ARCHITECTURE](ARCHITECTURE.md) · [API](API.md) · [AI models](AI_MODELS.md) · [Playbooks](PLAYBOOKS.md) ·
[MITRE mapping](MITRE_MAPPING.md) · [Security](SECURITY.md) · [Threat model](THREAT_MODEL.md) ·
[Development](DEVELOPMENT.md) · [Deployment](DEPLOYMENT.md) · [Changelog](CHANGELOG.md) ·
[SIEM setup](docs/SIEM_SETUP.md) · [Verification](docs/VERIFICATION.md) ·
[Security remediation](docs/SECURITY_REMEDIATION.md)

Originally developed as an academic project (UPES, Cybersecurity & Digital Forensics). Repository layout:
`soar/` API and pipeline · `ai/` models · `dashboard/frontend/` UI · `integrations/`, `cortex/`, `configs/wazuh/`,
`scripts/` Wazuh/Cortex/agent assets · `migrations/` · `tests/`.
