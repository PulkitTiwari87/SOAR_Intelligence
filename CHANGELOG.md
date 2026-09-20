# Changelog

## 2.0.0 (unreleased)

Complete rework of the repository into a locally runnable AI-assisted SOAR platform.

### Added
* FastAPI engine (`soar/`): event normalization (Wazuh, syslog, network, email, MISP, generic), weighted incident
  correlation, transparent risk scoring, MITRE mapping with per-mapping source, threat-intel enrichment (MISP + local
  feeds), incident timeline, PDF reports, blast radius from an asset inventory.
* Response layer: policy gate, executable playbooks, human approvals (recorded, atomically claimed), verification,
  rollback, blocklist feed, Wazuh active-response and TheHive connectors.
* Auth: bcrypt + JWT (httpOnly cookie or bearer), RBAC with four roles, CSRF header, rate limiting, audit log.
* PostgreSQL/SQLite persistence with Alembic migrations.
* LLM incident commander with provider abstraction (Gemini, OpenAI, Anthropic, Ollama/OpenAI-compatible), schema
  validation and a labelled deterministic fallback.
* React dashboard: overview, incidents (filters, detail), approvals, threat intel, assets graph, playbooks, models,
  system, admin.
* Docker: non-root API and UI images, PostgreSQL compose stack, optional SIEM overlay, health checks.
* CI (lint, tests, bandit, pip-audit, npm audit, compose validation, image builds), safe attack simulations, 197 tests.

### Changed
* ML triage retrained without label leakage and evaluated on a held-out shifted sample (previous "100% accuracy" was an
  artefact); anomaly detector threshold calibrated on the baseline plus an extreme-deviation rule; phishing analyzer
  gained URL/domain/header analysis and explanations; models are versioned, hash-verified artifacts.
* Playbook optimizer and feedback loop use stored data only (no synthetic history); retraining is guarded.

### Removed
* Node/Express/MongoDB backend, `orchestrator.py` (simulated actions), fake-data pages, mock threat intel, the committed
  archive with secrets, generated notebook duplicates, hardcoded credentials and always-off TLS verification.

### Fixed
* Injection paths in the old bridge, self-assigned privileges, `NameError` in the demo orchestrator, a missing import in
  the feedback loop, Cortex responder defaulting to agent `001`, unusable compose (`external` volume, `localhost` service
  addresses).

### Security notes
See [SECURITY.md](SECURITY.md): secrets committed in the original import remain in history and must be rotated.
