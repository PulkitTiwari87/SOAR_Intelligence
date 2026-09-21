# Security

## Reporting

Open a private security advisory on the repository (or contact the maintainer directly). Do not post exploits in
public issues.

## Controls in this codebase

* **AuthN**: bcrypt-hashed passwords (≥ 10 chars, ≤ 72 bytes), JWT sessions in an `httpOnly`, `SameSite=Strict`
  cookie (`Secure` via `COOKIE_SECURE`) or as a bearer token for API clients; logout revokes the token (`revoked_tokens`);
  the role is read from the database on every request, so demotion is immediate. Login is rate limited per IP+username
  (5 failures / 5 min by default, counted from the shared audit log so it holds across workers and containers;
  `LOGIN_MAX_ATTEMPTS`, `LOGIN_WINDOW_SECONDS`; 429 with `Retry-After`) and failures are indistinguishable for unknown users. No public registration:
  users are created by an admin or the CLI.
* **CSRF**: cookie-authenticated state-changing requests must carry `X-Requested-With`; CORS is an explicit allow-list.
* **RBAC**: `ADMIN`, `SOC_ANALYST`, `INCIDENT_RESPONDER`, `VIEWER` (matrix in `soar/domain.py`); high-risk approvals need
  `approve:high`.
* **Machine ingestion**: `X-API-Key` (constant-time compare) or a user token with `incident:write`.
* **Audit**: login/logout, user changes, ingestion, incident actions, approvals (including forbidden attempts),
  playbook runs, rollbacks, blocklist changes, asset changes, model retrains. Secrets in audit data are redacted.
* **Input**: pydantic validation on every body, SQLAlchemy parameterised queries, no shell or `eval`; report
  downloads are confined to the reports directory. The certificate checker accepts only strict public hostnames and
  refuses hosts resolving to non-public addresses (SSRF).
* **Secrets**: none in code; `.env` is git-ignored; production refuses to start without a ≥ 32-char `JWT_SECRET`;
  provider keys are never returned by the API. TLS verification is on for every outbound call unless
  `*_VERIFY_TLS=false` is set explicitly.
* **Containers**: non-root, read-only root filesystem, `no-new-privileges`, all capabilities dropped, ports bound to
  127.0.0.1, unprivileged nginx with a same-origin CSP.
* **Models**: integrity-checked artifacts, no pickle for the triage model.
* **CI**: ruff, bandit (medium+), `pip-audit`, `npm audit`, private-key grep, and a test that fails if the leaked
  literals from the original repository reappear.

## Problems found in the original repository and how they were resolved

| Finding | Resolution |
|---|---|
| Node backend built `python3 -c` source from request data (`hostname` in `/certificate` was an RCE) | Backend replaced; no code is generated from input |
| Anyone could register as `analyst`; `/initialize` let any user run a shell script | No public registration; endpoint removed |
| Hardcoded credentials/API keys in compose, routes and scripts | Removed; required from `.env`; compose fails fast |
| `verify=False` / `rejectUnauthorized:false` everywhere | TLS verified by default, opt-out per integration |
| Fake health data, `Math.random()` ML scores, fake CVE table, demo credentials on the login page | Removed; every figure is measured |
| Orchestrator "actions" were `sleep()`; the Cortex responder defaulted to agent `001` | Real actions with verification; no defaults, fails instead of guessing |
| Model pickles loaded without integrity checks; `os.system("pip install …")` at import | Hash-verified artifacts; no runtime installs |
| Committed archive containing a `.env` and Wazuh private keys | Archive removed |

## ⚠ Secrets that remain in git history

Commit `ad230ec` (the original import) still contains: the archive above (a `.env`, Wazuh CA/indexer/manager/admin
**private keys**), a TheHive API key default in `integrations/wazuh_to_thehive.py`, and the compose/route literals
listed in the table. History was intentionally not rewritten. **Treat all of them as compromised:** rotate the
TheHive/Cortex/MISP/Wazuh API keys and passwords, regenerate the Wazuh certificates
(`docker compose -f generate-certs.yml up`), and if the repository is public consider `git filter-repo` plus
a force-push (coordinate with collaborators) after rotating.

## Known limitations

* Concurrent failed logins can overshoot the limit by a few attempts (the count is read, not atomically reserved).
  Multi-worker operation of the rest of the pipeline has not been load-tested; the default is a single API worker.
* `block_ip` records intent in the SOAR blocklist; enforcement needs a consumer of `/api/blocklist.txt` or Wazuh
  active response. `isolate_host` / `disable_account` need a custom Wazuh command (`WAZUH_*_COMMAND`).
* The SIEM overlay uses the vendors' default indexer admin account and is a lab stack.
* JWT sessions last 8 h (`JWT_EXPIRE_MINUTES`); there is no refresh-token flow.
* No account-lockout policy beyond rate limiting; no MFA.
