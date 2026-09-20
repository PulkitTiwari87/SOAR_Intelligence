# Threat model

Scope: the SOAR API, its UI, its database and its outbound integrations. Assets that matter: the integrity of
incident/audit data, the response actions the platform can trigger, credentials for integrated systems, and the
analyst session.

## Trust boundaries

```
Log sources ──(API key)──▶ [ingestion] ─ untrusted event content (attacker-influenced!)
Browser ──(cookie+CSRF header)──▶ nginx ──▶ API ──▶ PostgreSQL
API ──▶ MISP / Wazuh / TheHive / LLM provider   (outbound, credentials from env)
```

**Log and email content is attacker-controlled.** It is parsed, stored and displayed, and sent to the LLM.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Forged alerts to trigger blocks/isolation (response abuse) | Ingest needs an API key/role; protected targets can never be blocked; medium/high actions need approval; every step audited and reversible where possible | A valid key can still create noisy incidents |
| Attacker-crafted logs cause a harmful block (e.g. block the gateway/DNS) | Private/loopback/reserved ranges and `PROTECTED_IPS` are undeniable-deny; TTL on blocks; rollback | A spoofed public IP that a partner uses can still be blocked after approval |
| Prompt injection via log/email text | Output schema + action allow-list + policy gate; model has no tools; untrusted text is delimited | The *summary* text can still be misleading: it is labelled as model output |
| Session theft (XSS) | `httpOnly` cookie, CSP `script-src 'self'`, no inline scripts, React escaping | Third-party npm supply chain |
| CSRF | `SameSite=Strict` + required custom header + explicit CORS | – |
| Credential stuffing | bcrypt, per IP+user rate limit, uniform errors | Per-process limiter; no MFA |
| Privilege escalation | Role read from DB per request; no self-registration; last admin cannot be demoted | – |
| SSRF via the certificate checker / integrations | Strict hostname regex + public-address check; integration URLs are admin-configured only | DNS rebinding between check and connect is mitigated by connecting to the vetted address |
| Path traversal in report download | Resolved path must be a `.pdf` directly inside the reports directory | – |
| Tampered ML artifacts | SHA-256 verified before load; native XGBoost format | An attacker who can write both file and metadata |
| Secret leakage | No secrets in repo/images; redacted audit data; provider keys never returned | Historical commit `ad230ec` (see SECURITY.md) |
| Duplicate/late execution | Idempotent event ids; at-most-once steps; atomic approval claim; at-least-once *ingestion* is safe | A crash mid-step leaves it `running` and it is not retried (fails the execution) |
| Denial of service | Batch cap (200), field length caps, bounded LLM timeouts | No global rate limit or body-size limit beyond nginx's 4 MB |
| Tampered audit trail | Append-only by convention (no update/delete API) | A database administrator can edit rows; ship logs off-host for stronger guarantees |

## Out of scope

Compromise of the host, Docker daemon or database credentials; the security of Wazuh/TheHive/Cortex/MISP themselves;
physical attacks; multi-tenant isolation (single organisation assumed).
