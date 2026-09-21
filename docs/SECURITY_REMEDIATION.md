# Security remediation: credentials exposed in the original commit

Commit `ad230ec` ("Initial commit") is the only commit on `main` and it contained live credential material.
This document records what was exposed, what has been done, what has **not** been done, and what only the
repository owner can do. No secret values appear here.

## Status

| Item | Status |
|---|---|
| Secrets removed from the working tree of `soar-platform-overhaul` | Done (commit `8aec9b2` and later) |
| Hardcoded literals replaced by required environment variables | Done (compose fails fast when unset) |
| `.gitignore` / `.dockerignore` exclude `.env*`, `*.pem`, `*.key`, certificate directories | Done |
| CI: private-key grep, leaked-literal regression test, gitleaks scan of the tree | Done |
| Secrets removed from **git history** (`ad230ec` is still in history, on `main` and on origin) | **Not done** (see below) |
| Exposed credentials **rotated** | **Not done. Only the owner can do this** |

## What was exposed

Categories only; inspect the commit with `git ls-tree -r ad230ec` and `git show --stat ad230ec`.

| Category | Where it was | Notes |
|---|---|---|
| A `.env` file | inside `SOAR_project_archive.zip` | Assume it held real deployment settings |
| Wazuh private keys (CA, indexer, manager, admin) | inside `SOAR_project_archive.zip` | Anyone holding the CA key can mint certificates your Wazuh components will trust |
| TheHive API key | default value in `integrations/wazuh_to_thehive.py` | |
| Service passwords and API keys as literals | compose files, Node routes, helper scripts | Listed in `SECURITY.md`; all replaced by `${VAR:?...}` |

## Remediation performed

1. The archive, the dataset and the scripts carrying literals were deleted (`8aec9b2`).
2. Every integration setting now comes from the environment. `.env.example` holds placeholders only.
   `docker-compose.yml` and `docker-compose.siem.yml` use `${VAR:?message}` so the stack refuses to start
   with a missing secret.
3. `.gitignore` and `.dockerignore` exclude `.env`, `.env.*` (except `.env.example`), `*.pem`, `*.key` and
   `wazuh-certificates/`.
4. CI (`.github/workflows/ci.yml`): a `git grep` for private-key headers, a test that fails if the known leaked
   literals reappear, and a gitleaks scan of the working tree.

## Not done, and why

**History was not rewritten.** Removing a file from the latest commit does not remove it from history: anyone
who cloned, forked or fetched `ad230ec` still has it, and GitHub keeps commits reachable by hash until support
purges them. Rewriting history would change every commit hash and require a force-push over `main`, which
affects every clone. That decision is the owner's; see "Optional: rewrite history" below.

**Credentials were not rotated.** They are issued by other systems and this repository cannot rotate them.
Until rotated, treat every item under "What was exposed" as compromised, whether or not history is rewritten.

## Credentials that require manual rotation

1. **Wazuh certificates and keys.** Regenerate the whole set (`docker compose -f generate-certs.yml up`,
   which uses `config/certs.yml`), redeploy the indexer, manager and dashboard, and re-enroll agents that pin
   the old CA.
2. **Wazuh API user password and indexer `admin` password.** Set new values in `.env`
   (`WAZUH_API_PASSWORD`, `WAZUH_INDEXER_ADMIN_PASSWORD`).
3. **TheHive API key**: create a new key in TheHive and revoke the old one.
4. **Precaution, per `SECURITY.md`:** the Cortex and MISP API keys and passwords, `THEHIVE_SECRET` and the MISP
   database password, if they were ever set to a value that appeared in the leaked files.
5. **Everything in the old `.env`**: LLM provider keys, webhook URLs, database passwords, the JWT signing
   secret. Revoke each at its provider and issue a new one.
6. **Any other system that reused one of these passwords.**

Never paste replacement values into Git, an issue, or a chat. Generate with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Safe configuration procedure

```bash
cp .env.example .env          # .env is git-ignored
# edit .env: set POSTGRES_PASSWORD, JWT_SECRET (>= 32 chars), SOAR_ADMIN_PASSWORD, and any integration keys
git status                    # .env must not appear
docker compose config -q      # fails with a named variable if a required secret is missing
```

## Optional: rewrite history

Only after rotating credentials, and only if you accept changing every commit hash. Work on a fresh mirror clone:

```bash
git clone --mirror <repo-url> soar-mirror.git && cd soar-mirror.git
git filter-repo --invert-paths --path SOAR_project_archive.zip     # plus any other exposed path
git push --force --all && git push --force --tags                  # affects every collaborator
```

Literals inside files (for example the TheHive key default) need `git filter-repo --replace-text` with a file
of patterns kept outside the repository. Afterwards every collaborator must re-clone, and existing forks keep
the old data.

## Verification procedure

```bash
# Working tree: must report no findings (this is what CI runs)
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect --no-git --source /repo --redact

# Full history: expected to report findings in ad230ec until history is rewritten
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect --source /repo --redact

git grep -nE 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY' -- . ':!*.md'   # must print nothing
docker compose config -q                                              # must fail without POSTGRES_PASSWORD
```

Rotation itself cannot be verified from this repository; confirm in each system that the old credential no
longer authenticates.
