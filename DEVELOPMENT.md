# Development

Requires Python 3.11+ (developed on 3.12) and Node 20+ (22 used). Docker is optional for local work.

## Backend

```bash
python -m venv .venv && source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env                                       # set SOAR_ADMIN_PASSWORD (>= 10 chars), INGEST_API_KEY
python -m uvicorn soar.main:app --reload --port 8000       # applies migrations, creates the admin, trains models on first use
```

Data lives in `./data` (SQLite, evidence, reports) and models in `./models`; both are git-ignored.
Useful commands (`python -m soar.cli …`): `create-user <name> <ROLE>`, `train-models`, `migrate`,
`seed-demo` (development-only asset topology), `simulate brute_force|phishing|malware` (sends safe synthetic events
to a running API using `INGEST_API_KEY`).

## Frontend

```bash
cd dashboard/frontend && npm ci && npm run dev             # http://localhost:5173, /api proxied to 127.0.0.1:8000
npm run lint && npm run build
```

## Tests and quality gates

```bash
pytest                                  # 197 tests: unit, integration, end-to-end attack scenarios (~45 s)
ruff check soar ai tests migrations integrations
bandit -q -r soar ai integrations cortex -ll
pip-audit -r requirements.txt
```

Tests use an in-memory SQLite database and train models once per session into a temp directory. The end-to-end tests
(`tests/test_e2e_scenarios.py`) drive brute force, phishing and reverse-shell scenarios through the HTTP API, including
approvals, verification, rollback, reports and audit. Nothing in the suite contacts an external service; provider and
MISP request shapes are checked with mock transports.

## Migrations

`alembic revision --autogenerate -m "message"`; `tests/test_platform.py` fails if models and migrations drift and checks
that migrations downgrade and re-apply. The database URL always comes from `DATABASE_URL` (`alembic.ini` stores none).

## Conventions

* Routers stay thin; logic goes in `soar/pipeline`, `soar/playbooks`, `soar/intel`, `ai/`.
* New action → add to `soar/playbooks/actions.py` **and** `policy.ACTION_RISK` **and** `ai/llm_commander/schema.py`
  (a test asserts the registry and the schema agree). It must report `succeeded|skipped|failed` truthfully and provide `verify`.
* Never add a default credential, mock threat-intel table or fake metric; show "unavailable" instead.
* Keep `.env.example` comments on their own lines (dotenv treats inline comments as part of the value; a test guards this).

## Dependency audit (what was removed)

`nltk`, `requests`, `urllib3`, `google-generativeai`, `imbalanced-learn` (now dev-only), Express/Mongoose/helmet/morgan/
bcryptjs/jsonwebtoken/dotenv/cors (Node backend), and MongoDB. Added, each with a concrete use: FastAPI, uvicorn,
SQLAlchemy, Alembic, psycopg, pydantic(-settings), PyJWT, bcrypt, httpx, joblib. SHAP is **not** used: XGBoost's
built-in TreeSHAP (`pred_contribs`) provides the explanations without the dependency.

## Cleaned-up repository items

Removed: `SOAR_project_archive.zip` (contained a `.env` and private keys), the Colab notebook duplicates, the leaky
`real_mapped_data.csv` (230k rows) and `fetch_real_data.py`, the mock IP-reputation analyzer, `plugin-security.policy`
(an unreferenced OpenSearch file), `simulate_attack.py` (a stub), `orchestrator.py`, and the Node backend.
Kept untouched: `vercel.json`/`.vercelignore` (static SPA deploy config; the SPA needs a reachable `/api`),
`scripts/agent_install.sh`, `scripts/fix_agent.sh`, `scripts/check_all.py`, the Wazuh custom rules, and the Cortex
block-IP responder (now without credential defaults).
