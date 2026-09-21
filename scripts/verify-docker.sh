#!/usr/bin/env bash
# Deterministic Docker verification for SOAR Intelligence. Stops at the first failed step.
#
#   scripts/verify-docker.sh            validate compose, build, start the core stack, check health, tear down
#   scripts/verify-docker.sh --siem     same, but start the SIEM overlay too (needs ~10 GB RAM and free ports
#                                       443, 1514, 1515, 9200, 55000 ...; it has NOT been run by the author)
#   KEEP=1 scripts/verify-docker.sh     leave the stack running afterwards
#   ENV_FILE=path                       env file to use (default: .env; if missing, throwaway secrets are generated)
#
# Runs in its own compose project (soar-verify), so cleanup never touches a stack you started yourself.
set -uo pipefail
cd "$(dirname "$0")/.."

PROJECT=soar-verify
FILES=(-f docker-compose.yml)
[[ "${1:-}" == "--siem" ]] && FILES+=(-f docker-compose.siem.yml)
API_PORT="${SOAR_API_PORT:-8000}"
UI_PORT="${SOAR_UI_PORT:-8080}"
ENV_FILE="${ENV_FILE:-.env}"
GENERATED_ENV=""
results=()

record() { results+=("$1|$2|$3"); }
finish() {
  printf '\n%-34s %-8s %s\n' STEP RESULT DETAIL
  for r in "${results[@]}"; do IFS='|' read -r s res d <<<"$r"; printf '%-34s %-8s %s\n' "$s" "$res" "$d"; done
  [[ "$1" == 0 ]] && echo "OVERALL: PASS" || echo "OVERALL: FAIL"
  exit "$1"
}
step() { # step <name> <command...>; the command's output is shown only on failure
  local name="$1"; shift
  if out=$("$@" 2>&1); then record "$name" PASS ""; else echo "$out" | tail -25; record "$name" FAIL "see output above"; finish 1; fi
}
gen() { python3 -c 'import secrets;print(secrets.token_urlsafe(48))' 2>/dev/null || python -c 'import secrets;print(secrets.token_urlsafe(48))'; }

command -v docker >/dev/null 2>&1 || { record "docker CLI" FAIL "docker not on PATH"; finish 1; }
record "docker CLI" PASS "$(docker --version)"
step "docker daemon reachable" docker info --format '{{.ServerVersion}}'

if [[ ! -f "$ENV_FILE" ]]; then
  ENV_FILE="$(mktemp)"; GENERATED_ENV="$ENV_FILE"
  { echo "POSTGRES_PASSWORD=$(gen)"; echo "JWT_SECRET=$(gen)"; echo "SOAR_ENV=production"; } >"$ENV_FILE"
  record "env file" PASS "no .env found: generated throwaway secrets"
else
  record "env file" PASS "using $ENV_FILE"
fi

C=(docker compose -p "$PROJECT" --env-file "$ENV_FILE" "${FILES[@]}")
cleanup() {
  [[ "${KEEP:-0}" == 1 ]] || "${C[@]}" down -v --remove-orphans >/dev/null 2>&1
  [[ -n "$GENERATED_ENV" ]] && rm -f "$GENERATED_ENV"
}
trap cleanup EXIT

step "compose config (selected files)" "${C[@]}" config -q
# The overlay needs SIEM secrets a core-only .env does not have; placeholders (overridden by the real
# env file, which comes last) let its syntax and interpolation be checked without starting anything.
siem_env="$(mktemp)"
printf '%s=placeholder\n' WAZUH_INDEXER_ADMIN_PASSWORD WAZUH_API_PASSWORD THEHIVE_SECRET MISP_DB_PASSWORD MISP_ADMIN_PASSPHRASE >"$siem_env"
cat "$ENV_FILE" >>"$siem_env"
step "compose config (core + SIEM)" docker compose -p "$PROJECT" --env-file "$siem_env" -f docker-compose.yml -f docker-compose.siem.yml config -q
rm -f "$siem_env"
empty_env="$(mktemp)"
if docker compose -p "$PROJECT" --env-file "$empty_env" -f docker-compose.yml config -q >/dev/null 2>&1; then
  rm -f "$empty_env"; record "required secrets enforced" FAIL "compose accepted a missing POSTGRES_PASSWORD"; finish 1
fi
rm -f "$empty_env"; record "required secrets enforced" PASS "missing secret is rejected"

step "image build" "${C[@]}" build
step "start + health checks (--wait)" "${C[@]}" up -d --wait --wait-timeout 240

check_http() { # check_http <name> <url> <expected substring, or empty for any 2xx>
  local body
  if body=$(curl -fsS --max-time 10 "$2") && [[ -z "$3" || "$body" == *"$3"* ]]; then
    record "$1" PASS "${body:0:60}"; else record "$1" FAIL "${body:-no response}"; finish 1; fi
}
check_http "GET /api/health" "http://127.0.0.1:${API_PORT}/api/health" '"ok"'
check_http "GET /api/ready (database)" "http://127.0.0.1:${API_PORT}/api/ready" '"ready"'
check_http "GET / (dashboard)" "http://127.0.0.1:${UI_PORT}/" ""
code=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${API_PORT}/api/auth/me")
if [[ "$code" == 401 ]]; then record "auth enforced (no token -> 401)" PASS ""
else record "auth enforced (no token -> 401)" FAIL "got ${code:-none}"; finish 1; fi

finish 0
