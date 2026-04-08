#!/usr/bin/env bash
# nyx.sh — Start Nyx (or wake it up after a break)
#
# Usage: ./nyx.sh [--refresh-after HOURS] [--build] [--check]
#   --refresh-after HOURS  Trigger all scan schedules if Nyx has been running
#                          longer than this many hours (default: 4)
#   --build                Rebuild Docker images before starting (required after
#                          pulling updates that add new dependencies)
#   --check                Run integration preflight checks and exit (does not start Nyx)
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFRESH_AFTER_HOURS=4
API_BASE="${NYX_API_BASE:-http://localhost:8000/api/v1}"
FRONTEND_URL="${NYX_FRONTEND_URL:-http://localhost:3000}"
FORCE_BUILD=false
CHECK_ONLY=false

# ── Args ─────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --refresh-after) REFRESH_AFTER_HOURS="$2"; shift 2 ;;
    --build) FORCE_BUILD=true; shift ;;
    --check) CHECK_ONLY=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
bold()    { printf '\033[1m%s\033[0m\n' "$*"; }
ok()      { printf '  \033[32m✓\033[0m  %s\n' "$*"; }
warn()    { printf '  \033[33m⚠\033[0m  %s\n' "$*"; }
fail()    { printf '  \033[31m✗\033[0m  %s\n' "$*"; }
green()   { printf '\033[32m%s\033[0m\n' "$*"; }
yellow()  { printf '\033[33m%s\033[0m\n' "$*"; }
blue()    { printf '\033[34m%s\033[0m\n' "$*"; }
dim()     { printf '\033[2m%s\033[0m\n' "$*"; }

# ── --check: preflight integration probe and exit ────────────────────────────
if $CHECK_ONLY; then
  bold "==> Nyx preflight integration check"
  echo ""

  ENV_FILE="$SCRIPT_DIR/.env"
  _env_get() { grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true; }

  GH_TOKEN=$(_env_get "GITHUB_TOKEN")
  ANT_KEY=$(_env_get "ANTHROPIC_API_KEY")
  JIRA_URL_VAL=$(_env_get "JIRA_URL")
  JIRA_TOKEN=$(_env_get "JIRA_API_TOKEN")
  JIRA_USER=$(_env_get "JIRA_USER_EMAIL")
  NYX_KEY=$(_env_get "NYX_API_KEY")

  # Backend health
  if curl -sf --max-time 5 http://localhost:8000/health >/dev/null 2>&1; then
    ok "Backend (http://localhost:8000/health)"
  else
    warn "Backend not reachable — run './nyx.sh' to start it"
  fi

  # Database (via /ready endpoint)
  if curl -sf --max-time 5 http://localhost:8000/ready >/dev/null 2>&1; then
    ok "Database (/ready)"
  else
    warn "Database readiness check failed"
  fi

  # Integration health endpoint (if backend is running)
  if [[ -n "$NYX_KEY" ]]; then
    INT_STATUS=$(curl -sf --max-time 10 -H "X-API-Key: $NYX_KEY" \
      http://localhost:8000/health/integrations 2>/dev/null || echo "")
    if [[ -n "$INT_STATUS" ]]; then
      OVERALL=$(echo "$INT_STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('overall','unknown'))" 2>/dev/null || echo "unknown")
      if [[ "$OVERALL" == "ok" ]]; then
        ok "Integration health: $OVERALL"
      else
        warn "Integration health: $OVERALL — run GET /health/integrations for details"
      fi
      # Per-integration breakdown
      echo "$INT_STATUS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for name, info in d.get('integrations', {}).items():
    status = info.get('status', 'unknown')
    detail = info.get('detail', info.get('authenticated_as', ''))
    sym = '✓' if status in ('ok', 'mock') else ('–' if status == 'not_configured' else '⚠')
    print(f'     {sym}  {name}: {status}' + (f' ({detail})' if detail else ''))
" 2>/dev/null || true
    else
      warn "Could not reach integration health endpoint"
    fi
  else
    warn "NYX_API_KEY not set — skipping integration health probe"
  fi

  # GitHub token direct check
  if [[ -n "$GH_TOKEN" ]] && [[ "$GH_TOKEN" != "ghp_xxxxxxxxxxxx" ]]; then
    GH_CODE=$(curl -sf -H "Authorization: token $GH_TOKEN" https://api.github.com/user \
      -o /dev/null -w "%{http_code}" --max-time 8 2>/dev/null || echo "0")
    if [[ "$GH_CODE" == "200" ]]; then
      ok "GitHub token valid"
    else
      warn "GitHub token returned HTTP $GH_CODE"
    fi
  else
    warn "GITHUB_TOKEN not configured"
  fi

  # Anthropic key check
  if [[ -n "$ANT_KEY" ]] && [[ "$ANT_KEY" != "sk-ant-xxxxxxxxxxxx" ]]; then
    ANT_CODE=$(curl -sf -H "x-api-key: $ANT_KEY" -H "anthropic-version: 2023-06-01" \
      "https://api.anthropic.com/v1/models" -o /dev/null -w "%{http_code}" --max-time 8 2>/dev/null || echo "0")
    if [[ "$ANT_CODE" == "200" ]]; then
      ok "Anthropic API key valid"
    else
      warn "Anthropic API key returned HTTP $ANT_CODE"
    fi
  else
    warn "ANTHROPIC_API_KEY not configured"
  fi

  # JIRA check
  if [[ -n "$JIRA_URL_VAL" ]] && [[ -n "$JIRA_TOKEN" ]]; then
    JIRA_CODE=$(curl -sf -u "${JIRA_USER}:${JIRA_TOKEN}" \
      "${JIRA_URL_VAL%/}/rest/api/3/myself" -o /dev/null -w "%{http_code}" --max-time 8 2>/dev/null || echo "0")
    if [[ "$JIRA_CODE" == "200" ]]; then
      ok "JIRA credentials valid"
    else
      warn "JIRA returned HTTP $JIRA_CODE"
    fi
  else
    warn "JIRA not configured"
  fi

  echo ""
  exit 0
fi

# ── Load API key from .env ────────────────────────────────────────────────────
NYX_API_KEY=""
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  NYX_API_KEY=$(grep -E '^NYX_API_KEY=' "$SCRIPT_DIR/.env" | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
fi

api_curl() {
  local args=(-sf --max-time 10)
  [[ -n "$NYX_API_KEY" ]] && args+=(-H "X-API-Key: $NYX_API_KEY")
  curl "${args[@]}" "$@"
}

# ── Step 1: Rebuild if requested ─────────────────────────────────────────────
cd "$SCRIPT_DIR"
if $FORCE_BUILD; then
  bold "==> Rebuilding Docker images..."
  docker compose build backend frontend
  green "  Build complete."
fi

# ── Step 2: Check which services are running ──────────────────────────────────
bold "==> Checking Nyx status..."

# Get running service names from docker compose
running_services=$(docker compose ps --services --filter status=running 2>/dev/null || true)
backend_running=false
frontend_running=false
[[ "$running_services" == *"backend"* ]] && backend_running=true
[[ "$running_services" == *"frontend"* ]] && frontend_running=true

# ── Step 2: Start if not running ──────────────────────────────────────────────
if ! $backend_running || ! $frontend_running; then
  if ! $backend_running && ! $frontend_running; then
    yellow "  Nyx is not running — starting services..."
  elif ! $backend_running; then
    yellow "  Backend is down — starting services..."
  else
    yellow "  Frontend is down — starting services..."
  fi

  docker compose up -d

  # Wait for backend health check
  printf "  Waiting for backend"
  for i in $(seq 1 30); do
    if curl -sf --max-time 3 http://localhost:8000/health >/dev/null 2>&1; then
      printf '\n'
      green "  Backend is healthy."
      break
    fi
    printf '.'
    sleep 2
    if [[ $i -eq 30 ]]; then
      printf '\n'
      echo "  ERROR: Backend did not become healthy after 60s." >&2
      echo "  Run: docker compose logs backend" >&2
      exit 1
    fi
  done
  # Services just started — no need to refresh data
  JUST_STARTED=true
else
  green "  Backend and frontend are running."
  JUST_STARTED=false
fi

# ── Step 3: Decide whether to refresh data ───────────────────────────────────
if ! $JUST_STARTED; then
  # Get backend container start time (seconds since epoch)
  container_started=$(docker inspect --format '{{.State.StartedAt}}' "$(docker compose ps -q backend 2>/dev/null)" 2>/dev/null || true)
  uptime_hours=0
  if [[ -n "$container_started" ]]; then
    started_epoch=$(date -d "$container_started" +%s 2>/dev/null || date -jf "%Y-%m-%dT%H:%M:%S" "${container_started%%.*}" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    uptime_hours=$(( (now_epoch - started_epoch) / 3600 ))
  fi

  if [[ $uptime_hours -ge $REFRESH_AFTER_HOURS ]]; then
    bold "==> Nyx has been running for ~${uptime_hours}h — refreshing scan data..."

    # List all scan schedules and trigger each one
    schedules_json=$(api_curl "$API_BASE/schedules" 2>/dev/null || echo "[]")
    schedule_ids=$(echo "$schedules_json" | grep -o '"id":"[^"]*"' | cut -d'"' -f4 || true)
    schedule_count=$(echo "$schedule_ids" | grep -c . || true)

    if [[ $schedule_count -eq 0 ]] || [[ -z "$schedule_ids" ]]; then
      dim "  No scan schedules configured — nothing to trigger."
    else
      triggered=0
      failed=0
      while IFS= read -r sid; do
        [[ -z "$sid" ]] && continue
        if api_curl -X POST "$API_BASE/schedules/$sid/trigger" >/dev/null 2>&1; then
          (( triggered++ )) || true
        else
          (( failed++ )) || true
        fi
      done <<< "$schedule_ids"
      green "  Triggered $triggered scan schedule(s)."
      [[ $failed -gt 0 ]] && yellow "  $failed schedule(s) failed to trigger (check logs)."
    fi
  else
    remaining=$(( REFRESH_AFTER_HOURS - uptime_hours ))
    dim "  Running for ~${uptime_hours}h (refresh kicks in after ${REFRESH_AFTER_HOURS}h, ${remaining}h to go)."
  fi
fi

# ── Step 4: Quick status summary ─────────────────────────────────────────────
bold "==> Dashboard summary..."
summary=$(api_curl "$API_BASE/dashboard/summary" 2>/dev/null || true)

if [[ -n "$summary" ]] && echo "$summary" | grep -q '"open_by_severity"'; then
  critical=$(echo "$summary" | grep -o '"CRITICAL":[0-9]*' | cut -d: -f2 || echo 0)
  high=$(echo "$summary"     | grep -o '"HIGH":[0-9]*'     | cut -d: -f2 || echo 0)
  medium=$(echo "$summary"   | grep -o '"MEDIUM":[0-9]*'   | cut -d: -f2 || echo 0)
  low=$(echo "$summary"      | grep -o '"LOW":[0-9]*'      | cut -d: -f2 || echo 0)

  [[ -z "$critical" ]] && critical=0
  [[ -z "$high" ]]     && high=0
  [[ -z "$medium" ]]   && medium=0
  [[ -z "$low" ]]      && low=0

  printf "  Open findings:  "
  [[ $critical -gt 0 ]] && printf '\033[31mCRITICAL: %s  \033[0m' "$critical"
  [[ $high     -gt 0 ]] && printf '\033[33mHIGH: %s  \033[0m'     "$high"
  [[ $medium   -gt 0 ]] && printf '\033[34mMEDIUM: %s  \033[0m'   "$medium"
  [[ $low      -gt 0 ]] && printf 'LOW: %s'                         "$low"
  printf '\n'
else
  dim "  (Could not fetch summary — API key may not be set in .env)"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
bold "Nyx is ready at $FRONTEND_URL"
