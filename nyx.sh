#!/usr/bin/env bash
# nyx.sh — Manage your Nyx instance
#
# Usage:
#   ./nyx.sh              Start Nyx (or show status if already running)
#   ./nyx.sh start        Start all services
#   ./nyx.sh stop         Stop all services
#   ./nyx.sh restart      Restart all services
#   ./nyx.sh status       Show service status and open finding counts
#   ./nyx.sh logs         Tail backend logs (Ctrl+C to stop)
#   ./nyx.sh build        Rebuild images and restart (after pulling updates)
#   ./nyx.sh check        Verify all integration credentials
#   ./nyx.sh refresh      Trigger all scan schedules now
#   ./nyx.sh help         Show this help
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

API_BASE="${NYX_API_BASE:-http://localhost:8000/api/v1}"
FRONTEND_URL="${NYX_FRONTEND_URL:-http://localhost:3000}"

# ── Colour helpers ───────────────────────────────────────────────────────────
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
ok()     { printf '  \033[32m✓\033[0m  %s\n' "$*"; }
warn()   { printf '  \033[33m⚠\033[0m  %s\n' "$*"; }
fail()   { printf '  \033[31m✗\033[0m  %s\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

# ── Load API key from .env ───────────────────────────────────────────────────
NYX_API_KEY=""
ENV_FILE="$SCRIPT_DIR/.env"
_env_get() {
  grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true
}
[[ -f "$ENV_FILE" ]] && NYX_API_KEY=$(_env_get "NYX_API_KEY")

api_curl() {
  local args=(-sf --max-time 10)
  [[ -n "$NYX_API_KEY" ]] && args+=(-H "X-API-Key: $NYX_API_KEY")
  curl "${args[@]}" "$@"
}

# ── Backend health check helper ──────────────────────────────────────────────
_wait_for_backend() {
  printf "  Waiting for backend"
  for i in $(seq 1 30); do
    if curl -sf --max-time 3 http://localhost:8000/health >/dev/null 2>&1; then
      printf '\n'
      green "  Backend is healthy."
      return 0
    fi
    printf '.'
    sleep 2
    if [[ $i -eq 30 ]]; then
      printf '\n'
      fail "Backend didn't start within 60s. Run: docker compose logs backend"
      return 1
    fi
  done
}

_is_running() {
  local services
  services=$(docker compose ps --services --filter status=running 2>/dev/null || true)
  [[ "$services" == *"backend"* ]] && [[ "$services" == *"frontend"* ]]
}

# ═════════════════════════════════════════════════════════════════════════════
# Commands
# ═════════════════════════════════════════════════════════════════════════════

cmd_help() {
  sed -n '2,/^set /{ /^#/s/^# \?//p }' "$0"
}

cmd_start() {
  bold "Starting Nyx..."
  docker compose up -d
  _wait_for_backend
  echo ""
  green "  Dashboard: $FRONTEND_URL"
}

cmd_stop() {
  bold "Stopping Nyx..."
  docker compose down
  green "  Stopped."
}

cmd_restart() {
  bold "Restarting Nyx..."
  docker compose restart
  _wait_for_backend
  green "  Dashboard: $FRONTEND_URL"
}

cmd_build() {
  bold "Rebuilding and restarting Nyx..."
  docker compose build
  docker compose up -d
  _wait_for_backend
  green "  Dashboard: $FRONTEND_URL"
}

cmd_logs() {
  docker compose logs -f --tail 100 backend
}

cmd_status() {
  bold "Nyx Status"
  echo ""

  # Service status
  local services
  services=$(docker compose ps --services --filter status=running 2>/dev/null || true)
  if [[ "$services" == *"backend"* ]]; then ok "Backend running"; else fail "Backend not running"; fi
  if [[ "$services" == *"frontend"* ]]; then ok "Frontend running"; else fail "Frontend not running"; fi
  if [[ "$services" == *"postgres"* ]]; then ok "PostgreSQL running"; fi

  # Uptime
  local container_started uptime_hours
  container_started=$(docker inspect --format '{{.State.StartedAt}}' \
    "$(docker compose ps -q backend 2>/dev/null)" 2>/dev/null || true)
  if [[ -n "$container_started" ]]; then
    local started_epoch now_epoch
    started_epoch=$(date -d "$container_started" +%s 2>/dev/null || \
      date -jf "%Y-%m-%dT%H:%M:%S" "${container_started%%.*}" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    uptime_hours=$(( (now_epoch - started_epoch) / 3600 ))
    dim "  Uptime: ~${uptime_hours}h"
  fi

  # Finding summary
  echo ""
  local summary
  summary=$(api_curl "$API_BASE/dashboard/summary" 2>/dev/null || true)
  if [[ -n "$summary" ]] && echo "$summary" | grep -q '"open_by_severity"'; then
    local critical high medium low
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
    [[ $low      -gt 0 ]] && printf 'LOW: %s'                        "$low"
    if [[ $critical -eq 0 && $high -eq 0 && $medium -eq 0 && $low -eq 0 ]]; then
      printf '\033[32mNone!\033[0m'
    fi
    printf '\n'
  else
    dim "  (Could not fetch findings — is the backend running?)"
  fi

  echo ""
  dim "  Dashboard: $FRONTEND_URL"
}

cmd_check() {
  bold "Nyx Integration Check"
  echo ""

  # Backend health
  if curl -sf --max-time 5 http://localhost:8000/health >/dev/null 2>&1; then
    ok "Backend health"
  else
    fail "Backend not reachable — run './nyx.sh start' first"
    exit 1
  fi

  # Database
  if curl -sf --max-time 5 http://localhost:8000/ready >/dev/null 2>&1; then
    ok "Database ready"
  else
    warn "Database readiness check failed"
  fi

  # Integration health (if API key available)
  if [[ -n "$NYX_API_KEY" ]]; then
    local int_status
    int_status=$(curl -sf --max-time 10 -H "X-API-Key: $NYX_API_KEY" \
      http://localhost:8000/health/integrations 2>/dev/null || echo "")
    if [[ -n "$int_status" ]]; then
      echo "$int_status" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for name, info in d.get('integrations', {}).items():
    status = info.get('status', 'unknown')
    detail = info.get('detail', info.get('authenticated_as', ''))
    sym = '✓' if status in ('ok', 'mock') else ('–' if status == 'not_configured' else '⚠')
    suffix = f' ({detail})' if detail else ''
    print(f'  {sym}  {name}: {status}{suffix}')
" 2>/dev/null || warn "Could not parse integration status"
    fi
  else
    warn "NYX_API_KEY not set — skipping integration probe"
  fi

  # Direct credential checks
  gh_token=$(_env_get "GITHUB_TOKEN")
  if [[ -n "$gh_token" ]] && [[ "$gh_token" != "ghp_xxxxxxxxxxxx" ]]; then
    local gh_code
    gh_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 8 \
      -H "Authorization: token $gh_token" https://api.github.com/user 2>/dev/null || echo "0")
    if [[ "$gh_code" == "200" ]]; then ok "GitHub token valid"; else warn "GitHub token: HTTP $gh_code"; fi
  else
    warn "GITHUB_TOKEN not configured"
  fi

  ant_key=$(_env_get "ANTHROPIC_API_KEY")
  if [[ -n "$ant_key" ]] && [[ "$ant_key" != "sk-ant-xxxxxxxxxxxx" ]]; then
    local ant_code
    ant_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 8 \
      -H "x-api-key: $ant_key" -H "anthropic-version: 2023-06-01" \
      "https://api.anthropic.com/v1/models" 2>/dev/null || echo "0")
    if [[ "$ant_code" == "200" ]]; then ok "Anthropic API key valid"; else warn "Anthropic key: HTTP $ant_code"; fi
  else
    warn "ANTHROPIC_API_KEY not configured"
  fi

  jira_url=$(_env_get "JIRA_URL")
  jira_token=$(_env_get "JIRA_API_TOKEN")
  jira_user=$(_env_get "JIRA_USER_EMAIL")
  if [[ -n "$jira_url" ]] && [[ -n "$jira_token" ]]; then
    local jira_code
    jira_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 8 \
      -u "${jira_user}:${jira_token}" "${jira_url%/}/rest/api/3/myself" 2>/dev/null || echo "0")
    if [[ "$jira_code" == "200" ]]; then ok "JIRA credentials valid"; else warn "JIRA: HTTP $jira_code"; fi
  else
    dim "  –  JIRA not configured (optional)"
  fi

  echo ""
}

cmd_refresh() {
  bold "Triggering all scan schedules..."

  if ! curl -sf --max-time 5 http://localhost:8000/health >/dev/null 2>&1; then
    fail "Backend not reachable — start Nyx first."
    exit 1
  fi

  local schedules_json schedule_ids schedule_count triggered=0 failed=0
  schedules_json=$(api_curl "$API_BASE/schedules" 2>/dev/null || echo "[]")
  schedule_ids=$(echo "$schedules_json" | grep -o '"id":"[^"]*"' | cut -d'"' -f4 || true)
  schedule_count=$(echo "$schedule_ids" | grep -c . 2>/dev/null || echo 0)

  if [[ $schedule_count -eq 0 ]] || [[ -z "$schedule_ids" ]]; then
    dim "  No scan schedules configured."
    return
  fi

  while IFS= read -r sid; do
    [[ -z "$sid" ]] && continue
    if api_curl -X POST "$API_BASE/schedules/$sid/trigger" >/dev/null 2>&1; then
      (( triggered++ )) || true
    else
      (( failed++ )) || true
    fi
  done <<< "$schedule_ids"

  green "  Triggered $triggered schedule(s)."
  [[ $failed -gt 0 ]] && yellow "  $failed schedule(s) failed."
}

# ── Default command (no args): start if stopped, status if running ──────────
cmd_default() {
  if _is_running; then
    cmd_status
  else
    # Check if setup has been run
    if [[ ! -f "$ENV_FILE" ]]; then
      yellow "  No .env found. Running first-time setup..."
      echo ""
      exec "$SCRIPT_DIR/setup.sh"
    fi
    cmd_start
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Dispatch
# ═════════════════════════════════════════════════════════════════════════════
COMMAND="${1:-}"

case "$COMMAND" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_restart ;;
  status)  cmd_status ;;
  logs)    cmd_logs ;;
  build)   cmd_build ;;
  check)   cmd_check ;;
  refresh) cmd_refresh ;;
  help|--help|-h) cmd_help ;;
  "")      cmd_default ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    echo "Run './nyx.sh help' for usage." >&2
    exit 1
    ;;
esac
