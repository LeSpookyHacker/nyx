#!/usr/bin/env bash
# nyx.sh — Start Nyx (or wake it up after a break)
#
# Usage: ./nyx.sh [--refresh-after HOURS]
#   --refresh-after HOURS  Trigger all scan schedules if Nyx has been running
#                          longer than this many hours (default: 4)
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFRESH_AFTER_HOURS=4
API_BASE="http://localhost:8000/api/v1"
FRONTEND_URL="http://localhost:3000"

# ── Args ─────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --refresh-after) REFRESH_AFTER_HOURS="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
bold()    { printf '\033[1m%s\033[0m\n' "$*"; }
green()   { printf '\033[32m%s\033[0m\n' "$*"; }
yellow()  { printf '\033[33m%s\033[0m\n' "$*"; }
blue()    { printf '\033[34m%s\033[0m\n' "$*"; }
dim()     { printf '\033[2m%s\033[0m\n' "$*"; }

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

# ── Step 1: Check which services are running ──────────────────────────────────
bold "==> Checking Nyx status..."
cd "$SCRIPT_DIR"

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
