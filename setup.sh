#!/usr/bin/env bash
# setup.sh — First-run setup wizard for Nyx
#
# Usage: ./setup.sh [--non-interactive]
#
# What this script does:
#   1. Checks system dependencies (docker, docker compose, python3, curl)
#   2. Creates .env from .env.example if it doesn't exist
#   3. Generates secure random values for NYX_SECRET_KEY and NYX_API_KEY
#   4. Runs a preflight connectivity check (optional)
#   5. Builds and starts Docker services
#   6. Waits for the backend to become healthy
#   7. Prints the dashboard URL and first API key
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NON_INTERACTIVE=false
SKIP_START=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --skip-start)      SKIP_START=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Colour helpers ────────────────────────────────────────────────────────────
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

echo ""
bold "═══════════════════════════════════════════════════"
bold "  Nyx Security Dashboard — First-Run Setup"
bold "═══════════════════════════════════════════════════"
echo ""

# ── 1. Dependency checks ──────────────────────────────────────────────────────
bold "==> Checking dependencies..."

MISSING=()
command -v docker       >/dev/null 2>&1 || MISSING+=("docker")
command -v python3      >/dev/null 2>&1 || MISSING+=("python3")
command -v curl         >/dev/null 2>&1 || MISSING+=("curl")

# docker compose v2 (plugin) or docker-compose v1
if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  MISSING+=("docker-compose (or docker compose plugin)")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
  red "  Missing required tools:"
  for dep in "${MISSING[@]}"; do
    red "    • $dep"
  done
  exit 1
fi
green "  All dependencies found."

# ── 2. Create .env if missing ─────────────────────────────────────────────────
bold "==> Configuring environment..."

ENV_FILE="$SCRIPT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  yellow "  .env already exists — skipping creation."
else
  if [[ ! -f "$SCRIPT_DIR/.env.example" ]]; then
    red "  ERROR: .env.example not found in $SCRIPT_DIR"
    exit 1
  fi
  cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
  green "  Created .env from .env.example"
fi

# ── Helper: get/set values in .env ────────────────────────────────────────────
_env_get() {
  local key="$1"
  grep -E "^${key}=" "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true
}

_env_set() {
  local key="$1" value="$2"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    # Replace existing line
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

# ── 3. Generate secrets if missing ────────────────────────────────────────────
bold "==> Generating secure secrets..."

CURRENT_SECRET_KEY=$(_env_get "NYX_SECRET_KEY")
if [[ -z "$CURRENT_SECRET_KEY" ]]; then
  NEW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  _env_set "NYX_SECRET_KEY" "$NEW_SECRET_KEY"
  green "  Generated NYX_SECRET_KEY"
else
  dim "  NYX_SECRET_KEY already set — keeping existing value."
fi

CURRENT_API_KEY=$(_env_get "NYX_API_KEY")
if [[ -z "$CURRENT_API_KEY" ]] || [[ "$CURRENT_API_KEY" == "nyx-your-secret-key-here" ]]; then
  NEW_API_KEY="nyx-$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")"
  _env_set "NYX_API_KEY" "$NEW_API_KEY"
  green "  Generated NYX_API_KEY: $NEW_API_KEY"
  echo ""
  yellow "  *** SAVE THIS KEY — it will not be shown again ***"
  yellow "  NYX_API_KEY=$NEW_API_KEY"
  echo ""
else
  dim "  NYX_API_KEY already set."
fi

CURRENT_WEBHOOK_SECRET=$(_env_get "NYX_WEBHOOK_SECRET")
if [[ -z "$CURRENT_WEBHOOK_SECRET" ]]; then
  NEW_WH_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  _env_set "NYX_WEBHOOK_SECRET" "$NEW_WH_SECRET"
  green "  Generated NYX_WEBHOOK_SECRET"
else
  dim "  NYX_WEBHOOK_SECRET already set."
fi

# ── 4. Prompt for required keys (interactive) ─────────────────────────────────
if ! $NON_INTERACTIVE; then
  echo ""
  bold "==> Configure required integrations (press Enter to skip)..."

  CURRENT_GITHUB_TOKEN=$(_env_get "GITHUB_TOKEN")
  if [[ -z "$CURRENT_GITHUB_TOKEN" ]] || [[ "$CURRENT_GITHUB_TOKEN" == "ghp_xxxxxxxxxxxx" ]]; then
    echo ""
    dim "  GitHub Personal Access Token (scopes: repo, admin:repo_hook, security_events)"
    dim "  Create at: https://github.com/settings/tokens"
    printf "  GITHUB_TOKEN: "
    read -r INPUT_TOKEN
    if [[ -n "$INPUT_TOKEN" ]]; then
      _env_set "GITHUB_TOKEN" "$INPUT_TOKEN"
      green "  GITHUB_TOKEN set."
    else
      yellow "  Skipped — GitHub integration will not be available."
    fi
  else
    dim "  GITHUB_TOKEN already set."
  fi

  CURRENT_ANTHROPIC_KEY=$(_env_get "ANTHROPIC_API_KEY")
  if [[ -z "$CURRENT_ANTHROPIC_KEY" ]] || [[ "$CURRENT_ANTHROPIC_KEY" == "sk-ant-xxxxxxxxxxxx" ]]; then
    echo ""
    dim "  Anthropic API Key (required for AI fix generation)"
    dim "  Create at: https://console.anthropic.com/settings/keys"
    printf "  ANTHROPIC_API_KEY: "
    read -r INPUT_ANTHROPIC
    if [[ -n "$INPUT_ANTHROPIC" ]]; then
      _env_set "ANTHROPIC_API_KEY" "$INPUT_ANTHROPIC"
      green "  ANTHROPIC_API_KEY set."
    else
      yellow "  Skipped — AI remediation will not be available."
    fi
  else
    dim "  ANTHROPIC_API_KEY already set."
  fi

  CURRENT_WEBHOOK_ENDPOINT=$(_env_get "GITHUB_WEBHOOK_ENDPOINT")
  if [[ -z "$CURRENT_WEBHOOK_ENDPOINT" ]] || [[ "$CURRENT_WEBHOOK_ENDPOINT" == "https://your-nyx-instance.example.com/api/v1/webhooks/github" ]]; then
    echo ""
    dim "  Public URL of your Nyx backend (used for GitHub webhook registration)."
    dim "  For local dev, use ngrok: https://ngrok.com/  or  cloudflared tunnel"
    dim "  Example: https://abc123.ngrok.io/api/v1/webhooks/github"
    printf "  GITHUB_WEBHOOK_ENDPOINT: "
    read -r INPUT_ENDPOINT
    if [[ -n "$INPUT_ENDPOINT" ]]; then
      _env_set "GITHUB_WEBHOOK_ENDPOINT" "$INPUT_ENDPOINT"
      green "  GITHUB_WEBHOOK_ENDPOINT set."
    else
      yellow "  Skipped — automatic webhook registration will not work."
    fi
  else
    dim "  GITHUB_WEBHOOK_ENDPOINT already set."
  fi
fi

# ── 5. Preflight check ────────────────────────────────────────────────────────
echo ""
bold "==> Running preflight checks..."

_preflight_check() {
  local name="$1" result="$2"
  if [[ "$result" == "ok" ]]; then
    green "  ✓ $name"
  else
    yellow "  ⚠ $name: $result"
  fi
}

# GitHub token validation
GH_TOKEN=$(_env_get "GITHUB_TOKEN")
if [[ -n "$GH_TOKEN" ]] && [[ "$GH_TOKEN" != "ghp_xxxxxxxxxxxx" ]]; then
  GH_STATUS=$(curl -sf -H "Authorization: token $GH_TOKEN" https://api.github.com/user -o /dev/null -w "%{http_code}" --max-time 8 || echo "error")
  if [[ "$GH_STATUS" == "200" ]]; then
    _preflight_check "GitHub token" "ok"
  else
    _preflight_check "GitHub token" "HTTP $GH_STATUS — token may be invalid or expired"
  fi
else
  dim "  - GitHub token not configured — skipping check."
fi

# Anthropic API key validation
ANT_KEY=$(_env_get "ANTHROPIC_API_KEY")
if [[ -n "$ANT_KEY" ]] && [[ "$ANT_KEY" != "sk-ant-xxxxxxxxxxxx" ]]; then
  ANT_STATUS=$(curl -sf -H "x-api-key: $ANT_KEY" -H "anthropic-version: 2023-06-01" \
    "https://api.anthropic.com/v1/models" -o /dev/null -w "%{http_code}" --max-time 8 || echo "error")
  if [[ "$ANT_STATUS" == "200" ]]; then
    _preflight_check "Anthropic API key" "ok"
  else
    _preflight_check "Anthropic API key" "HTTP $ANT_STATUS — key may be invalid"
  fi
else
  dim "  - Anthropic API key not configured — skipping check."
fi

# Docker daemon
if docker info >/dev/null 2>&1; then
  _preflight_check "Docker daemon" "ok"
else
  red "  ✗ Docker daemon is not running — start Docker Desktop or the daemon first."
  exit 1
fi

# ── 6. Build and start ────────────────────────────────────────────────────────
if ! $SKIP_START; then
  echo ""
  bold "==> Building and starting Nyx..."
  cd "$SCRIPT_DIR"
  docker compose build
  docker compose up -d

  # Wait for backend health check
  printf "  Waiting for backend to become healthy"
  for i in $(seq 1 40); do
    if curl -sf --max-time 3 http://localhost:8000/health >/dev/null 2>&1; then
      printf '\n'
      green "  Backend is healthy."
      break
    fi
    printf '.'
    sleep 3
    if [[ $i -eq 40 ]]; then
      printf '\n'
      red "  ERROR: Backend did not start within 120s."
      echo "  Check logs: docker compose logs backend"
      exit 1
    fi
  done
fi

# ── 7. Summary ────────────────────────────────────────────────────────────────
echo ""
bold "═══════════════════════════════════════════════════"
bold "  Nyx is ready!"
bold "═══════════════════════════════════════════════════"
echo ""
green "  Dashboard:  http://localhost:3000"
green "  API:        http://localhost:8000"
dim   "  API Key:    $(_env_get "NYX_API_KEY")"
echo ""
bold  "  Next steps:"
dim   "  1. Open http://localhost:3000 and enter your API key"
dim   "  2. Register a GitHub repository: POST /api/v1/repositories"
dim   "  3. Import scan results or push a commit to trigger a scan"
echo ""
dim   "  For webhook testing locally, use ngrok:"
dim   "    ngrok http 8000"
dim   "  Then set GITHUB_WEBHOOK_ENDPOINT=https://<ngrok-id>.ngrok.io/api/v1/webhooks/github"
echo ""
dim   "  Run './nyx.sh --check' at any time to verify integrations."
echo ""
