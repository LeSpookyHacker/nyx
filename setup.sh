#!/usr/bin/env bash
# setup.sh — First-run setup for Nyx
#
# Usage:
#   ./setup.sh                     Interactive setup (recommended for first run)
#   ./setup.sh --non-interactive   Headless setup (for CI/CD or scripting)
#   ./setup.sh --skip-start        Configure .env only, don't start Docker
#   ./setup.sh --help              Show this help
#
# What it does:
#   1. Checks dependencies (docker, docker compose, python3, curl)
#   2. Creates .env from .env.example (if it doesn't exist)
#   3. Generates cryptographic secrets (NYX_SECRET_KEY, NYX_API_KEY, NYX_WEBHOOK_SECRET)
#   4. Prompts for GitHub token & Anthropic key (interactive mode)
#   5. Validates credentials via API
#   6. Builds and starts Docker containers
#   7. Waits for backend health check
#   8. Prints dashboard URL and your API key
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NON_INTERACTIVE=false
SKIP_START=false

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --skip-start)      SKIP_START=true; shift ;;
    --help|-h)
      sed -n '2,/^set /{ /^#/s/^# \?//p }' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 1 ;;
  esac
done

# ── Colour helpers ───────────────────────────────────────────────────────────
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

# ── .env helpers ─────────────────────────────────────────────────────────────
ENV_FILE="$SCRIPT_DIR/.env"

_env_get() {
  grep -E "^${1}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true
}

_env_set() {
  local key="$1" value="$2"
  # Escape sed special chars in value
  local escaped_value
  escaped_value=$(printf '%s' "$value" | sed -e 's/[&\\/]/\\&/g')
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${escaped_value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

_is_placeholder() {
  local val="$1" placeholder="$2"
  [[ -z "$val" ]] || [[ "$val" == "$placeholder" ]]
}

echo ""
bold "  Nyx — First-Run Setup"
bold "  ====================="
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# Step 1: Check dependencies
# ═════════════════════════════════════════════════════════════════════════════
bold "[1/5] Checking dependencies..."

MISSING=()
command -v docker  >/dev/null 2>&1 || MISSING+=("docker")
command -v python3 >/dev/null 2>&1 || MISSING+=("python3")
command -v curl    >/dev/null 2>&1 || MISSING+=("curl")

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  MISSING+=("docker compose (v2 plugin or standalone)")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
  red "  Missing:"
  for dep in "${MISSING[@]}"; do red "    - $dep"; done
  echo ""
  red "  Install the missing tools and re-run ./setup.sh"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  red "  Docker is installed but the daemon isn't running."
  red "  Start Docker Desktop (or 'sudo systemctl start docker') and try again."
  exit 1
fi

green "  All dependencies found."

# ═════════════════════════════════════════════════════════════════════════════
# Step 2: Create .env
# ═════════════════════════════════════════════════════════════════════════════
echo ""
bold "[2/5] Setting up configuration..."

if [[ -f "$ENV_FILE" ]]; then
  dim "  .env already exists — keeping it."
else
  if [[ ! -f "$SCRIPT_DIR/.env.example" ]]; then
    red "  ERROR: .env.example not found. Are you in the nyx directory?"
    exit 1
  fi
  cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
  green "  Created .env from template."
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 3: Generate secrets (always — idempotent)
# ═════════════════════════════════════════════════════════════════════════════
echo ""
bold "[3/5] Generating secrets..."

_generate_if_missing() {
  local key="$1" placeholder="${2:-}" label="$3" generator="$4"
  local current
  current=$(_env_get "$key")
  if _is_placeholder "$current" "$placeholder"; then
    local val
    val=$(python3 -c "$generator")
    _env_set "$key" "$val"
    green "  Generated $label"
  else
    dim "  $label already set."
  fi
}

_generate_if_missing "NYX_SECRET_KEY"    "" "NYX_SECRET_KEY (encryption + audit HMAC)"  "import secrets; print(secrets.token_hex(32))"
_generate_if_missing "NYX_API_KEY"       "nyx-your-secret-key-here" "NYX_API_KEY (your login key)"  "import secrets; print('nyx-' + secrets.token_urlsafe(24))"
_generate_if_missing "NYX_WEBHOOK_SECRET" "" "NYX_WEBHOOK_SECRET (webhook auth)"         "import secrets; print(secrets.token_hex(32))"

# ═════════════════════════════════════════════════════════════════════════════
# Step 4: Prompt for integration keys (interactive only)
# ═════════════════════════════════════════════════════════════════════════════
echo ""
bold "[4/5] Integrations..."

if $NON_INTERACTIVE; then
  dim "  Non-interactive mode — skipping prompts."
  dim "  Edit .env manually to add GITHUB_TOKEN and ANTHROPIC_API_KEY."
else
  # ── GitHub Token ─────────────────────────────────────────────────────────
  current_gh=$(_env_get "GITHUB_TOKEN")
  if _is_placeholder "$current_gh" "ghp_xxxxxxxxxxxx"; then
    echo ""
    dim "  GitHub Personal Access Token"
    dim "  Needed for: webhook registration, PR creation, file access"
    dim "  Create one at: https://github.com/settings/tokens"
    dim "  Required scopes: Contents, Pull requests, Webhooks, Workflows, Checks"
    dim "  (press Enter to skip — you can add it to .env later)"
    printf "  GITHUB_TOKEN: "
    read -r input_token
    if [[ -n "$input_token" ]]; then
      _env_set "GITHUB_TOKEN" "$input_token"
      green "  Saved."
    else
      yellow "  Skipped. GitHub features won't work until you set GITHUB_TOKEN in .env"
    fi
  else
    dim "  GITHUB_TOKEN already configured."
  fi

  # ── Anthropic API Key ───────────────────────────────────────────────────
  current_ant=$(_env_get "ANTHROPIC_API_KEY")
  if _is_placeholder "$current_ant" "sk-ant-xxxxxxxxxxxx"; then
    echo ""
    dim "  Anthropic API Key"
    dim "  Needed for: AI-generated code fixes"
    dim "  Create one at: https://console.anthropic.com/settings/keys"
    dim "  (press Enter to skip — you can add it to .env later)"
    printf "  ANTHROPIC_API_KEY: "
    read -r input_ant
    if [[ -n "$input_ant" ]]; then
      _env_set "ANTHROPIC_API_KEY" "$input_ant"
      green "  Saved."
    else
      yellow "  Skipped. AI remediation won't work until you set ANTHROPIC_API_KEY in .env"
    fi
  else
    dim "  ANTHROPIC_API_KEY already configured."
  fi
fi

# ── Validate provided credentials ────────────────────────────────────────
echo ""
dim "  Validating credentials..."

gh_token=$(_env_get "GITHUB_TOKEN")
if [[ -n "$gh_token" ]] && ! _is_placeholder "$gh_token" "ghp_xxxxxxxxxxxx"; then
  gh_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 8 \
    -H "Authorization: token $gh_token" https://api.github.com/user 2>/dev/null || echo "0")
  if [[ "$gh_code" == "200" ]]; then
    green "  GitHub token is valid."
  else
    yellow "  GitHub token returned HTTP $gh_code — double-check it."
  fi
fi

ant_key=$(_env_get "ANTHROPIC_API_KEY")
if [[ -n "$ant_key" ]] && ! _is_placeholder "$ant_key" "sk-ant-xxxxxxxxxxxx"; then
  ant_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 8 \
    -H "x-api-key: $ant_key" -H "anthropic-version: 2023-06-01" \
    "https://api.anthropic.com/v1/models" 2>/dev/null || echo "0")
  if [[ "$ant_code" == "200" ]]; then
    green "  Anthropic API key is valid."
  else
    yellow "  Anthropic key returned HTTP $ant_code — double-check it."
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Step 5: Build and start
# ═════════════════════════════════════════════════════════════════════════════
if $SKIP_START; then
  echo ""
  green "  Setup complete (--skip-start). Run 'docker compose up -d' when ready."
  exit 0
fi

echo ""
bold "[5/5] Starting Nyx..."
cd "$SCRIPT_DIR"
docker compose build --quiet 2>&1 | tail -5
docker compose up -d

printf "  Waiting for backend health check"
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
    red "  Backend didn't start within 120s."
    red "  Check logs: docker compose logs backend"
    exit 1
  fi
done

# ═════════════════════════════════════════════════════════════════════════════
# Done — print summary
# ═════════════════════════════════════════════════════════════════════════════
API_KEY=$(_env_get "NYX_API_KEY")

echo ""
bold "  =========================================="
bold "  Nyx is running!"
bold "  =========================================="
echo ""
green "  Dashboard:   http://localhost:3000"
green "  API:         http://localhost:8000/docs"
echo ""
bold  "  Your API key:"
echo  "  $API_KEY"
echo ""
dim   "  Copy the key above, open http://localhost:3000, click Settings,"
dim   "  and paste it in to authenticate."
echo ""
bold  "  What next?"
dim   "  1. Add a GitHub repo:  Repositories > Add Repository"
dim   "  2. Push the scan workflow to it (one click)"
dim   "  3. Push a commit — Nyx will ingest the scan results automatically"
echo ""
dim   "  Useful commands:"
dim   "    ./nyx.sh status     Show running services and open findings"
dim   "    ./nyx.sh logs       Tail backend logs"
dim   "    ./nyx.sh stop       Stop all services"
dim   "    ./nyx.sh check      Verify all integrations"
dim   "    ./nyx.sh help       Show all commands"
echo ""
