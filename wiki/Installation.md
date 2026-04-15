# Installation

This page covers everything required to get a working Nyx instance running on a developer workstation or a single server. For production hardening, load balancing, and PostgreSQL migration, continue to **[Production Deployment](Deployment.md)** after finishing here.

---

## Prerequisites

| Requirement | Minimum version | Why |
|---|---|---|
| **Docker Engine** | 24.x | Runs backend and frontend containers |
| **Docker Compose** | v2 (`docker compose`, not `docker-compose`) | Orchestration |
| **Python** | 3 (any 3.x — 3.11+ if running backend without Docker) | `setup.sh` uses it to generate secrets |
| **curl** | Any | Used by `setup.sh` for credential validation |
| **Free RAM** | ~1 GB | Backend + frontend + (optionally) Postgres |
| **Free disk** | ~2 GB | Images, logs, SQLite/Postgres volume |
| **Open ports** | `3000`, `8000` | Frontend and API on the host |

> **Linux / macOS / WSL2 supported.** Native Windows is not supported — use WSL2.
---

## Option A — One-command setup (recommended)

```bash
git clone https://github.com/LeSpookyHacker/nyx.git
cd nyx
./setup.sh
```

The wizard will:

1. **Check tooling.** Verify Docker, Compose, Python 3, and curl are installed.
2. **Bootstrap `.env`.** Copy `.env.example` → `.env` and generate values for `NYX_API_KEY`, `NYX_SECRET_KEY`, and `NYX_WEBHOOK_SECRET` using `secrets.token_hex(32)`.
3. **Prompt for credentials.** Ask for your `GITHUB_TOKEN` and `ANTHROPIC_API_KEY` — press Enter to skip either and you can set them later in **Settings**.
4. **Validate.** Probe GitHub and Anthropic to verify the tokens actually work before writing them.
5. **Build and start.** Run `docker compose build && docker compose up -d`.
6. **Print the dashboard URL and the bootstrap API key.**


### Flags

| Flag | Effect |
|---|---|
| `--non-interactive` | Skip all prompts — useful for CI, automated bakes, or Ansible runs |
| `--skip-start` | Configure `.env` but do **not** launch containers |
| `--help` | Print flag reference |

---

## Option B — Manual setup

If you prefer to see what is happening:

```bash
git clone https://github.com/LeSpookyHacker/nyx.git
cd nyx
cp .env.example .env
```

Edit `.env` and fill the **required** variables:

```bash
# --- Required ---
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_TOKEN=ghp_...
NYX_API_KEY=any-secret-string-you-pick
NYX_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
NYX_WEBHOOK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

All other variables have sane defaults. See **[Configuration Reference](Configuration.md)** for the full list.

Start the stack:

```bash
docker compose up -d
```

Verify it came up:

```bash
docker compose ps
./nyx.sh status
```

---

## First login

| URL | What |
|---|---|
| **http://localhost:3000** | Dashboard (React SPA) |
| **http://localhost:8000/docs** | Interactive OpenAPI docs (Swagger UI) |
| **http://localhost:8000/redoc** | ReDoc API reference |

1. Open **http://localhost:3000**.
2. Nyx redirects you to **Sign in**.
3. Paste the API key that `setup.sh` printed (or whatever you set `NYX_API_KEY` to) and click **Sign in**.
4. The server mints a random opaque session token and stores it in an HTTP-only `SameSite=Strict` cookie. The raw API key never lives in the cookie — revoking the session is a single DB row delete.
5. To mint additional scoped keys (for CI pipelines or other users), open **Settings → API Keys**.


---

## Managing Nyx — the `nyx.sh` helper

Day-to-day operations happen through `./nyx.sh`:

```bash
./nyx.sh              # Start Nyx (or show status if already running)
./nyx.sh status       # Show services and open finding counts
./nyx.sh stop         # Stop all services
./nyx.sh restart      # Restart all services
./nyx.sh build        # Rebuild images after pulling updates
./nyx.sh logs         # Tail backend logs (Ctrl+C to exit)
./nyx.sh check        # Verify every integration credential
./nyx.sh doctor       # End-to-end canary — health, auth, integrations, and a round-trip scan import
./nyx.sh refresh      # Trigger all scan schedules immediately
```

Most of these are thin wrappers around `docker compose` with friendlier output.

---

## Verifying the install

After first login, run the end-to-end canary:

```bash
./nyx.sh doctor
```

`doctor` checks `/health` and `/ready`, proves the cookie auth flow works end-to-end (`POST /auth/session` → `GET /auth/whoami`), verifies API-key header auth, probes every integration, and — if the platform is live — creates a canary repo, imports a dummy scan, polls for ingestion, and cleans itself up. Any red line tells you exactly what is broken before you invite teammates.

For a lighter check (credentials only, no round-trip) run:

```bash
./nyx.sh check
# or
curl -s -H "X-API-Key: $NYX_API_KEY" http://localhost:8000/health/integrations | jq
```

You should see per-integration status for `database`, `anthropic`, `github`, `jira`, and `webhook_notifier`. Each returns `ok` / `error` plus a short message.


---

## Uninstall / reset

```bash
./nyx.sh stop
docker compose down -v    # -v also removes the database volume
rm -f .env                # delete generated secrets
```

Re-run `./setup.sh` to rebuild from a blank slate.

---

## What next

- **Register your first repository and pull in findings →** [First-Time Walkthrough](First-Time-Walkthrough.md)
- **Expose Nyx to the internet so GitHub can reach the webhook →** [GitHub Integration](GitHub-Integration.md)
- **Set up automated CI/CD scans →** [CI/CD Integration](CICD-Integration.md)
