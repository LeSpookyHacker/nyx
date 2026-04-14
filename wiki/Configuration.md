# Configuration Reference

Every environment variable Nyx reads, grouped by subsystem. Defaults are what you get if the variable is unset — only override what you need.

> **Source of truth:** `backend/app/config.py` and `.env.example`. If this page drifts from the code, the code wins.

---

## Required variables

These must be set before Nyx will start in production mode. `setup.sh` generates them automatically.

| Variable | Example | Purpose |
|---|---|---|
| `NYX_API_KEY` | `change-me-in-prod` | Bootstrap API key, seeded with `admin` scope on first run |
| `NYX_SECRET_KEY` | `<64 hex chars>` | Session cookie signing, CSRF tokens |
| `NYX_WEBHOOK_SECRET` | `<64 hex chars>` | HMAC secret used by the global webhook receiver |
| `ANTHROPIC_API_KEY` | `sk-ant-...` | AI fix generation |
| `GITHUB_TOKEN` | `ghp_...` | GitHub integration (PAT) — **or** use `GITHUB_APP_ID` + `GITHUB_PRIVATE_KEY_PATH` |

> **Dev tip:** leaving `NYX_API_KEY` blank disables auth for local evaluation. Never do this in anything reachable from the internet.

---

## Database

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/nyx.db` | Full async SQLAlchemy URL. Postgres example: `postgresql+asyncpg://user:pass@host:5432/nyx` |
| `DB_POOL_SIZE` | `10` | Connections in the pool (Postgres only) |
| `DB_MAX_OVERFLOW` | `20` | Overflow connections beyond the pool |
| `DB_ECHO` | `false` | Log every SQL statement — useful for debugging, expensive otherwise |

---

## GitHub

| Variable | Default | Notes |
|---|---|---|
| `GITHUB_TOKEN` | — | Fine-grained PAT. See [GitHub Integration](GitHub-Integration.md) for required scopes |
| `GITHUB_APP_ID` | — | Use a GitHub App instead of a PAT for production |
| `GITHUB_PRIVATE_KEY_PATH` | — | Path to the App's private key PEM (mount as a Docker secret) |
| `GITHUB_WEBHOOK_ENDPOINT` | — | Public URL GitHub will hit, e.g. `https://nyx.example.com` |
| `GITHUB_WEBHOOK_AUTO_INSTALL` | `true` | Install webhook automatically on repo registration |
| `CODE_SCANNING_SYNC_ENABLED` | `false` | Poll GitHub Code Scanning API |
| `CODE_SCANNING_POLL_INTERVAL` | `3600` | Seconds between polls |

---

## JIRA

| Variable | Default | Notes |
|---|---|---|
| `JIRA_URL` | — | `https://your-org.atlassian.net` |
| `JIRA_USER_EMAIL` | — | Owner of the API token |
| `JIRA_API_TOKEN` | — | Token from id.atlassian.com |
| `JIRA_DEFAULT_PROJECT_KEY` | `SEC` | Project key for new tickets |
| `JIRA_MOCK_MODE` | `false` | Log instead of creating real tickets — useful for tests |
| `JIRA_SYNC_INTERVAL` | `600` | Bidirectional sync poll interval (seconds) |

---

## AI / remediation

| Variable | Default | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Required for any AI feature |
| `AI_MODEL` | `claude-sonnet-4-6` | Model ID. Can swap to Opus for quality or Haiku for cost |
| `AI_MAX_TOKENS` | `8000` | Per-fix output cap |
| `AI_MIN_CONFIDENCE_THRESHOLD` | `0.7` | Fixes below this confidence are flagged `REVIEW_LOW_CONFIDENCE` |
| `AI_MAX_CONCURRENT` | `3` | Concurrent in-flight fix requests |
| `AI_COST_ALERT_DAILY_USD` | `50` | Trigger a notification if daily spend exceeds this |
| `AI_DIFF_SCAN_ENABLED` | `true` | Scan generated diffs for dangerous patterns |

---

## Security

| Variable | Default | Notes |
|---|---|---|
| `NYX_API_KEY` | — | Bootstrap admin key |
| `NYX_SECRET_KEY` | — | Session signing key |
| `NYX_WEBHOOK_SECRET` | — | Global webhook HMAC secret |
| `SESSION_MAX_AGE` | `86400` | Session cookie TTL (seconds) |
| `CSRF_ENABLED` | `true` | Enforce CSRF tokens on state-changing routes |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated origins. Set to your dashboard URL in prod |
| `AUTH_LOCKOUT_MAX_ATTEMPTS` | `5` | Failed attempts before a temporary lockout |
| `AUTH_LOCKOUT_WINDOW` | `900` | Lockout window in seconds |
| `SUPPRESSION_MAX_AGE_DAYS` | `180` | Auto-expire suppressions older than this |

---

## Notifications

| Variable | Default | Notes |
|---|---|---|
| `NOTIFICATION_WEBHOOK_URL` | — | Slack/Teams/generic webhook for alerts |
| `NOTIFICATION_CHANNELS` | `critical,sla_breach,regression` | Comma-separated list of event types |
| `NOTIFICATION_DAILY_DIGEST_ENABLED` | `true` | Daily summary of new findings |
| `NOTIFICATION_DIGEST_TIME` | `09:00` | HH:MM in backend TZ |

---

## Workers / scheduling

| Variable | Default | Notes |
|---|---|---|
| `NYX_WORKER_LEADER` | `true` | Whether this instance runs background workers. Set `false` on secondary replicas |
| `SLA_CHECK_INTERVAL` | `3600` | SLA escalation loop (seconds) |
| `RISK_SNAPSHOT_HOUR` | `2` | Hour of day (UTC) to record daily risk |
| `SCHEDULE_TICK_INTERVAL` | `300` | Scan-schedule poll interval |

---

## Logging

| Variable | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_FORMAT` | `json` | `json` or `text` |
| `LOG_FILE_PATH` | `/app/logs/nyx.log` | Inside the container. Backed by a named volume |
| `LOG_MAX_BYTES` | `52428800` | 50 MB — rotating handler threshold |
| `LOG_BACKUP_COUNT` | `5` | Number of rotated files to keep |

---

## Feature flags

| Variable | Default | Notes |
|---|---|---|
| `ENABLE_SBOM` | `true` | Generate and diff SBOMs per repo |
| `ENABLE_AUDIT_CHAIN` | `true` | HMAC hash chain on the audit log |
| `ENABLE_AI_COST_DASHBOARD` | `true` | Track token spend |
| `ENABLE_CUSTOM_COMPLIANCE` | `true` | Allow user-defined compliance frameworks |

---

## Development-only

| Variable | Default | Notes |
|---|---|---|
| `NYX_DEV_MODE` | `false` | Enables stack traces in API errors, disables cookie Secure flag |
| `NYX_SEED_DEMO` | `false` | Populate DB with realistic demo findings on first start |

---

## Where variables are read

- **`backend/app/config.py`** — all backend variables funnel through a Pydantic `Settings` class.
- **`frontend/vite.config.ts`** — frontend build-time variables (prefix `VITE_`).
- **`docker-compose.yml`** / **`docker-compose.postgres.yml`** — injects variables into the backend container.
- **`setup.sh`** — generates the initial `.env` with safe defaults.

---

## What next

- **Expose Nyx to GitHub →** [GitHub Integration](GitHub-Integration.md)
- **Harden before deploying publicly →** [Security Hardening](Security.md)
- **Move from SQLite to Postgres →** [Production Deployment](Deployment.md)
