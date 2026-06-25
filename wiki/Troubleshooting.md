# Troubleshooting

The most common things that break, and what to do about them. If your issue is not here, start with `./nyx.sh doctor` — it runs an end-to-end canary (health → auth → integrations → round-trip scan import) and tells you exactly which step fails. Then `./nyx.sh logs` for the traceback, and finally open an issue with the output of both.

---

## Setup and startup

### `setup.sh` fails on "Docker not found"
**Cause:** Docker Engine is not installed, or `docker compose` v2 is missing.
**Fix:** Install Docker Engine and Compose v2. On Ubuntu: `curl -fsSL https://get.docker.com | sh` and then `sudo usermod -aG docker $USER` (log out and back in).

### `setup.sh` hangs at "validating GitHub token"
**Cause:** Network issue or proxy blocking GitHub API calls.
**Fix:** Run with `--non-interactive --skip-start` then validate manually: `curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user`.

### Containers come up but the dashboard is a white page
**Cause:** The frontend container is up but the backend behind the Nginx proxy is not, so every API call fails.
**Fix:** Check browser DevTools console — usually a 502 from `/api/*` or `/auth/*`. Run `./nyx.sh doctor` to see exactly which step fails, and `./nyx.sh logs` for the backend traceback. Rebuild with `./nyx.sh build` if a stale image is suspected.

### Backend restarts every 30 seconds
**Cause:** Healthcheck failing, Docker's `restart: unless-stopped` policy respawning the container.
**Fix:** `docker compose logs backend --tail=200` — look for tracebacks. Common culprits: invalid `DATABASE_URL`, missing `NYX_SECRET_KEY`, bad Anthropic key.

<!-- IMAGE: `docker compose logs backend` output showing a traceback.
     File: wiki/images/troubleshoot-logs.png -->
![Backend logs with error](images/troubleshoot-logs.png)
<!-- /IMAGE -->

---

## Authentication

### `401 Unauthorized` on every API call
- **Header typo:** it is `X-API-Key`, not `X-Api-Key` or `Authorization`.
- **Key not seeded:** on first start, Nyx seeds a key from `NYX_API_KEY`. If that was unset, no key exists. Either set it and restart, or create one via the dashboard.
- **Key revoked or expired:** check Settings → API Keys.
- **Scanner-scoped key returns 401 from CI:** if your key was created with an expiry and the backend logs show `DB API key lookup failed … TypeError: can't compare offset-naive and offset-aware datetimes`, you are on a version prior to the timezone fix. Pull the latest and rebuild the backend image (`docker compose build backend && docker compose up -d backend`).

### Cookie session won't persist
- **Not using HTTPS in prod:** cookies with the `Secure` flag won't stick on HTTP. Either enable TLS, or leave `ENVIRONMENT=development` / `HTTPS_ONLY=false` for local use.
- **SameSite mismatch:** the session cookie is `SameSite=Strict`, which means the dashboard and API must share a parent origin. Serve both under the same host (the shipped compose stack already does — the frontend proxies `/api` and `/auth` to the backend).

---

## GitHub

### Webhooks not firing
1. Confirm `GITHUB_WEBHOOK_ENDPOINT` is correct in `.env`.
2. Check the webhook on GitHub → Repo → Settings → Webhooks → Recent Deliveries. If you see attempts, inspect the response.
3. If GitHub shows 401, your `NYX_WEBHOOK_SECRET` does not match the per-repo secret in the DB. Re-install from Nyx.
4. If GitHub shows connection refused, your tunnel/proxy is down.

### `403 Resource not accessible by integration` on push workflow
Your PAT is missing the **Workflows** permission. Edit the token, add the scope, restart backend.

### `404 Not Found` when registering a repository
- Token cannot see the repo — check fine-grained PAT repo access.
- Repo name typo — it must be `owner/name`, case-sensitive.

### Multiple webhooks / `401` signature always fails

If you've added and removed a repository multiple times (or clicked **Add** while debugging), GitHub may have accumulated several Nyx webhooks for the same repo. Only the most recently registered one matches Nyx's stored per-repo secret — older ones will always return `401 invalid signature`.

**Fix:**
1. Go to **GitHub → your repo → Settings → Webhooks**
2. Delete **all** Nyx webhooks except the most recently created one
3. Verify the remaining webhook's URL ends in `/api/v1/webhooks/github` and matches your current `GITHUB_WEBHOOK_ENDPOINT`
4. Trigger a test delivery (click the webhook → **Recent Deliveries** → **Redeliver** the ping) and confirm it returns `200`

> After re-adding a repo in Nyx, always check GitHub's webhook list to make sure only one remains.

### Config changes not taking effect after editing `.env`

Nyx reads environment variables once at container startup and caches them via `@lru_cache`. Editing `.env` while containers are running has **no effect** until you recreate the containers.

**To apply `.env` changes:**
```bash
docker compose up -d   # stops, recreates, and restarts containers with the new env
```

`docker compose restart` alone does **NOT** re-read `.env` — it only bounces the process inside the existing container, which still has the old environment baked in.

**Common symptom:** You updated `GITHUB_WEBHOOK_ENDPOINT` in `.env`, re-added a repo in Nyx, but the newly registered webhook on GitHub still points to the old URL. The new webhook was created using the cached (stale) value from before your edit. Fix: run `docker compose up -d`, then delete the stale webhook on GitHub and re-add the repo.

---

## Auto PR Mode

### Auto PR budget never resets / constant `BUDGET_EXCEEDED`

**Cause:** The daily budget-reset loop (`_auto_pr_budget_reset_loop` in `main.py`) only starts when
`AUTO_PR_MODE_ENABLED=true` in the environment. If the master switch is off, per-repo
`auto_pr_mode=true` settings still allow the pipeline to run — but tokens accumulate and never roll
over, causing every subsequent finding to hit `BUDGET_EXCEEDED`.

**Fix:** Set `AUTO_PR_MODE_ENABLED=true` in `.env` and recreate the containers:
```bash
docker compose up -d
```

If the budget is already exhausted mid-day and you need an immediate reset, run directly against the database:
```sql
-- SQLite
UPDATE repositories SET auto_pr_tokens_used_today = 0 WHERE auto_pr_mode = 1;
-- PostgreSQL
UPDATE repositories SET auto_pr_tokens_used_today = 0 WHERE auto_pr_mode = true;
```

### Auto PR pipeline triggers but no PRs are opened

1. Confirm `AUTO_PR_MODE_ENABLED=true` (master switch).
2. Confirm the per-repo toggle is on: Repositories → repo → Auto PR Mode.
3. Confirm `GITHUB_TOKEN` has `repo` and `workflow` scopes — the PR and branch creation require both.
4. Check the Remediation page for the finding: the status column will show which gate blocked it
   (`AUDIT_FAILED`, `TEST_FAILED`, `REVIEW_LOW_CONFIDENCE`, `BUDGET_EXCEEDED`).
5. Check backend logs: `docker compose logs backend | grep auto_pr` for the audit events.

---

## AI remediation

### Every fix returns `REVIEW_LOW_CONFIDENCE`
- You are scanning obscure languages Claude has weak priors on.
- Your findings lack file/line context — Claude can't see the code.
- Lower `AI_MIN_CONFIDENCE_THRESHOLD` temporarily, or switch `ANTHROPIC_MODEL` to `claude-opus-4-6` for higher quality.

### Fix is marked `PARSE_ERROR`
Claude returned an unstructured response twice. The `/remediation/{id}` detail page has the raw text — usually obvious (it wrote prose instead of a diff). Retry the request; if it persists, the response may be getting truncated — raise `AI_MAX_OUTPUT_TOKENS` (default `8192`).

### AI spend spike
- Someone kicked a big bulk fix. Check the remediation queue and the AI Cost dashboard.
- A finding is looping (rare — check logs for retry storms).
- The model changed upstream. Pin `ANTHROPIC_MODEL` explicitly in `.env`.

---

## Scanners

### Scan imports return `422 validation error`
Scanner `results` field isn't raw scanner JSON. Some tools wrap output — pass the inner object.

### `scanner: GRYPE` ingests but no findings appear
Grype's empty-state response still validates. Confirm the command actually found something: `grype dir:. -o json | jq '.matches | length'`.

### Trivy SBOM not diffed
- Trivy was run without `--format cyclonedx`.
- The SBOM payload was uploaded to the scan record but the component hash matches the previous snapshot — diffing only emits alerts on deltas.

---

## Database

### `OperationalError: database is locked` (SQLite)
SQLite can't handle concurrent writers well. Either:
- **Immediate:** restart (`./nyx.sh restart`)
- **Permanent:** switch to PostgreSQL (see [Deployment](Deployment.md))

### Schema errors on startup
1. Back up first: `docker compose exec postgres pg_dump -U nyx nyx > /tmp/nyx-backup.sql`
2. Check backend logs: `docker compose logs backend` — `create_all` errors will appear here.
3. Nyx does not use Alembic migration files. Schema is created via `Base.metadata.create_all` in `database.py`. New columns are added by `_migrate_add_columns` on startup. If a column is missing, the container logs will show the error and the helper will attempt to add it.

---

## Frontend

### Changes not appearing after rebuild
Hard-refresh: `Cmd/Ctrl + Shift + R`. Vite's cache is aggressive. In extremes, `docker compose down -v` and rebuild.

### "API key is invalid" right after pasting it
You copied a trailing space or a newline. Re-copy.

---

## Health check commands

```bash
# End-to-end canary (recommended first step)
./nyx.sh doctor

# One-shot credentials self-check
./nyx.sh check

# Backend liveness
curl -f http://localhost:8000/health

# Full integration status
curl -s -H "X-API-Key: $NYX_API_KEY" \
  http://localhost:8000/health/integrations | jq

# Audit chain integrity
curl -s -H "X-API-Key: $NYX_API_KEY" \
  http://localhost:8000/api/v1/audit/verify | jq
```

---

## When all else fails

1. `./nyx.sh logs | tail -200` — real errors are usually obvious
2. `docker compose ps` — is everything actually up?
3. `docker compose down && docker compose up -d --force-recreate`
4. Open an issue with:
   - Output of `./nyx.sh check`
   - Relevant section of backend logs
   - Exact command / UI action that triggered the issue
   - `git log -1 --oneline` so we know which version you're on

<!-- IMAGE: Example of a clean GitHub issue with all the right attached info.
     File: wiki/images/good-issue.png -->
![Good issue example](images/good-issue.png)
<!-- /IMAGE -->
