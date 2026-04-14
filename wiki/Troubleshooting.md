# Troubleshooting

The most common things that break, and what to do about them. If your issue is not here, check `./nyx.sh logs`, then `./nyx.sh check`, then open an issue with the output of both.

---

## Setup and startup

### `setup.sh` fails on "Docker not found"
**Cause:** Docker Engine is not installed, or `docker compose` v2 is missing.
**Fix:** Install Docker Engine and Compose v2. On Ubuntu: `curl -fsSL https://get.docker.com | sh` and then `sudo usermod -aG docker $USER` (log out and back in).

### `setup.sh` hangs at "validating GitHub token"
**Cause:** Network issue or proxy blocking GitHub API calls.
**Fix:** Run with `--non-interactive --skip-start` then validate manually: `curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user`.

### Containers come up but the dashboard is a white page
**Cause:** Frontend built with an incorrect `VITE_API_BASE_URL`.
**Fix:** Check browser DevTools console. Usually a CORS error or 502 from the API. `./nyx.sh logs` will show the real error. Rebuild with `./nyx.sh build`.

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

### Cookie session won't persist
- **Not using HTTPS in prod:** cookies with `Secure` flag won't stick on HTTP. Either enable TLS or set `NYX_DEV_MODE=true` for local.
- **SameSite mismatch:** serving frontend and backend on different top-level domains. Host them on the same domain with a path prefix.

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

---

## AI remediation

### Every fix returns `REVIEW_LOW_CONFIDENCE`
- You are scanning obscure languages Claude has weak priors on.
- Your findings lack file/line context — Claude can't see the code.
- Lower `AI_MIN_CONFIDENCE_THRESHOLD` temporarily or switch to `claude-opus-4-6` for higher quality.

### Fix is marked `PARSE_ERROR`
Claude returned an unstructured response twice. The `/remediation/{id}` detail page has the raw text — usually obvious (it wrote prose instead of a diff). Retry the request; if it persists, the finding's prompt may be truncated by `AI_MAX_TOKENS` — raise it.

### AI spend spike
- Someone kicked a big bulk fix. Check the remediation queue.
- A finding is looping (rare — check logs for retry storms).
- The model changed upstream. Set `AI_MODEL` explicitly.
- Add `AI_COST_ALERT_DAILY_USD` if you have not already.

---

## Scanners

### Scan imports return `422 validation error`
Scanner `results` field isn't raw scanner JSON. Some tools wrap output — pass the inner object.

### `scanner: GRYPE` ingests but no findings appear
Grype's empty-state response still validates. Confirm the command actually found something: `grype dir:. -o json | jq '.matches | length'`.

### Trivy SBOM not diffed
- `ENABLE_SBOM` not set or set to `false`.
- Trivy was run without `--format cyclonedx`.

---

## Database

### `OperationalError: database is locked` (SQLite)
SQLite can't handle concurrent writers well. Either:
- **Immediate:** restart (`./nyx.sh restart`)
- **Permanent:** switch to PostgreSQL (see [Deployment](Deployment.md))

### Migration fails on upgrade
1. Back up first: `docker compose exec postgres pg_dump -U nyx nyx > /tmp/nyx-backup.sql`
2. Check `alembic history` for the version gap.
3. If a migration is broken in your installation, `alembic stamp` to the last known-good revision and manually replay the changes.

---

## Frontend

### Changes not appearing after rebuild
Hard-refresh: `Cmd/Ctrl + Shift + R`. Vite's cache is aggressive. In extremes, `docker compose down -v` and rebuild.

### "API key is invalid" right after pasting it
You copied a trailing space or a newline. Re-copy.

---

## Health check commands

```bash
# One-shot self-check
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
