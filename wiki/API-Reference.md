# API Reference

Nyx ships a full OpenAPI specification — the canonical reference is the live Swagger UI at:

```
http://localhost:8000/docs     # dev
https://your-nyx-url/docs      # prod
```

This page is a **grouped overview** of what each router exposes, so you know where to look. For parameter shapes and example requests, use the live docs.

---

## Authentication

Two supported mechanisms:

### Cookie session
Used by the dashboard. `POST /auth/session` with `{"api_key": "..."}` validates the key, mints an opaque random session token (`secrets.token_urlsafe(32)`), stores its SHA-256 hash in the `user_sessions` table, and sets the raw token as an `HttpOnly`, `Secure` (in prod), `SameSite=Strict` cookie. The raw API key never lives in the cookie. `GET /auth/whoami` resolves the cookie to `{identity, scopes}` and is what `ProtectedRoute` calls on page load. `POST /auth/logout` deletes the session row.

### API key header
Used by CI and programmatic clients:

```
X-API-Key: <your-api-key>
```

Keys are scoped. A `scanner` key returns `403` on any non-scan endpoint.

---

## Routers

Each router lives under `backend/app/routers/`. The path prefix is `/api/v1/<router>`.

| Router | Prefix | Purpose |
|---|---|---|
| `dashboard` | `/dashboard` | Aggregate KPIs, risk snapshots, hot repos |
| `findings` | `/findings` | CRUD, search, bulk actions, suppression |
| `repositories` | `/repositories` | Register, list, push workflow, settings |
| `scans` | `/scans` | Ingest results, list history |
| `remediation` | `/remediation` | AI fixes, streaming, alternatives |
| `schedules` | `/schedules` | Scheduled scans CRUD |
| `sla_policies` | `/sla-policies` | SLA policy CRUD |
| `jira` | `/jira` | Ticket create/sync/verify |
| `compliance` | `/compliance` | Framework coverage, custom framework CRUD |
| `reports` | `/reports` | Executive PDF, velocity, AI cost, MTTR |
| `sbom` | `/sbom` | Per-repo SBOM list, diff, alerts |
| `audit` | `/audit` | Audit log search, chain verify |
| `api_keys` | `/api-keys` | Key CRUD with scope |
| `webhooks` | `/webhooks` | GitHub, Snyk, generic receivers |
| `regression_alerts` | `/regression-alerts` | Auto-sort batch alerts |
| `velocity` | `/velocity` | Finding rate metrics, MTTR breakdowns |
| `ai_costs` | `/ai-costs` | Token usage, spend time series |

---

## Notable endpoints

### Ingest scan results
```
POST /api/v1/scans/import
```
The one endpoint every CI pipeline hits. Requires `scanner` or `admin` scope.

### Request an AI fix
```
POST /api/v1/remediation
GET  /api/v1/remediation/{id}
GET  /api/v1/remediation/{id}/stream          (SSE)
POST /api/v1/remediation/{id}/alternatives
POST /api/v1/remediation/{id}/approve
POST /api/v1/remediation/{id}/create_pr
```

### Register a repository
```
POST   /api/v1/repositories
GET    /api/v1/repositories
GET    /api/v1/repositories/{id}
PATCH  /api/v1/repositories/{id}
DELETE /api/v1/repositories/{id}
POST   /api/v1/repositories/{id}/push-workflow
POST   /api/v1/repositories/{id}/detect-scanners
```

### Search findings
```
GET    /api/v1/findings
GET    /api/v1/findings/{id}
PATCH  /api/v1/findings/{id}
POST   /api/v1/findings/{id}/suppress
POST   /api/v1/findings/bulk/status
POST   /api/v1/findings/bulk/ai-fix
POST   /api/v1/findings/bulk/generate-prompt
```

### Verify audit chain
```
GET /api/v1/audit/verify
```
Walks the HMAC hash chain and returns either `{"valid": true}` or the first index where a break is detected.

### Integration health
```
GET /api/v1/health/integrations
```
Returns per-integration `ok`/`error` status. Use it as your uptime probe.

---

## Rate limits

Default: **60 requests per minute per API key**. Configurable via `RATE_LIMIT_PER_MINUTE`. Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header.

The SSE streaming endpoint is exempt — it counts as one request for the lifetime of the stream.

---

## Errors

Every error response has a consistent shape:

```json
{
  "error": "validation_failed",
  "message": "repository_id is required",
  "request_id": "req_01HXYZ...",
  "details": { "field": "repository_id" }
}
```

`request_id` correlates to the entry in the audit log and the backend logs — include it when reporting issues.

---

## Pagination

List endpoints use cursor pagination:

```
GET /api/v1/findings?limit=50&cursor=<opaque>
```

Response:

```json
{
  "items": [ ... ],
  "next_cursor": "<opaque-or-null>",
  "total": 4321
}
```

`total` is returned as a best-effort count and may be approximate for very large result sets.

---

## Webhooks (incoming)

Nyx receives webhooks at:

| Source | Endpoint | Signature header |
|---|---|---|
| GitHub | `/api/v1/webhooks/github` | `X-Hub-Signature-256` |
| Snyk | `/api/v1/webhooks/snyk` | `X-Snyk-Signature` |
| Generic | `/api/v1/webhooks/generic` | `X-Nyx-Signature` |

All incoming webhooks are HMAC-verified before their payload is parsed.

---

## What next

- **Swagger / ReDoc →** `http://localhost:8000/docs` · `http://localhost:8000/redoc`
- **Client generation →** OpenAPI spec is available at `/openapi.json`
- **Dev environment →** [Development Guide](Development.md)
