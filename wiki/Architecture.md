# Architecture

How Nyx is put together, why those choices were made, and how data moves through the system.

---

## High-level diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Developer Workflow                             │
│   git push → GitHub Webhook → Nyx → Run Scanners → Ingest Findings     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                   ┌────────────────▼────────────────┐
                   │          Nyx Backend             │
                   │         (FastAPI + Python)        │
                   │                                  │
                   │  ┌──────────┐  ┌─────────────┐  │
                   │  │ Webhooks │  │   Routers   │  │
                   │  │ Receiver │  │  (REST API) │  │
                   │  └────┬─────┘  └──────┬──────┘  │
                   │       │               │          │
                   │  ┌────▼───────────────▼──────┐  │
                   │  │       Core Services        │  │
                   │  │  Deduplication │ Priority  │  │
                   │  │  AI Service    │ JIRA      │  │
                   │  │  GitHub        │ Notify    │  │
                   │  │  Compliance    │ SBOM      │  │
                   │  └────────────────┬───────────┘  │
                   │                   │               │
                   │  ┌────────────────▼────────────┐ │
                   │  │   Background Workers         │ │
                   │  │  SLA Checker    (hourly)     │ │
                   │  │  Risk Snapshots (daily)      │ │
                   │  │  Scan Schedules (5 min)      │ │
                   │  │  Suppression Expiry (hourly) │ │
                   │  │  Key Expiry Warnings (daily) │ │
                   │  └────────────────┬─────────────┘ │
                   │                   │                │
                   │  ┌────────────────▼────────────┐  │
                   │  │  Database (SQLite/Postgres)  │  │
                   │  └──────────────────────────────┘ │
                   └─────────────────┬───────────────┘
                                     │
           ┌─────────────────────────┼───────────────────────┐
           │                         │                       │
   ┌───────▼──────┐    ┌─────────────▼────────┐    ┌────────▼──────┐
   │   Nyx UI     │    │     GitHub API        │    │   JIRA API    │
   │ (React SPA)  │    │  Webhooks · PRs       │    │   Tickets     │
   │  Dashboard   │    │  Check Runs · Code    │    │   Status sync │
   │  Reports     │    │  Scanning             │    │               │
   └──────────────┘    └───────────────────────┘    └───────────────┘
```


---

## Components

### Backend — FastAPI

Python 3.11+ async FastAPI app. Stateless — any instance can serve any request. All persistent state lives in the database.

**Key directories** (under `backend/app/`):

| Path | Role |
|---|---|
| `main.py` | App entry point, router mounting, startup hooks |
| `config.py` | Typed settings loaded from environment |
| `database.py` | SQLAlchemy async engine + session factory |
| `models/` | SQLAlchemy ORM models (one file per aggregate) |
| `schemas/` | Pydantic request/response schemas |
| `routers/` | FastAPI routers — one file per resource |
| `services/` | Business logic (dedup, priority, AI, GitHub, JIRA, SBOM, compliance, notifications, audit) |
| `services/normalization/` | One file per scanner — `AbstractNormalizer` implementations |
| `workers/` | Background workers (SLA, schedules, risk snapshots, etc.) |
| `core/` | Cross-cutting concerns: auth, logging, exceptions |

### Frontend — React + Vite

TypeScript, React 18, Tailwind CSS, Zustand for state.

**Key directories** (under `frontend/src/`):

| Path | Role |
|---|---|
| `pages/` | Top-level routes (`DashboardPage.tsx`, `FindingsPage.tsx`, …) |
| `components/` | Reusable UI — cards, tables, modals, forms |
| `api/` | Typed API client (wraps the FastAPI REST surface) |
| `store/` | Zustand stores for cross-page state |
| `hooks/` | Custom hooks for data fetching and UI behavior |
| `constants/`, `types/` | Enums, interfaces, severity colors |

### Database

Two supported backends:

- **SQLite** — default, used for local dev and evaluation. Single file under `backend/data/`.
- **PostgreSQL** — recommended for production. Switch via `docker-compose.postgres.yml` and `DATABASE_URL`.

Schema is managed by **Alembic** (`backend/alembic/`). Migrations run automatically on container start via `entrypoint.sh`.

### Background workers

Not separate processes — they are asyncio tasks spawned from the FastAPI app at startup. Each runs on its own interval loop. If you scale to multiple backend replicas, gate workers to a single instance via the `NYX_WORKER_LEADER` env flag or run them in a dedicated single-replica deployment.

| Worker | Interval | Purpose |
|---|---|---|
| SLA checker | hourly | Escalate breaches, mark overdue |
| Scan schedules | 5 min | Trigger CI scans when a schedule is due |
| Risk snapshots | daily | Record per-repo and org-wide risk score |
| Suppression expiry | hourly | Expire old suppressions |
| Key expiry warnings | daily | Warn on API keys nearing expiry |
| Code Scanning sync | configurable | Poll GitHub for code scanning results |
| SBOM drift | per-scan | Diff against previous SBOM and alert |

### Container restart policy

The backend and frontend containers run under Docker's native `restart: unless-stopped` policy. An earlier `willfarrell/autoheal` sidecar was removed because it required mounting `/var/run/docker.sock`, which grants host-level Docker access and enables container escape if the sidecar is compromised.

---

## End-to-end data flow

The path a single finding takes from scanner output to "closed":

```
1.  Developer pushes code to GitHub
2.  GitHub webhook fires → Nyx /webhooks/github
3.  Nyx verifies the webhook HMAC and triggers configured scans
    (either via GitHub Actions dispatch or by registering a scan-due event)
4.  Scanner runs in CI and pushes JSON to POST /scans/import
5.  scan_worker processes results:
      a. Normalize raw output → Finding schema
      b. Deduplicate against existing findings (fingerprint match)
      c. Detect regressions:
          - If previously FIXED → mark is_regression, alert
          - If previously ACCEPTED_RISK/SUPPRESSED with auto_close_status
            → restore status, batch into regression auto-sort alert
      d. Compute priority score (CVSS + EPSS + age + SLA factor)
      e. Compute SLA deadline from active policy
      f. Publish inline annotations to GitHub Check Run on the PR
6.  Security engineer reviews the finding in the dashboard
7.  Engineer clicks "Request AI Fix" (single or bulk)
8.  Claude generates a targeted fix, streamed via SSE
9.  Diff is scanned for dangerous patterns; confidence is recorded
10. If confidence ≥ threshold and diff is clean, Nyx creates a GitHub PR
11. JIRA ticket is created and linked to the finding and the PR
12. Developer reviews, approves, and merges the PR
13. GitHub webhook fires (PR merged) → Nyx closes finding and JIRA ticket
```


---

## Storage model (simplified)

```
Repository 1 ─── * Scan
Repository 1 ─── * SLAPolicy
Repository 1 ─── * ScanSchedule
Repository 1 ─── * RepoRiskHistory
Repository 1 ─── 1 Sbom (latest) + 1 Sbom (previous)

Scan 1 ─── * Finding

Finding 1 ─── * Remediation
Finding 1 ─── * JiraLink
Finding 1 ─── * RiskAcceptance
Finding 1 ─── * SuppressionPattern (via fingerprint match)

AuditLogEntry — HMAC hash-chained, append-only
ApiKey — scoped, expiring
RegressionAutoAlert — batched alerts for auto-sort events
```

Concrete models live in `backend/app/models/` — one file per aggregate root.

---

## Authentication and authorization

- **Cookie-based session** for the dashboard, backed by a server-side session store.
- **API keys** for programmatic access (`X-API-Key` header). Keys are database-backed and carry a scope: `scanner`, `readonly`, `analyst`, or `admin`.
- **HMAC-verified webhooks** — GitHub, Snyk, and notification receivers all validate signatures. The secret is generated per-repo on webhook install.
- **Per-request audit entry** — every mutating request writes an entry to the hash-chained audit log with actor, target, action, and old→new diff.

See **[Security Hardening](Security.md)** for the full threat model.

---

## Why FastAPI + React?

- **FastAPI**: async + Pydantic + OpenAPI generation out of the box. Swagger and ReDoc exist for free and the React client is generated from the same schema. Workers live alongside the API in a single process which keeps the dev footprint small.
- **React + Vite**: Vite's dev server is ~50ms reload; the bundle is small; TypeScript support is first-class. Tailwind keeps the Nyx dark/purple theme consistent across pages without CSS bikeshedding.
- **SQLAlchemy 2.0 async**: lets the same session handle request I/O and worker loops without a separate ORM for each.
- **Claude Sonnet**: the balance of quality vs cost for targeted code fixes. Opus is available by changing the model ID in `ai_service.py`; Haiku works for lower-stakes bulk summarization.

---

## Scaling considerations

| Dimension | Guidance |
|---|---|
| **Request volume** | Scale backend replicas horizontally behind a load balancer. Workers must run on a single leader instance or be guarded by the `NYX_WORKER_LEADER` flag. |
| **Database** | SQLite is fine up to a few thousand findings. Move to PostgreSQL as soon as you have more than one engineer using the dashboard or more than 10 registered repositories. |
| **AI cost** | Bulk fix requests serialize per-finding Claude calls. Set `AI_MAX_CONCURRENT` to throttle. Monitor spend via the AI Cost dashboard. |
| **Log volume** | Rotating file handler caps at 50 MB × 5 files per container. For long retention, ship logs to an external sink (Loki, Datadog, CloudWatch). |
| **Webhook bursts** | GitHub will retry failed webhook deliveries. The `/webhooks/github` handler is idempotent on `delivery_id`. |

---

## What next

- **Trace a single request →** [API Reference](API-Reference.md)
- **Add a scanner →** [Adding a Scanner](Adding-a-Scanner.md)
- **Deploy to production →** [Production Deployment](Deployment.md)
