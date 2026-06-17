# Production Deployment

Getting Nyx from "runs on my laptop" to "runs in front of real users." This page covers PostgreSQL, TLS, backups, and the minimum set of things you should check before pointing GitHub at a public URL.

---

## Prerequisites

- A Linux host (or WSL2 for evaluation)
- Docker + Compose v2
- A real domain name with DNS pointing at the host
- Ports 80 and 443 open
- A sane backup target (S3, B2, or just another disk)

---

## 1. Switch to PostgreSQL

SQLite is fine for evaluation. In production use PostgreSQL — it survives concurrent access, backs up cleanly, and handles hundreds of thousands of findings without blinking.

```bash
# Stop Nyx
./nyx.sh stop

# Start with the Postgres compose file
docker compose -f docker-compose.postgres.yml up -d
```

Set in `.env`:

```bash
DATABASE_URL=postgresql+asyncpg://nyx:nyx_password@postgres:5432/nyx
```

Alembic migrations run automatically on backend startup.


---

## 2. Put a reverse proxy in front

### Nginx + Let's Encrypt (minimum viable)

```nginx
server {
    listen 80;
    server_name nyx.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name nyx.example.com;

    ssl_certificate     /etc/letsencrypt/live/nyx.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nyx.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE streaming
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }

    # Webhook receiver
    location /api/v1/webhooks/ {
        proxy_pass http://127.0.0.1:8000;
        client_max_body_size 10M;
    }
}
```

Get a cert:

```bash
sudo certbot --nginx -d nyx.example.com
```



---

## 3. Production `.env` settings

```bash
# --- Hard requirements ---
NYX_API_KEY=<strong random>
NYX_SECRET_KEY=<64 hex>
NYX_WEBHOOK_SECRET=<64 hex>
DATABASE_URL=postgresql+asyncpg://nyx:...@postgres:5432/nyx
GITHUB_WEBHOOK_ENDPOINT=https://nyx.example.com

# --- Hardening ---
ENVIRONMENT=production
HTTPS_ONLY=true
CORS_ORIGINS_STR=https://nyx.example.com
TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12
REQUIRE_SUBMISSION_HMAC=true
GITHUB_WEBHOOK_IP_ALLOWLIST_ENABLED=true
API_KEY_MAX_LIFETIME_DAYS=90
LOG_LEVEL=INFO
```

> Setting `NYX_SECRET_KEY` in production also turns on Fernet encryption at rest for `scans.raw_output` and the webhook secret column — the first boot blocks on a backfill migration that re-encrypts any pre-existing plaintext rows.

---

## 4. Database migrations

Schema is managed by SQLAlchemy `create_all` and runs automatically on every container start via `entrypoint.sh`. Alembic is not configured — there are no migration files to run. New columns on existing tables are handled by the `_migrate_add_columns` helper in `database.py`.

Always back up before schema-breaking changes:

```bash
# PostgreSQL backup
docker compose exec postgres pg_dump -U nyx nyx > nyx-backup.sql
```

---

## 5. Backups

### PostgreSQL

```bash
# Daily cron
docker compose exec -T postgres pg_dump -U nyx nyx | \
  gzip > /backups/nyx-$(date +%F).sql.gz

# Retention (keep 30 days)
find /backups -name 'nyx-*.sql.gz' -mtime +30 -delete
```

### Logs

Backend logs are in a named volume — nothing to do. For offsite retention, ship to Loki, Datadog, or CloudWatch via a log shipper sidecar.

### Restore test

Once a quarter, restore to a staging instance:

```bash
gunzip -c /backups/nyx-2026-01-15.sql.gz | \
  docker compose exec -T postgres psql -U nyx nyx
```

---

## 6. Monitoring

Minimum probes:

| Check | Endpoint / command | Frequency |
|---|---|---|
| **Liveness** | `GET /health` | 30s |
| **Readiness** | `GET /health/ready` | 30s |
| **Integrations** | `GET /health/integrations` | 5 min |
| **Disk** | `df -h` on the host | 1 min |
| **Audit chain** | `GET /audit/verify` | 1 h |
| **AI spend** | Nyx dashboard card | daily |

For Grafana, scrape the health endpoints and chart `status == ok` per integration. Page on three consecutive failures.

---

## 7. Scaling out

When you outgrow a single box:

1. **Move Postgres to a managed service** (RDS, Cloud SQL, Supabase) and update `DATABASE_URL`.
2. **Backend scaling** — Nyx is designed around a single-leader backend. The lifespan hook spawns in-process worker loops (SLA escalation, schedule tick, Code Scanning sync, JIRA sync, risk snapshots) on startup, and those loops are not coordinated across replicas. For now, run a single backend container per deployment; put the reverse proxy in front of it for TLS and static-asset caching, not for horizontal scaling.
3. **Shared file storage** is not required — Nyx stores everything in the DB.
4. **Frontend is static** — build once, serve from a CDN if you like.

---

## 8. Upgrading

```bash
git pull
./nyx.sh build
./nyx.sh restart
./nyx.sh check
```

Migrations run automatically. For breaking-change releases, read the changelog first and back up before upgrading.

---

## 9. Minimum hardening checklist

Before pointing the outside world at Nyx, confirm all of:

- [ ] `NYX_API_KEY` set, and the bootstrap key has been rotated or revoked via Settings → API Keys
- [ ] `NYX_SECRET_KEY` and `NYX_WEBHOOK_SECRET` are random, not `change-me`
- [ ] `ENVIRONMENT=production` and `HTTPS_ONLY=true`
- [ ] `CORS_ORIGINS_STR` restricted to your dashboard hostname (no wildcard)
- [ ] `TRUSTED_PROXY_CIDRS` lists only your reverse proxy's private CIDRs
- [ ] `REQUIRE_SUBMISSION_HMAC=true` if CI submits scans
- [ ] `GITHUB_WEBHOOK_IP_ALLOWLIST_ENABLED=true` if webhooks come from github.com
- [ ] TLS certificate valid and renewing automatically
- [ ] Database backups running and a restore has been tested
- [ ] Separate API keys for CI — `scanner` scope only, never `admin`
- [ ] GitHub App installed (not a long-lived PAT) for prod org
- [ ] `./nyx.sh doctor` returns clean end-to-end before handing out the URL
- [ ] Log shipping in place if you need retention beyond the rotating file handler

---

## What next

- **Full security threat model →** [Security Hardening](Security.md)
- **Troubleshooting when something breaks →** [Troubleshooting](Troubleshooting.md)
