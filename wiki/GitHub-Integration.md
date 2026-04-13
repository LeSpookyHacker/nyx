# GitHub Integration

Nyx uses GitHub for three things: **reading repository contents** (so AI fixes have context), **writing pull requests** (so fixes become merge-ready), and **receiving webhooks** (so the dashboard reflects reality without polling). This page walks through all three.

---

## Choose your authentication method

| Method | Use when | Rate limits | Setup |
|---|---|---|---|
| **Personal Access Token (PAT)** | Single developer, evaluation, small team | 5 000 req/hr | Fast — one token, one env var |
| **Fine-grained PAT** | Small-to-medium org, scoped to specific repos | 5 000 req/hr | As fast as classic PAT, with tighter permissions |
| **GitHub App** | Production, org-wide installation, multiple tenants | 15 000 req/hr + higher per-installation quotas | More steps — recommended for anything you call "prod" |

---

## Option A — Fine-grained PAT (recommended for evaluation)

### 1. Create the token

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Name it `nyx-security-platform`
4. Set an expiration (1 year is a reasonable default)
5. Under **Repository access**, pick **All repositories** or select specific repos
6. Grant the following **Repository permissions**:

| Permission | Access | Why |
|---|---|---|
| **Contents** | Read and write | Create fix PRs |
| **Metadata** | Read-only | Mandatory for any repo API |
| **Pull requests** | Read and write | Open fix PRs |
| **Webhooks** | Read and write | Auto-install Nyx webhooks |
| **Workflows** | Read and write | Required for the **Push Workflow** feature (deploys `nyx-scan.yml`) |
| **Checks** | Read and write | PR annotations as GitHub Check Runs |
| **Security events** | Read-only | Sync GitHub Code Scanning alerts |

7. Generate and copy the token.

<!-- IMAGE: The GitHub fine-grained PAT permission screen with the above boxes checked.
     File: wiki/images/github-pat-permissions.png -->
![GitHub PAT permissions](images/github-pat-permissions.png)
<!-- /IMAGE -->

### 2. Store it in Nyx

Edit `.env` and set:

```bash
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Restart the backend:

```bash
./nyx.sh restart
./nyx.sh check    # verify github.status == "ok"
```

> **Gotcha:** if you created a PAT before the **Workflows** feature existed, editing the token to add the workflow scope **does not change the token value** — the existing value still works.

---

## Option B — GitHub App (recommended for production)

A GitHub App gives you higher rate limits, per-installation scoping, and cleaner audit trails.

### 1. Create the app

1. Go to **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**
2. Name: `Nyx Security Platform`
3. Homepage URL: your Nyx dashboard URL
4. Webhook URL: `https://your-nyx-url/api/v1/webhooks/github`
5. Webhook secret: the value of `NYX_WEBHOOK_SECRET` from your `.env`
6. **Repository permissions:** the same list as the PAT above.
7. **Subscribe to events:** `push`, `pull_request`, `check_suite`, `workflow_run`, `security_advisory`, `code_scanning_alert`.
8. Install it on your org or specific repos.
9. Generate a private key and download the `.pem` file.

<!-- IMAGE: GitHub App creation page with filled fields.
     File: wiki/images/github-app-create.png -->
![GitHub App creation](images/github-app-create.png)
<!-- /IMAGE -->

### 2. Wire it into Nyx

```bash
# Mount the PEM into the backend container
mkdir -p secrets/
mv ~/Downloads/nyx-security-platform.*.pem secrets/github-app-key.pem
chmod 600 secrets/github-app-key.pem
```

Add to `.env`:

```bash
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY_PATH=/app/secrets/github-app-key.pem
# remove GITHUB_TOKEN — App auth takes precedence when both are set
```

Update `docker-compose.yml` to mount the directory:

```yaml
services:
  backend:
    volumes:
      - ./secrets:/app/secrets:ro
```

Restart:

```bash
./nyx.sh restart
./nyx.sh check
```

---

## Expose the webhook endpoint

GitHub must be able to reach Nyx's `/api/v1/webhooks/github` over the public internet. Pick one:

### A — ngrok (development)

```bash
ngrok http 8000
# → https://abc123.ngrok.io
```

Set `GITHUB_WEBHOOK_ENDPOINT=https://abc123.ngrok.io` in `.env` and restart.

> Free ngrok URLs change on restart. Pay for a static domain if you rely on this.

### B — Cloudflare Tunnel (free, persistent)

```bash
cloudflared tunnel login
cloudflared tunnel create nyx
cloudflared tunnel run --url http://localhost:8000 nyx
```

Point a DNS record at the tunnel and set `GITHUB_WEBHOOK_ENDPOINT=https://nyx.yourdomain.com`.

### C — Reverse proxy with TLS (production)

Any Nginx/Caddy/Traefik reverse proxy with a real TLS cert works. See **[Production Deployment](Deployment.md)** for a working Nginx config.

<!-- IMAGE: Architecture diagram showing GitHub → public URL → Nyx backend.
     File: wiki/images/webhook-topology.png -->
![Webhook topology](images/webhook-topology.png)
<!-- /IMAGE -->

---

## Register a repository

### Via the UI

1. Dashboard → **Repositories → Add Repository**
2. Enter the full name: `acme-corp/backend-api`
3. Pick which scanners you want Nyx to collect results from
4. **Add Repository**

Nyx will install the webhook automatically.

### Via the API

```bash
curl -X POST "https://your-nyx-url/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NYX_API_KEY" \
  -d '{
    "github_full_name": "acme-corp/backend-api",
    "enabled_scanners": ["SEMGREP", "BANDIT", "TRIVY", "GRYPE"]
  }'
```

<!-- IMAGE: Repositories page with an added repo and all scanners enabled.
     File: wiki/images/repo-added.png -->
![Registered repository](images/repo-added.png)
<!-- /IMAGE -->

---

## Push the scan workflow to a repo

Nyx ships a canonical `nyx-scan.yml` GitHub Actions workflow that runs five scanners and posts results back. You do not need to copy it manually — use the **Push Workflow** button on the repository detail page.

1. Repositories → click your repo → **Push Workflow**
2. Pick the target branch (default: `main`)
3. Nyx commits `.github/workflows/nyx-scan.yml` via the GitHub Contents API

> Requires the **Workflows** permission on your token — see above.

<!-- IMAGE: Repository detail page with the Push Workflow modal open.
     File: wiki/images/push-workflow-modal.png -->
![Push workflow modal](images/push-workflow-modal.png)
<!-- /IMAGE -->

---

## Check Runs and PR annotations

Once a repo is registered and scans run on a PR, Nyx creates a **GitHub Check Run** named `Nyx Security` on the PR. Findings are posted as **inline annotations** so engineers see them directly in the GitHub diff view — no need to switch apps.

Check Runs can be in states `in_progress`, `success`, `failure`, or `neutral`. Configure `BLOCK_MERGE_ON_CRITICAL` in `.env` to make critical findings a failing check that blocks merges.

<!-- IMAGE: A PR on GitHub showing Nyx Security check run and inline annotations.
     File: wiki/images/check-run-annotations.png -->
![Check Run annotations](images/check-run-annotations.png)
<!-- /IMAGE -->

---

## Code Scanning sync

If your org already uses GitHub Code Scanning (CodeQL, or a partner integration), Nyx can poll the Code Scanning API and import alerts as findings automatically:

```bash
CODE_SCANNING_SYNC_ENABLED=true
CODE_SCANNING_POLL_INTERVAL=3600
```

All Code Scanning alerts are imported with scanner `GITHUB_CODE_SCANNING` and participate in dedup, priority scoring, and AI remediation like any other finding.

---

## Webhook verification

Every webhook delivery from GitHub includes an `X-Hub-Signature-256` header. Nyx verifies this against the per-repo secret (or the App-level secret) before accepting the payload. Deliveries with invalid signatures are logged and rejected with `401`.

To test:

```bash
curl -I -X POST https://your-nyx-url/api/v1/webhooks/github
# → 401 missing signature header
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `403` when pushing workflow | Missing **Workflows** permission on PAT | Edit token, add Workflows scope |
| Webhooks not firing | `GITHUB_WEBHOOK_ENDPOINT` unset or unreachable | Check tunnel/reverse proxy |
| `401 signature mismatch` on webhooks | Secret drift between GitHub and `NYX_WEBHOOK_SECRET` | Reinstall webhook from the repo page |
| PR annotations missing | Repo is not registered in Nyx or **Checks** permission missing | Register repo, re-scope token |
| Rate limit errors | Using a PAT at org scale | Switch to a GitHub App |

---

## What next

- **JIRA integration →** [JIRA Integration](JIRA-Integration.md)
- **CI/CD pipeline setup →** [CI/CD Integration](CICD-Integration.md)
- **Scanner-by-scanner reference →** [Scanners](Scanners.md)
