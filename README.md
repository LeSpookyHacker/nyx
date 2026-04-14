<div align="center">

<br/>

# 🌙 Nyx

### Security Intelligence Platform

**Unified findings management, AI-powered remediation, and compliance visibility for engineering teams.**

<br/>

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.2-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Claude AI](https://img.shields.io/badge/AI-Claude%20Sonnet-CC785C?style=for-the-badge)](https://anthropic.com)

<br/>

</div>

---

## What is Nyx?

Security tooling generates noise. **Nyx converts it into signal.**

Engineering and security teams face a common problem: dozens of scanners produce thousands of findings across hundreds of repositories, with no coherent view of what matters, what is progressing, or what has regressed. Tickets fall through the cracks. Critical vulnerabilities linger unfixed for months. Compliance audits become crisis events.

**Nyx is the platform that sits between your scanners and your engineers.** It ingests results from every scanner you already use — SAST, DAST, SCA, container, IaC — deduplicates them, scores them by real-world exploitability, surfaces what matters first, automatically creates fix PRs using Claude AI, tracks SLA compliance, maps everything to regulatory frameworks, and gives leadership clean executive reports.

> **Zero-friction path from vulnerability detected to vulnerability fixed** — with full audit trail and compliance visibility at every step.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Organization Setup Guide](#organization-setup-guide)
  - [GitHub Setup](#1-github-setup)
  - [Expose Nyx Publicly](#2-expose-nyx-publicly)
  - [JIRA Integration](#3-jira-integration)
  - [Scanner Integrations](#4-scanner-integrations)
  - [Register Repositories](#5-register-repositories)
  - [Configure SLA Policies](#6-configure-sla-policies)
  - [Set Up Scan Schedules](#7-set-up-scan-schedules)
  - [CI/CD Integration](#8-cicd-integration)
- [Configuration Reference](#configuration-reference)
- [Scanners Reference](#scanners-reference)
- [Feature Walkthrough](#feature-walkthrough)
- [API Reference](#api-reference)
- [Production Deployment](#production-deployment)
- [Development Guide](#development-guide)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Security Policy](#security-policy)

---

## Features

### Core Platform

| | Feature | Description |
|---|---|---|
| 🔍 | **Multi-Scanner Ingestion** | SEMGREP, Bandit, Trivy, Snyk, Grype, Checkov, OWASP ZAP, GitHub Code Scanning |
| 🧠 | **Intelligent Deduplication** | Cross-scanner fingerprinting eliminates duplicate findings from overlapping tools |
| 📊 | **Priority Scoring** | Composite 0–100 score combining CVSS, EPSS exploit probability, fix age, and SLA status |
| 🤖 | **AI-Powered Remediation** | Claude generates pull requests with actual code fixes, including explanation and test suggestions |
| ⚡ | **Bulk AI Fix Requests** | Select up to 20 findings and queue fix PRs in a single action |
| 🔀 | **PR Merge Detection** | GitHub webhooks automatically close findings when a fix PR is merged |
| 🎫 | **JIRA Integration** | Auto-create tickets per finding, sync status bidirectionally, bulk ticket creation |
| 🚫 | **False Positive Learning** | Suppression patterns are learned and surfaced as hints on similar future findings |
| 👤 | **Finding Assignment** | Assign findings to engineers; assignments reflect on linked JIRA tickets |
| 🔄 | **Regression Detection** | Re-opened previously fixed findings are flagged and alerted immediately |
| 🔃 | **Regression Auto-Sort** | Findings that were previously marked ACCEPTED_RISK or SUPPRESSED are automatically restored to that status when they reappear — no engineer action required. A bell-notification alert records each batch with per-finding detail |
| ⏱️ | **SLA Policy Engine** | Per-severity, per-repository SLA deadlines with auto-escalation via Slack or JIRA |
| 📅 | **Scan Schedules** | Recurring automated scans on a configurable interval (6h – 1 week) |
| ✅ | **GitHub Check Runs** | Inline PR annotations with security findings as GitHub status checks |
| 📦 | **SBOM Generation** | CycloneDX SBOM per repository via Trivy in GitHub Actions; diff alerts on component changes |
| 🚀 | **One-Click Workflow Push** | Push the canonical `nyx-scan.yml` to any registered repo via GitHub API — no manual workflow maintenance |
| 🔁 | **Autoheal** | Docker healthcheck + autoheal container automatically restarts the backend if it becomes unhealthy |
| 🧬 | **Auto Scanner Detection** | Nyx inspects repository contents and recommends the optimal scanner set — apply with one click or automatically |
| 📜 | **Log Persistence** | Backend logs survive container restarts and `docker compose down` via a named Docker volume; rotating file handler caps at 50 MB × 5 files |

### AI Prompt Generation

| | Feature | Description |
|---|---|---|
| 🪄 | **Claude Code Prompt Generator** | Select any findings in the Findings list and generate a structured, copy-ready prompt for Claude Code — grouped by scanner category with full finding context, code snippets, CVE data, and a built-in completion report template |
| 📋 | **Bulk Repository Prompt** | Generate a Claude Code prompt covering all open findings in a specific repository in one click from the Repositories page or the repository detail view |
| 🔄 | **IN_REMEDIATION Status** | Findings used to generate a Claude prompt are automatically flipped to `IN_REMEDIATION` status so the team knows active work is in progress |
| 🌊 | **SSE Fix Streaming** | `GET /remediation/{id}/stream` streams AI fix generation progress as Server-Sent Events — useful for long-running fixes without polling |
| 🔀 | **Alternative Fix Suggestions** | `POST /remediation/{id}/alternatives` requests 2–3 independently reasoned fix approaches with trade-off analysis, letting engineers choose the best fit for their codebase |
| 🧪 | **Test File Context** | Nyx automatically locates test files for the finding's source file (common naming conventions: `test_foo.py`, `foo_test.py`, `tests/test_foo.py`) and includes their content in the AI prompt — enabling Claude to generate fixes that pass existing tests |
| ⚠️ | **AI Confidence Gating** | Fixes with confidence below `AI_MIN_CONFIDENCE_THRESHOLD` are flagged `REVIEW_LOW_CONFIDENCE` and surfaced for human review before merge consideration |
| 🔬 | **Diff Security Scanning** | Generated diffs are heuristically scanned for dangerous patterns (`os.system`, `eval`, `exec`, hardcoded secrets, shell injection) before storage. Flagged warnings are stored and returned with the remediation record |

### Visibility & Reporting

| | Feature | Description |
|---|---|---|
| 📄 | **Executive PDF Report** | Print-ready HTML report covering KPIs, trends, scanner breakdown by severity, SLA status (overdue / due soon / on track), per-repository findings breakdown, and compliance summary |
| 📈 | **Risk Score Over Time** | Daily risk score snapshots per repository and organization-wide trend |
| 🔥 | **Hot Repos Detection** | Surface repositories with the most new findings in the last 7 days |
| 🕵️ | **Scanner Coverage Gaps** | Identify stale, unconfigured, or partially-covered repositories |
| 📋 | **Compliance Mapping** | PCI DSS, SOC 2, NIST 800-53, CIS Controls, OWASP Top 10 — findings mapped to controls |
| 📉 | **Compliance Trend Analysis** | Weekly coverage percentage trend per framework over 30/60/90 days |
| ⏰ | **MTTR Tracking** | Mean Time to Remediate per severity level, broken down by scanner and category |
| 🚨 | **Regression Alerts** | Dashboard banner and KPI card for recently re-appeared findings |
| 🔔 | **Unified Alert Bell** | Top-bar notification bell shows two tabs: SBOM component change alerts and Regression Auto-Sort alerts. Each tab has its own unread badge contributing to the total bell count |
| 🔑 | **API Key Management** | Create, rotate, and revoke database-backed API keys with four permission scopes: `scanner` (submit scans only), `readonly` (read-only access), `analyst` (update/suppress findings), `admin` (full access). Each key carries a name, optional expiry, last-used timestamp, and scope. The bootstrap key is seeded from `NYX_API_KEY` automatically on first start with `admin` scope |
| 📝 | **Audit Log** | Comprehensive, searchable, downloadable record of every action with tamper-evident HMAC hash chain. Each entry carries `entry_hash` and `prev_hash` — walk the full chain via `GET /audit/verify` to detect any modification, insertion, or deletion |
| 📊 | **Velocity Analytics** | Finding rate metrics, net-new vs fixed per day, burndown estimate, weekly trend, and MTTR breakdown by severity, scanner, and category |
| 💰 | **AI Cost Dashboard** | Token usage totals, estimated Claude API spend (input/output tokens × published pricing), daily time series, and top-10 most expensive remediations — all from `GET /dashboard/ai-costs` |
| 📐 | **Custom Compliance Frameworks** | Define your own compliance frameworks and controls in the DB with CWE/OWASP mappings. Custom frameworks appear alongside built-in ones in all compliance views and reports |
| ✅ | **Risk Acceptance Workflow** | Formal risk acceptance with business justification, compensating controls, evidence URL, approver, and configurable expiry. Approvals and revocations are tracked with full audit trail |
| 🏥 | **Integration Health Check** | `GET /health/integrations` probes database, Anthropic API, GitHub, JIRA, and notification webhook — returns per-integration status for monitoring and alerting |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Developer Workflow                             │
│   git push → GitHub Webhook → Nyx → Run Scanners → Ingest Findings    │
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
                   │  │  Deduplication  │ Priority  │  │
                   │  │  AI Service     │ JIRA      │  │
                   │  │  GitHub         │ Notify    │  │
                   │  │  Compliance     │ SBOM      │  │
                   │  └────────────────┬───────────┘  │
                   │                  │               │
                   │  ┌───────────────▼─────────────┐ │
                   │  │   Background Workers         │ │
                   │  │  SLA Checker    (hourly)     │ │
                   │  │  Risk Snapshots (daily)      │ │
                   │  │  Scan Schedules (5 min)      │ │
                   │  │  Suppression Expiry (hourly) │ │
                   │  │  Key Expiry Warnings (daily) │ │
                   │  └───────────────┬─────────────┘ │
                   │                  │               │
                   │  ┌───────────────▼─────────────┐ │
                   │  │  Database (SQLite/Postgres)  │ │
                   │  │  Findings · Repos · Scans    │ │
                   │  │  Remediations · JiraLinks    │ │
                   │  │  SLAPolicies · Schedules     │ │
                   │  │  SuppressionPatterns · SBOM  │ │
                   │  │  RegressionAutoAlerts        │ │
                   │  │  ApiKeys                     │ │
                   │  └─────────────────────────────┘ │
                   └───────────────┬─────────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
   ┌───────▼──────┐    ┌──────────▼──────────┐    ┌───────▼──────┐
   │   Nyx UI     │    │     GitHub API       │    │  Jira API    │
   │ (React SPA)  │    │  Webhooks · PRs      │    │  Tickets     │
   │  Dashboard   │    │  Check Runs · Code   │    │  Status sync │
   │  Reports     │    │  Scanning            │    │              │
   └──────────────┘    └─────────────────────┘    └──────────────┘
```

**External Scanners** (push results via API):
`SEMGREP` · `BANDIT` · `TRIVY` · `SNYK` · `GRYPE` · `CHECKOV` · `ZAP`

### End-to-End Data Flow

```
1.  Developer pushes code to GitHub
2.  GitHub webhook fires → Nyx webhook receiver
3.  Nyx triggers configured scanner(s) against the new commit
4.  Scanners push JSON results to POST /scans/import
5.  scan_worker processes results:
      a. Normalise raw output → Finding schema
      b. Deduplicate against existing findings (fingerprint match)
      c. Detect regressions (FIXED finding reappears → check auto_close_status: auto-restore to ACCEPTED_RISK/SUPPRESSED if set, otherwise flag as regression with is_regression=True)
      d. Calculate priority score (CVSS + EPSS + age + SLA breach factor)
      e. Calculate SLA deadline based on active policy
      f. Update GitHub Check Run with inline annotations on the PR
6.  Security engineer reviews findings in Nyx dashboard
7.  Engineer clicks "Request AI Fix" (single or bulk)
8.  Claude analyzes the finding, code context, and generates a targeted fix
9.  Nyx creates a GitHub PR with the fix and a JIRA ticket with full details
10. Developer reviews, approves, and merges the PR
11. GitHub webhook fires (PR merged) → Nyx closes finding + updates JIRA → Done
```

---

## Quick Start

> [!NOTE]
> **Prerequisites:** Docker with Compose v2, Python 3, and curl.

### One-command setup

```bash
git clone https://github.com/LeSpookyHacker/nyx.git
cd nyx
./setup.sh
```

That's it. The setup wizard will:
1. Check that Docker, Python 3, and curl are installed
2. Create `.env` and generate all required secrets automatically
3. Ask for your GitHub token and Anthropic API key (press Enter to skip either)
4. Validate your credentials
5. Build and start the Docker containers
6. Print your API key and the dashboard URL

When it finishes, open **http://localhost:3000**, click **Settings**, and paste in the API key it printed.

> [!TIP]
> **Flags:** `./setup.sh --non-interactive` for headless/CI use, `./setup.sh --skip-start` to configure `.env` without starting containers.

### Manual setup

If you prefer to do it yourself:

```bash
git clone https://github.com/LeSpookyHacker/nyx.git
cd nyx
cp .env.example .env
```

Edit `.env` and fill in at minimum:

```bash
ANTHROPIC_API_KEY=sk-ant-...          # AI fix generation
GITHUB_TOKEN=ghp_...                   # GitHub integration
NYX_API_KEY=any-secret-string          # Your login key
NYX_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
NYX_WEBHOOK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

Then start:

```bash
docker compose up -d
```

### After setup

| URL | What |
|---|---|
| **http://localhost:3000** | Dashboard |
| **http://localhost:8000/docs** | Interactive API docs |

### Managing Nyx

Use `./nyx.sh` as your day-to-day interface:

```
./nyx.sh              Start Nyx (or show status if already running)
./nyx.sh status       Show services and open finding counts
./nyx.sh stop         Stop all services
./nyx.sh restart      Restart all services
./nyx.sh build        Rebuild images after pulling updates
./nyx.sh logs         Tail backend logs
./nyx.sh check        Verify all integration credentials
./nyx.sh refresh      Trigger all scan schedules now
```

> [!TIP]
> After the first start, go to **Settings > API Keys** to create purpose-specific keys for CI/CD pipelines. Create CI/CD keys with `scanner` scope — they can submit scans but cannot modify findings or manage keys.

> [!WARNING]
> If `NYX_API_KEY` is left blank, the API is unauthenticated. This is fine for local evaluation but **never deploy publicly without a key set**.

---

## Organization Setup Guide

A step-by-step walkthrough for deploying Nyx across an organization with multiple GitHub repositories and JIRA.

---

### 1. GitHub Setup

#### 1a. Create a Personal Access Token

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Name it `nyx-security-platform`, set expiration to 1 year
4. Under **Repository access**, select **All repositories** (or specific ones)
5. Grant the following permissions:

| Permission | Access |
|---|---|
| **Contents** | Read and write — to create fix PRs |
| **Metadata** | Read-only |
| **Pull requests** | Read and write |
| **Webhooks** | Read and write |
| **Workflows** | Read and write — **required** for Push Workflow feature |
| **Checks** | Read and write — for PR annotations |
| **Security events** | Read-only — for Code Scanning sync |

6. Click **Generate token** and save it as `GITHUB_TOKEN` in your `.env`

> [!WARNING]
> The **Workflows** permission is required if you want to use the **Push Workflow** button in Nyx to deploy `nyx-scan.yml` to your repositories. Without it you will receive a 403 from GitHub when pushing. If you created your PAT before this feature existed, edit it and check the **Workflow** box — the token value does not change.

> [!TIP]
> For production deployments at scale, use **GitHub App** authentication instead of a PAT for higher rate limits and org-wide installation. Set `GITHUB_APP_ID` and `GITHUB_PRIVATE_KEY_PATH` in your `.env`.

#### 1b. Webhook Installation

Nyx automatically installs webhooks on every repository you register. The webhook secret is auto-generated per repository and stored in the database. You only need the public URL ready before registering repos.

---

### 2. Expose Nyx Publicly

GitHub must be able to reach Nyx's webhook endpoint over the internet. Choose an option:

<details>
<summary><strong>Option A — ngrok (Development / Testing)</strong></summary>

```bash
# Install ngrok: https://ngrok.com/download
ngrok http 8000

# ngrok gives you a URL like: https://abc123.ngrok.io
# Set in .env:
# GITHUB_WEBHOOK_ENDPOINT=https://abc123.ngrok.io
```

> [!WARNING]
> Free ngrok URLs change on restart. Use a paid ngrok account with a static domain for persistent testing.

</details>

<details>
<summary><strong>Option B — Cloudflare Tunnel (Free, Persistent)</strong></summary>

```bash
# Install cloudflared
brew install cloudflare/cloudflare/cloudflared  # macOS

# Authenticate and create a tunnel
cloudflared tunnel login
cloudflared tunnel create nyx
cloudflared tunnel run --url http://localhost:8000 nyx

# Set in .env:
# GITHUB_WEBHOOK_ENDPOINT=https://nyx.your-domain.com
```

</details>

<details>
<summary><strong>Option C — Cloud Deployment (Production)</strong></summary>

Deploy Nyx behind a load balancer or reverse proxy with a real domain and TLS certificate. See [Production Deployment](#production-deployment) for the full Nginx + Let's Encrypt configuration.

</details>

---

### 3. JIRA Integration

Nyx integrates with Jira Cloud to automatically create, update, and close tickets as findings move through their lifecycle.

#### 3a. Create a JIRA API Token

1. Go to **https://id.atlassian.com/manage-profile/security/api-tokens**
2. Click **Create API token**, name it `nyx-security-platform`
3. Copy the token

#### 3b. Configure JIRA in `.env`

```bash
# Your Jira instance URL (no trailing slash)
JIRA_URL=https://your-org.atlassian.net

# Email address of the user who owns the API token
JIRA_USER_EMAIL=security-bot@your-org.com

# The API token
JIRA_API_TOKEN=your-jira-api-token

# Default project key (e.g. "SEC" for SEC-1234)
JIRA_DEFAULT_PROJECT_KEY=SEC

# Set to false for real tickets; true for testing
JIRA_MOCK_MODE=false
```

#### 3c. Verify Connection

```bash
curl -u "security-bot@your-org.com:your-api-token" \
  "https://your-org.atlassian.net/rest/api/3/myself"
```

#### 3d. How the Integration Works

Once configured, Nyx will:

- **Auto-create tickets** when an AI fix PR is generated (includes severity, CVSS score, remediation diff, and a link to the PR)
- **Manual ticket creation** from any finding detail page with a single click
- **Bulk ticket creation** for all CRITICAL and HIGH findings in a repository
- **Sync status bidirectionally** — Nyx polls Jira for status, assignee, and priority updates
- **Auto-close tickets** when a fix PR is merged on GitHub (status → Done)
- **Per-SLA-policy routing** — route findings from different repos or severities to different Jira projects

---

### 4. Scanner Integrations

Nyx does not run scanners directly — it receives their JSON output via the REST API. This keeps Nyx scanner-agnostic and works with your existing CI/CD pipeline.

#### Import Endpoint

All scanners push to the same endpoint:

```
POST /api/v1/scans/import
Content-Type: application/json
X-API-Key: your-nyx-api-key

{
  "repository_id": "<nyx-repo-uuid>",
  "scanner": "SEMGREP",
  "git_ref": "main",
  "git_sha": "abc123...",
  "trigger": "push",
  "results": { ...raw scanner JSON output... }
}
```

<details>
<summary><strong>SEMGREP — SAST, all languages</strong></summary>

```bash
pip install semgrep
semgrep --config=auto --json --output=semgrep-results.json .

curl -s -X POST "https://your-nyx-url/api/v1/scans/import" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NYX_API_KEY" \
  -d "{
    \"repository_id\": \"$NYX_REPO_ID\",
    \"scanner\": \"SEMGREP\",
    \"git_ref\": \"$(git branch --show-current)\",
    \"git_sha\": \"$(git rev-parse HEAD)\",
    \"trigger\": \"push\",
    \"results\": $(cat semgrep-results.json)
  }"
```

**Recommended rulesets:** `p/owasp-top-ten` · `p/secrets` · `p/python` · `p/javascript` · `p/supply-chain`

</details>

<details>
<summary><strong>Bandit — Python SAST</strong></summary>

```bash
pip install bandit
bandit -r . -f json -o bandit-results.json

# Push with scanner: "BANDIT"
```

</details>

<details>
<summary><strong>Trivy — Container & IaC</strong></summary>

```bash
brew install aquasecurity/trivy/trivy  # macOS

# Scan a Docker image
trivy image --format json --output trivy-results.json your-org/your-image:latest

# Scan filesystem / IaC
trivy fs --format json --output trivy-results.json .

# Scan Kubernetes manifests
trivy config --format json --output trivy-results.json ./k8s/

# Push with scanner: "TRIVY"
```

</details>

<details>
<summary><strong>Grype — SCA, dependency vulnerabilities</strong></summary>

```bash
brew install anchore/grype/grype  # macOS

grype dir:. -o json > grype-results.json
# or: grype your-org/your-image:latest -o json > grype-results.json

# Push with scanner: "GRYPE"
```

</details>

<details>
<summary><strong>Snyk — SCA</strong></summary>

```bash
npm install -g snyk
snyk auth
snyk test --json > snyk-results.json

# Push with scanner: "SNYK"
```

> [!TIP]
> Snyk also supports direct webhook delivery. Set `SNYK_WEBHOOK_SECRET` in `.env` and configure a Snyk webhook pointing to `https://your-nyx-url/api/v1/webhooks/snyk`.

</details>

<details>
<summary><strong>Checkov — IaC misconfigurations</strong></summary>

```bash
pip install checkov

checkov -d ./terraform --output json > checkov-results.json
checkov -d ./k8s --output json > checkov-results.json
checkov -f Dockerfile --output json > checkov-results.json

# Push with scanner: "CHECKOV"
```

</details>

<details>
<summary><strong>OWASP ZAP — DAST</strong></summary>

```bash
docker run --rm -v $(pwd):/zap/wrk owasp/zap2docker-stable \
  zap-baseline.py -t https://your-app.example.com -J zap-results.json

# Push with scanner: "ZAP"
```

</details>

<details>
<summary><strong>GitHub Code Scanning — Automatic sync</strong></summary>

Enable in `.env`:

```bash
CODE_SCANNING_SYNC_ENABLED=true
CODE_SCANNING_POLL_INTERVAL=3600  # seconds
```

Nyx will automatically poll the GitHub Code Scanning API for all registered repositories and import findings — no manual push required.

</details>

---

### 5. Register Repositories

#### Via the UI

1. Go to **Nyx Dashboard → Repositories → Add Repository**
2. Enter the full GitHub name (e.g., `acme-corp/backend-api`)
3. Select which scanners to enable
4. Click **Add Repository**

Nyx automatically installs a GitHub webhook on the repository.

#### Via the API

```bash
curl -X POST "https://your-nyx-url/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NYX_API_KEY" \
  -d '{
    "github_full_name": "acme-corp/backend-api",
    "enabled_scanners": ["SEMGREP", "BANDIT", "TRIVY", "GRYPE"]
  }'
```

#### Bulk Register an Entire Organization

```bash
#!/bin/bash
ORG="acme-corp"
NYX_URL="https://your-nyx-url"
NYX_API_KEY="your-api-key"
GITHUB_TOKEN="ghp_..."
SCANNERS='["SEMGREP","BANDIT","TRIVY","GRYPE","CHECKOV"]'

REPOS=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/orgs/$ORG/repos?per_page=100&type=all" \
  | jq -r '.[].full_name')

for REPO in $REPOS; do
  echo "Registering $REPO..."
  curl -s -X POST "$NYX_URL/api/v1/repositories" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $NYX_API_KEY" \
    -d "{\"github_full_name\": \"$REPO\", \"enabled_scanners\": $SCANNERS}"
  sleep 1
done
```

---

### 6. Configure SLA Policies

SLA Policies define how long findings may remain open before automatic escalation. You can define org-wide policies and override per repository.

#### Via the UI

Go to **Nyx → SLA Policies → Add Policy** and fill in:

- **Policy Name** — e.g., "Org Critical 7-day SLA"
- **Scope** — Org-wide or a specific repository
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFO / ALL
- **Max Days** — Days before escalation triggers
- **Escalation** — NOTIFY (Slack), JIRA, BOTH, or NONE
- **JIRA Project Key** — Which project to create the escalation ticket in

#### Recommended Starting Policies

| Severity | Max Days | Escalation | Notes |
|---|---|---|---|
| **CRITICAL** | 7 | BOTH | Mirrors PCI DSS Requirement 6 |
| **HIGH** | 30 | BOTH | Standard SOC 2 expectation |
| **MEDIUM** | 90 | NOTIFY | Balance coverage with noise |
| **LOW** | 180 | NONE | Track but don't alert |

#### How Escalation Works

Every hour, Nyx's SLA checker:

1. Queries all open findings where `sla_breach_at < now()` and `sla_notified_at IS NULL`
2. Looks up the most specific matching policy (repo-specific first, then org-wide)
3. Executes the escalation action (Slack message, JIRA update, or both)
4. Sets `sla_notified_at = now()` to prevent duplicate notifications

---

### 7. Set Up Scan Schedules

Scheduled scanning ensures repositories with infrequent commits are still regularly checked for newly discovered vulnerabilities in unchanged dependencies.

#### Via the UI

1. Go to **Nyx → Schedules → Add Schedule**
2. Select the repository and scanners to include
3. Choose an interval: `6h` / `12h` / `24h` / `48h` / `72h` / `1 week`
4. Click **Create Schedule**

You can manually trigger any schedule immediately using the **▶** button in the Schedules table.

#### How Schedules Work

Every 5 minutes, Nyx's schedule worker:
1. Queries all enabled schedules where `next_run_at <= now()`
2. Triggers the scanner invocation and creates a Scan record
3. Updates `last_run_at` and computes `next_run_at = now() + interval_hours`

---

### 8. CI/CD Integration

#### Recommended: Push Workflow from the Nyx UI

The easiest way to integrate any repository with Nyx is to use the **Push Workflow** button on the Repositories page. Nyx generates and pushes a canonical `nyx-scan.yml` directly to the repository via the GitHub API — no manual file creation needed.

**What it requires in GitHub — configure these after clicking Push Workflow:**

**Secrets** (Repository → Settings → Secrets and variables → Actions → Secrets):

| Secret | Value | Required |
|---|---|---|
| `NYX_API_KEY` | Your Nyx API key — use a `scanner`-scoped key from Nyx Settings → API Keys | Yes |
| `SNYK_TOKEN` | Snyk API token from [app.snyk.io/account](https://app.snyk.io/account) — enables Snyk SCA step | Optional |

**Variables** (Repository → Settings → Secrets and variables → Actions → Variables):

| Variable | Value | Required |
|---|---|---|
| `NYX_URL` | Your Nyx public URL, no trailing slash — e.g. `https://nyx.example.com` | Yes |
| `NYX_ZAP_TARGET` | Full URL of the app to DAST scan — e.g. `https://myapp.com`. Enables the `nyx-zap` job. | Optional |

> **Note:** You do **not** need to set `NYX_REPO_ID` — the repository UUID is baked directly into the workflow YAML when Nyx pushes it. No environment variable is read at runtime for this value.

> [!TIP]
> Use a **`scanner`-scoped API key** for CI/CD (`NYX_API_KEY` secret in GitHub). Scanner keys can submit scans but cannot suppress findings, manage other keys, or access audit exports — limiting blast radius if a CI secret is compromised.

> [!TIP]
> **Scan submission provenance:** Workflows can optionally sign scan payloads by including an `X-Nyx-Submission-HMAC: sha256=<hmac>` header — computed as `HMAC-SHA256(key=repo_webhook_secret, msg=SHA256(request_body))`. Nyx verifies this on import and marks verified scans with `submission_verified=true`. Unsigned submissions are accepted but flagged.

The generated workflow runs the full scanner suite:
- **Semgrep** — SAST across all languages
- **Trivy** — SCA vulnerability scan + CycloneDX SBOM submission
- **OWASP ZAP** — DAST baseline scan (only if `NYX_ZAP_TARGET` is set; uses `-m 3` spider minutes)
- **Snyk** — SCA dependency vulnerabilities (requires `SNYK_TOKEN`)
- **Gitleaks** — Secrets detection across the full commit history; binary is SHA-256 verified against the publisher's checksums file before execution
- **Hadolint** — Dockerfile best-practice linting (skipped if no Dockerfile present); binary is SHA-256 verified against the publisher's `.sha256` sidecar file before execution
- Creates a scoped `zap-wrk/` directory with write permissions for ZAP output (no workspace-wide chmod)
- ZAP runs with `continue-on-error: true` so Trivy and SBOM always complete even if ZAP fails
- Repository UUID is baked into the workflow YAML at push time — no `NYX_REPO_ID` variable needed in GitHub settings

> [!NOTE]
> If `SNYK_TOKEN` is not set, the Snyk step is skipped gracefully — all other scanners still run.

> [!TIP]
> After clicking **Push Workflow**, run the workflow once manually in GitHub to confirm it's working: **Actions → nyx-scan → Run workflow**.

#### Manual: Full GitHub Actions Pipeline

If you prefer to manage the workflow file yourself, create `.github/workflows/nyx-security.yml` in your repository:

```yaml
name: Nyx Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  NYX_URL: https://your-nyx-url
  NYX_API_KEY: ${{ secrets.NYX_API_KEY }}

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Get repository ID from Nyx
        id: nyx-repo
        run: |
          REPO_ID=$(curl -s \
            -H "X-API-Key: $NYX_API_KEY" \
            "$NYX_URL/api/v1/repositories" | \
            jq -r '.[] | select(.github_full_name == "${{ github.repository }}") | .id')
          echo "repo_id=$REPO_ID" >> $GITHUB_OUTPUT

      - name: Run Semgrep
        if: steps.nyx-repo.outputs.repo_id != ''
        run: |
          pip install semgrep
          semgrep --config=auto --json --output=semgrep-results.json . || true

      - name: Push Semgrep results to Nyx
        if: steps.nyx-repo.outputs.repo_id != ''
        run: |
          curl -s -X POST "$NYX_URL/api/v1/scans/import" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $NYX_API_KEY" \
            -d "{
              \"repository_id\": \"${{ steps.nyx-repo.outputs.repo_id }}\",
              \"scanner\": \"SEMGREP\",
              \"git_ref\": \"${{ github.ref_name }}\",
              \"git_sha\": \"${{ github.sha }}\",
              \"trigger\": \"push\",
              \"results\": $(cat semgrep-results.json)
            }"

      - name: Run Trivy
        if: steps.nyx-repo.outputs.repo_id != ''
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: json
          output: trivy-results.json
          exit-code: 0

      - name: Push Trivy results to Nyx
        if: steps.nyx-repo.outputs.repo_id != ''
        run: |
          curl -s -X POST "$NYX_URL/api/v1/scans/import" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $NYX_API_KEY" \
            -d "{
              \"repository_id\": \"${{ steps.nyx-repo.outputs.repo_id }}\",
              \"scanner\": \"TRIVY\",
              \"git_ref\": \"${{ github.ref_name }}\",
              \"git_sha\": \"${{ github.sha }}\",
              \"trigger\": \"push\",
              \"results\": $(cat trivy-results.json)
            }"

      - name: Run Grype
        if: steps.nyx-repo.outputs.repo_id != ''
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype dir:. -o json > grype-results.json || true

      - name: Push Grype results to Nyx
        if: steps.nyx-repo.outputs.repo_id != ''
        run: |
          curl -s -X POST "$NYX_URL/api/v1/scans/import" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $NYX_API_KEY" \
            -d "{
              \"repository_id\": \"${{ steps.nyx-repo.outputs.repo_id }}\",
              \"scanner\": \"GRYPE\",
              \"git_ref\": \"${{ github.ref_name }}\",
              \"git_sha\": \"${{ github.sha }}\",
              \"trigger\": \"push\",
              \"results\": $(cat grype-results.json)
            }"
```

Add `NYX_API_KEY` to **GitHub → Repository → Settings → Secrets → Actions**.

#### Block Merges on Critical Findings

Nyx creates GitHub Check Runs on every PR. To block merges when critical findings are detected:

1. Go to **GitHub → Repository → Settings → Branches**
2. Add a branch protection rule for `main`
3. Enable **Require status checks to pass before merging**
4. Add `Nyx Security` as a required check

When Nyx detects new CRITICAL or HIGH findings in a PR, the check fails with inline annotations at the exact lines. Otherwise it passes.

---

## Configuration Reference

All configuration is via environment variables. Copy `.env.example` to `.env`.

<details>
<summary><strong>Required</strong></summary>

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key — get one at https://console.anthropic.com |
| `GITHUB_TOKEN` | GitHub PAT or App installation token |
| `GITHUB_WEBHOOK_ENDPOINT` | Public HTTPS URL where GitHub can reach Nyx (no trailing slash) |

</details>

<details>
<summary><strong>Database</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/nyx.db` | SQLite for dev, PostgreSQL for production. Format: `postgresql+asyncpg://user:pass@host:5432/nyx` |

</details>

<details>
<summary><strong>Security</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `NYX_API_KEY` | _(blank)_ | Bootstrap API key. On first startup Nyx registers this value in the database as the `bootstrap` key with `admin` scope. All subsequent key management (create / rotate / revoke) is done through the Settings UI or `/api/v1/api-keys`. Leave blank to disable auth in development only — **never deploy without this set in production**. |
| `NYX_SECRET_KEY` | _(blank)_ | Master secret key for two functions: (1) HMAC signing of each audit log entry — enables tamper detection via `/audit/verify`; (2) Fernet encryption of webhook secrets at rest in the database. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. Strongly recommended for any non-local deployment. |
| `API_KEY_MAX_LIFETIME_DAYS` | `0` | Maximum API key lifetime in days. `0` = no limit. When set, keys created without an explicit expiry are automatically capped at this limit. A daily background task warns (log + audit event) about keys expiring within 7 days. |
| `CORS_ORIGINS_STR` | `http://localhost:3000,http://localhost:5173` | Comma-separated allowed CORS origins |
| `HTTPS_ONLY` | `false` | Set `true` in production to enforce HTTPS + HSTS |
| `ENVIRONMENT` | `development` | Set `production` to enable stricter security defaults |
| `TRUSTED_PROXY_CIDRS` | _(blank)_ | Comma-separated CIDRs of trusted reverse proxies (e.g. `10.0.0.0/8,172.16.0.0/12`). Only requests from these IPs have their `X-Forwarded-For` header trusted for client IP resolution. Leave blank to always use the direct peer address. |
| `REQUIRE_SUBMISSION_HMAC` | `false` | When `true`, scan submissions missing the `X-Nyx-Submission-HMAC` header are rejected with HTTP 403. Enables strict CI/CD submission integrity enforcement. |
| `GITHUB_WEBHOOK_IP_ALLOWLIST_ENABLED` | `false` | When `true`, GitHub webhook deliveries are rejected unless they originate from GitHub's published IP ranges. Fetched from `api.github.com/meta`. |

</details>

<details>
<summary><strong>AI / Claude</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Claude model for fix generation |
| `AI_MAX_OUTPUT_TOKENS` | `8192` | Maximum output tokens for AI-generated fixes. Higher values allow Claude to generate larger diffs for complex fixes. |
| `AI_MIN_CONFIDENCE_THRESHOLD` | `0.4` | Fixes with confidence below this value receive `REVIEW_LOW_CONFIDENCE` status and are flagged for human review before merge consideration. |
| `ANTHROPIC_TIMEOUT` | `90.0` | Per-call timeout (seconds) for Anthropic API requests. Increase for very large files; decrease to fail fast on network issues. |

</details>

<details>
<summary><strong>GitHub</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `GITHUB_APP_ID` | _(blank)_ | GitHub App ID (alternative to PAT) |
| `GITHUB_PRIVATE_KEY_PATH` | _(blank)_ | Path to GitHub App private key PEM |
| `GITHUB_CHECK_RUNS_ENABLED` | `true` | Create PR check runs with inline annotations |

</details>

<details>
<summary><strong>JIRA</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `JIRA_URL` | _(blank)_ | Jira Cloud URL, e.g. `https://acme.atlassian.net` |
| `JIRA_USER_EMAIL` | _(blank)_ | Email of the Jira user who owns the API token |
| `JIRA_API_TOKEN` | _(blank)_ | Jira API token |
| `JIRA_DEFAULT_PROJECT_KEY` | `SEC` | Default Jira project key |
| `JIRA_MOCK_MODE` | `false` | Log Jira actions without creating real tickets |

</details>

<details>
<summary><strong>SLA Defaults</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `SLA_CRITICAL_DAYS` | `7` | Days before a CRITICAL finding breaches SLA |
| `SLA_HIGH_DAYS` | `30` | Days before a HIGH finding breaches SLA |
| `SLA_MEDIUM_DAYS` | `90` | Days before a MEDIUM finding breaches SLA |
| `SLA_LOW_DAYS` | `180` | Days before a LOW finding breaches SLA |

</details>

<details>
<summary><strong>Notifications, Scanners, Logging</strong></summary>

| Variable | Default | Description |
|---|---|---|
| `NOTIFICATION_WEBHOOK_URL` | _(blank)_ | Slack (or any webhook) URL for SLA breach alerts |
| `DEFAULT_ENABLED_SCANNERS_STR` | `SEMGREP,BANDIT,TRIVY,GRYPE,CHECKOV` | Default scanners for new repositories |
| `EPSS_API_ENABLED` | `true` | Fetch EPSS exploit probability scores for CVEs |
| `CODE_SCANNING_SYNC_ENABLED` | `false` | Periodically poll GitHub Code Scanning API |
| `CODE_SCANNING_POLL_INTERVAL` | `3600` | Seconds between Code Scanning polls |
| `SNYK_WEBHOOK_SECRET` | _(blank)_ | Snyk webhook HMAC secret |
| `SCAN_SCHEDULES_ENABLED` | `true` | Enable recurring scan schedules |
| `SLA_CHECK_ENABLED` | `true` | Enable SLA breach detection background task |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_FORMAT` | `json` | `json` for log aggregators, `text` for human-readable |
| `DEBUG` | `false` | FastAPI debug mode — never use in production |

</details>

---

## Scanners Reference

| Scanner | Type | Languages / Targets | Key Detections |
|---|---|---|---|
| **SEMGREP** | SAST | 30+ languages | SQL injection, XSS, secrets, OWASP Top 10, custom rules |
| **Bandit** | SAST | Python | Dangerous functions, weak crypto, shell injection, hardcoded passwords |
| **Trivy** | SCA + IaC | Containers, Terraform, K8s | CVE-matched OS/library vulnerabilities, misconfigurations |
| **Grype** | SCA | All ecosystems | CVE-matched dependency vulnerabilities using Syft SBOM |
| **Snyk** | SCA | All package managers | Dependency vulnerabilities, fix advice, license risk |
| **Checkov** | IaC | Terraform, Helm, K8s, Docker | 1000+ IaC misconfigurations, CIS benchmarks |
| **OWASP ZAP** | DAST | Web applications | Runtime XSS, SQLi, CSRF, broken authentication |
| **GitHub Code Scanning** | SAST | CodeQL — 9 languages | Deep semantic analysis, high-confidence findings |

---

## Feature Walkthrough

<details>
<summary><strong>Dashboard</strong></summary>

The main dashboard gives a real-time operational view of your organization's security posture:

- **KPI Cards** — Total open findings, Critical count, SLA Breached count, Repository count, Regression count — all clickable, navigate to the filtered findings list
- **Regression Alert Banner** — Appears when previously fixed findings have re-appeared in the last 7 days
- **Open by Severity Donut** — Click any segment to jump to the filtered findings list
- **Findings by Scanner** — Bar chart showing which scanners produce the most findings
- **MTTR by Severity** — Mean time to remediate, measuring response effectiveness
- **30-Day Trend Chart** — New vs. fixed findings over time; shows whether the backlog is growing or shrinking
- **Top Vulnerability Types** — Most prevalent finding patterns across all repositories
- **Repository Risk Table** — Risk-scored repos with clickable critical/high counts
- **Org Risk Over Time** — 30-day area chart of the aggregated organization risk score
- **Hot Repos (7d)** — Repositories generating the most new findings recently
- **Scanner Coverage Gaps** — Warning panel listing stale repos, repos with no scanners, and partially-covered repos

</details>

<details>
<summary><strong>Findings List</strong></summary>

The findings list is the core operational view for security engineers:

- **Filters** — Severity, Scanner, Status (multi-select toggles). Regression-only toggle.
- **Repository Filter** — Dropdown to scope the view to a single repository; updates the URL for deep-linking
- **Search** — Full-text search across finding title, rule ID, file path, CVE ID
- **Sorting** — Priority score (default), first seen, severity
- **Bulk AI Fix** — Select multiple findings (up to 20) and request fixes in a single action
- **Bulk Claude Prompt** — Select any findings and generate a structured Claude Code remediation prompt; findings are flipped to `IN_REMEDIATION`
- **Mark Fixed** — Bulk action to mark selected findings as fixed (available in the toolbar when findings are selected)
- **Accept Risk** — Bulk action to accept risk on selected findings; marks `auto_close_status` so they are auto-restored on future regressions instead of re-opening
- **REGRESSION badge** — Orange badge on findings that have re-appeared after being fixed
- **Assignee display** — Shows the assigned engineer directly in the list
- **Export** — Download as CSV for reporting

</details>

<details>
<summary><strong>Finding Detail</strong></summary>

Each finding has a dedicated page:

- **Header** — Severity badge, scanner badge, status badge, REGRESSION badge (if applicable), **Claude Prompt** button to generate a Claude Code remediation prompt for this individual finding
- **Repository link** — Displayed at the top of the Details sidebar; links to the repository detail page
- **Description** — Full finding description with OWASP category tag
- **Vulnerable Code** — Syntax-highlighted code snippet with line numbers
- **Remediation Guidance** — Static guidance from the scanner or Nyx
- **Engineer Notes** — Free-text notes field for context, workarounds, or investigation notes
- **Mark Fixed** — Manually mark a finding as fixed (e.g. after an out-of-band fix)
- **Accept Risk** — Mark as accepted risk with a required expiry date (max 180 days). Nyx automatically reopens the finding when the expiry passes, forcing periodic re-review. Sets `auto_close_status` so future regressions are auto-sorted
- **Suppress** — Suppress with a required reason. CRITICAL and HIGH findings require a minimum 50-character reason to prevent drive-by suppression. Creates a learned pattern for future similar findings; sets `auto_close_status` so future regressions are auto-sorted
- **Sidebar — Details** — Rule ID, category, priority score, CVSS, EPSS, CVE link, first seen, SLA deadline
- **Sidebar — Assignment** — Assign to an engineer (email/username); syncs to linked JIRA ticket
- **Sidebar — Suppression Suggestion** — If this rule has been suppressed before, shows count and previous reason
- **Sidebar — Fix PR** — Link to the AI-generated pull request
- **Sidebar — JIRA** — Create, view, sync, or unlink a JIRA ticket

</details>

<details>
<summary><strong>AI Remediation Flow</strong></summary>

The remediation flow keeps engineers in control at every step:

1. **Request Fix** — Engineer clicks "Request AI Fix" on any OPEN finding
2. **Generation** — Claude analyzes the finding, code snippet, and context; generates a targeted code fix. The exact prompt and a SHA-256 hash of the resulting diff are stored on the remediation record for non-repudiation
3. **Review** — Engineer sees a diff view of the proposed change with an AI explanation
4. **Approve** — Nyx creates the GitHub PR and a JIRA ticket with full fix details
5. **Merge** — Developer merges the PR; GitHub webhook fires; finding → FIXED; JIRA → Done
6. **Regenerate** — If the first fix is inadequate, regenerate with additional context

> [!IMPORTANT]
> **Prompt injection protection:** File content passed to Claude is wrapped in structural delimiters (`<<<NYX_FILE_CONTENT_BEGIN>>>`). The system prompt instructs Claude to treat content between these markers as data only — not instructions. This prevents a malicious finding (e.g., a secret containing `IGNORE PREVIOUS INSTRUCTIONS`) from hijacking the fix generation.
>
> **Diff integrity:** The SHA-256 hash stored in `ai_diff_sha256` lets auditors verify that the diff shown in the UI matches exactly what was approved — database tampering with the diff would break the hash.

</details>

<details>
<summary><strong>Claude Code Prompt Generator</strong></summary>

Use this feature when you want to hand off a batch of findings to Claude Code running locally — particularly useful for dependency updates (Snyk/Trivy SCA findings), IaC misconfigurations, or any fix that requires changes across multiple files.

**From the Findings list:**
1. Select any findings using the checkboxes
2. Click **Claude Prompt (N)** in the toolbar
3. A modal displays the structured prompt — click **Copy** and paste it into a Claude Code session
4. Selected findings are automatically set to `IN_REMEDIATION`

**From the Repositories page:**
- Each repository card has a **Claude Prompt** button that generates a prompt covering all open findings for that repo in one action

**From the Repository detail page:**
- The header card has a **Claude Prompt** button for all open findings in the repository
- The Findings tab also has per-selection **Claude Prompt (N)** in the bulk-action toolbar

**What the prompt includes:**
- Findings grouped by scanner category (SAST, SCA, IaC, Secrets, DAST)
- Per-finding tables: severity, CVE/CWE, CVSS score, file location, code snippet, remediation guidance
- Category-specific instructions (e.g., "update package manifests", "rotate exposed secrets")
- A completion report template for Claude to fill in when done

> [!TIP]
> For dependency-heavy repositories, filter to SCA findings only before generating the prompt to keep it focused and within Claude's context window.

</details>

<details>
<summary><strong>Compliance</strong></summary>

The compliance module maps findings to regulatory frameworks automatically:

- **Framework cards** — PCI DSS, SOC 2, NIST 800-53, CIS Controls, OWASP Top 10. Each shows a gauge ring with the overall compliance percentage.
- **Control breakdown** — Click any control to see its description, CWE and OWASP category mappings, a fixed/open bar, and the full list of open findings by repository (linked directly to the finding and repo detail pages).
- **Compliance Trend** — In the Reports page; weekly coverage percentage over 30/60/90 days to demonstrate improvement to auditors.

</details>

<details>
<summary><strong>Reports</strong></summary>

- **Executive Security Report** — Click "Generate Report" to download a print-ready HTML report covering: KPIs, MTTR by severity, weekly trends table, top 10 vulnerability types, scanner breakdown by severity, SLA status breakdown (overdue / due in 7 days / on track with visual bars), per-repository findings breakdown by scanner and severity, and compliance summary across all frameworks. The report is fetched securely via the API (key sent as a header, never in the URL) and opened in a new tab. Use **Cmd+P / Ctrl+P → Save as PDF** for leadership or auditors.
- **Compliance Trend Analysis** — Select a framework and date range; see current coverage %, change over the period, and open finding count.

</details>

<details>
<summary><strong>SBOM</strong></summary>

The SBOM page gives per-repository software supply chain visibility:

- **Generate SBOM** — Click the **Generate** button for any repository. Nyx dispatches a GitHub Actions `workflow_dispatch` event which runs Trivy in CycloneDX format and submits the result back to Nyx automatically.
- **Component History** — Each submission is snapshotted. View the current component list or browse the full submission history.
- **Diff Alerts** — Every new submission is diffed against the previous snapshot. If components were added, removed, or updated, a change alert is created. Alerts show added/removed/updated counts and the full component-level diff.
- **Acknowledge Alerts** — Dismiss individual alerts or acknowledge all at once. Unacknowledged alert count appears as a badge.

> [!NOTE]
> SBOM generation requires the `nyx-scan.yml` workflow to be present in the repository. Use the **Push Workflow** button on the Repositories page to deploy it.

</details>

<details>
<summary><strong>API Key Management</strong></summary>

Nyx manages API keys in the database rather than relying solely on a single env-var secret. This enables key rotation, per-consumer keys, scoped permissions, expiry enforcement, and a complete audit trail — without restarting the service.

**Settings page → API Keys:**

- **Key list** — Shows name, scope, active status, expiry date, last-used timestamp, and the actor that created each key. The plaintext key and hash are never shown after creation.
- **Create key** — Enter a name (e.g., `github-actions-prod`), choose a scope, and set an optional expiry (1–730 days). The plaintext key is returned once — copy it immediately. Requires `admin` scope.
- **Deactivate** — Soft-deletes the key. It is rejected on the next request and the deactivation is recorded in the audit log. Requires `admin` scope.

**Key scopes:**

| Scope | Permitted operations |
|---|---|
| `scanner` | Submit scan results (`POST /scans/import`), read repositories |
| `readonly` | Read findings, repositories, audit log, dashboard, reports |
| `analyst` | All of `readonly` + update finding status, suppress/unsuppress, add notes |
| `admin` | Everything — manage API keys, push workflows, full audit access |

**Bootstrap flow:**
On first startup, Nyx automatically registers `NYX_API_KEY` from `.env` as the `bootstrap` key with `admin` scope. Once running, create dedicated scoped keys for each consumer and deactivate `bootstrap`.

**Recommended key hygiene:**
1. Create one key per consumer with the minimum required scope: CI/CD → `scanner`, dashboards → `readonly`, security engineers → `analyst`, admin tooling → `admin`
2. Set appropriate expiry dates (e.g., 365 days for CI keys). Use `API_KEY_MAX_LIFETIME_DAYS` to enforce a cap globally
3. Deactivate the bootstrap key after creating purpose-specific replacements
4. Review `last_used_at` monthly — deactivate any keys not seen in 30+ days
5. A daily background task logs a warning and writes an `api_key.expiry_warning` audit event for any key expiring within 7 days

</details>

<details>
<summary><strong>Audit Log</strong></summary>

Every action taken in Nyx is recorded in an append-only audit log with hash chain integrity. Each entry captures the actor (key name), scope used, action, resource type and ID, IP address, and full JSON metadata.

- **Covered events** — Finding status changes, suppression (with reason and escalation event for CRITICAL/HIGH), unsuppression, notes updates, assignment, bulk status updates, AI fix requests/approvals/rejections/regenerations, JIRA ticket lifecycle, scan imports (`submission_verified` flag included), repository registration/updates/deletion, workflow pushes, SBOM submissions and alerts, SLA policy and schedule CRUD, API key creation and deactivation, API key expiry warnings, regression auto-sort alerts
- **Hash chain integrity** — Every entry carries `entry_hash` (HMAC-SHA256 over all content fields, keyed by `NYX_SECRET_KEY`) and `prev_hash` (the previous entry's hash). Tampering with, deleting, or inserting any entry breaks the chain and is detectable
- **Chain verification** — `GET /api/v1/audit/verify` walks the complete chain chronologically and returns a report listing any breaks, with the entry ID, timestamp, and error type (`entry_hash mismatch` or `prev_hash mismatch`)
- **Filter bar** — Search by text (searches action name and metadata), filter by action prefix (finding, remediation, repository, scan, sbom, api_key, sla_policy, schedule), resource type, and date range
- **Expandable rows** — Click any row to expand the full JSON metadata for that event
- **Color coding** — Actions are color-coded by type for quick visual scanning
- **Download** — Export up to 10,000 entries as CSV or JSON. Pass `?include_hashes=true` to include `entry_hash` and `prev_hash` for out-of-band verification. JSON exports include a `chain_tip` field (hash of the last entry in the export) for integrity anchoring

</details>

---

## API Reference

All endpoints are prefixed with `/api/v1`. Authentication via `X-API-Key` header.

> [!TIP]
> Full interactive documentation is available at **`http://your-nyx-url:8000/docs`**

<details>
<summary><strong>Findings</strong></summary>

| Method | Path | Description |
|---|---|---|
| `GET` | `/findings` | List findings with filters (severity, scanner, status, repo, search, pagination) |
| `GET` | `/findings/{id}` | Get a single finding with full details |
| `PATCH` | `/findings/{id}/status` | Update finding status |
| `PATCH` | `/findings/{id}/notes` | Update engineer notes |
| `POST` | `/findings/{id}/suppress` | Suppress a finding with reason |
| `DELETE` | `/findings/{id}/suppress` | Unsuppress a finding |
| `PATCH` | `/findings/{id}/assign` | Assign a finding to an engineer |
| `GET` | `/findings/{id}/suppression-suggestion` | Get suppression pattern suggestion |
| `GET` | `/findings/suppression-patterns` | List all learned suppression patterns |
| `POST` | `/findings/bulk/status` | Bulk update status for multiple findings |
| `GET` | `/findings/export` | Export findings as CSV or JSON |
| `POST` | `/findings/generate-claude-prompt` | Generate a Claude Code remediation prompt for specific finding IDs (max 100); sets status to `IN_REMEDIATION` |
| `POST` | `/findings/generate-claude-prompt/repository/{id}` | Generate a Claude Code prompt for all open findings in a repository; sets status to `IN_REMEDIATION` |

</details>

<details>
<summary><strong>Repositories</strong></summary>

| Method | Path | Description |
|---|---|---|
| `GET` | `/repositories` | List all registered repositories |
| `POST` | `/repositories` | Register a new repository (auto-installs webhook) |
| `GET` | `/repositories/{id}` | Get repository details with risk metrics |
| `PATCH` | `/repositories/{id}` | Update repository scanners or default branch |
| `DELETE` | `/repositories/{id}` | Remove repository and all associated data |
| `POST` | `/repositories/{id}/webhook` | Refresh / reinstall the GitHub webhook |
| `POST` | `/repositories/{id}/sync-code-scanning` | Manually trigger GitHub Code Scanning sync |
| `POST` | `/repositories/{id}/push-workflow` | Push the canonical `nyx-scan.yml` to the repository via GitHub API |
| `GET` | `/repositories/{id}/risk-history` | Get 30-day risk score history |
| `POST` | `/repositories/{id}/detect-scanners` | Inspect repository contents and return recommended scanner set; pass `?auto_apply=true` to apply automatically |

</details>

<details>
<summary><strong>Scans</strong></summary>

| Method | Path | Description |
|---|---|---|
| `GET` | `/scans` | List scans (filter by repository, status, scanner) |
| `POST` | `/scans/import` | Import scanner JSON results. Requires `scanner` or `analyst` scope. Optionally include `X-Nyx-Submission-HMAC: sha256=<hmac>` for provenance verification — verified scans are flagged `submission_verified=true` |

</details>

<details>
<summary><strong>Remediation</strong></summary>

| Method | Path | Description |
|---|---|---|
| `GET` | `/remediation` | List all remediation requests |
| `POST` | `/remediation` | Request an AI fix for a finding |
| `POST` | `/remediation/bulk` | Request AI fixes for up to 20 findings at once |
| `GET` | `/remediation/{id}` | Get remediation details with diff |
| `POST` | `/remediation/{id}/approve` | Approve and create the GitHub PR |
| `POST` | `/remediation/{id}/reject` | Reject the proposed fix |
| `POST` | `/remediation/{id}/regenerate` | Regenerate the fix with new context |

</details>

<details>
<summary><strong>Dashboard</strong></summary>

| Method | Path | Description |
|---|---|---|
| `GET` | `/dashboard/summary` | KPI summary |
| `GET` | `/dashboard/trends` | Daily new/fixed/open findings for N days |
| `GET` | `/dashboard/mttr` | Mean time to remediate by severity |
| `GET` | `/dashboard/repo-risk` | Risk-scored repository list |
| `GET` | `/dashboard/top-vulnerabilities` | Most frequent vulnerability types |
| `GET` | `/dashboard/hot-repos` | Repos with most new findings in last N days |
| `GET` | `/dashboard/coverage-gaps` | Stale, unconfigured, partial-coverage repos |
| `GET` | `/dashboard/regressions` | Recent regression findings |
| `GET` | `/dashboard/org-risk-history` | 30-day aggregated org risk score history |
| `GET` | `/dashboard/compliance-trends` | Weekly compliance coverage % per framework |
| `GET` | `/dashboard/severity-trend` | Open counts by severity over time |

</details>

<details>
<summary><strong>Schedules, SLA Policies, Reports, Compliance, JIRA, SBOM, Webhooks, Audit</strong></summary>

**Schedules**

| Method | Path | Description |
|---|---|---|
| `GET` | `/schedules` | List all scan schedules |
| `POST` | `/schedules` | Create a new scan schedule |
| `PATCH` | `/schedules/{id}` | Update schedule (enable/disable, interval, scanners) |
| `DELETE` | `/schedules/{id}` | Delete a schedule |
| `POST` | `/schedules/{id}/trigger` | Manually trigger a schedule immediately |

**SLA Policies**

| Method | Path | Description |
|---|---|---|
| `GET` | `/sla-policies` | List all SLA policies |
| `POST` | `/sla-policies` | Create a new SLA policy |
| `PATCH` | `/sla-policies/{id}` | Update policy |
| `DELETE` | `/sla-policies/{id}` | Delete a policy |

**Reports**

| Method | Path | Description |
|---|---|---|
| `GET` | `/reports/executive` | Generate executive HTML report (printable to PDF) |

**Compliance**

| Method | Path | Description |
|---|---|---|
| `GET` | `/compliance/summary` | Compliance summary across all frameworks |
| `GET` | `/compliance/report/{framework_id}` | Detailed report for a specific framework |
| `GET` | `/compliance/report/{framework_id}/controls/{control_id}/findings` | Open findings mapped to a specific control |
| `GET` | `/compliance/frameworks` | List all supported frameworks |

**JIRA**

| Method | Path | Description |
|---|---|---|
| `POST` | `/jira/tickets/{finding_id}` | Create a JIRA ticket for a finding |
| `GET` | `/jira/tickets/{finding_id}` | Get the linked JIRA ticket |
| `POST` | `/jira/tickets/{finding_id}/sync` | Sync ticket status from JIRA |
| `DELETE` | `/jira/tickets/{finding_id}` | Unlink the ticket (does not delete from Jira) |
| `GET` | `/jira/repository/{repo_id}/tickets` | List all tickets for a repository |
| `POST` | `/jira/repository/{repo_id}/bulk-create` | Bulk create tickets for CRITICAL & HIGH findings |

**SBOM**

| Method | Path | Description |
|---|---|---|
| `POST` | `/sbom/repositories/{id}/generate` | Trigger GitHub Actions to generate a CycloneDX SBOM via Trivy (returns 202) |
| `POST` | `/sbom/repositories/{id}/submit` | Submit a raw CycloneDX or SPDX JSON SBOM; diffs against previous snapshot and creates change alert |
| `GET` | `/sbom/repositories/{id}/current` | Get the latest SBOM snapshot with full component list |
| `GET` | `/sbom/repositories/{id}/history` | List SBOM snapshots (newest first, no component detail) |
| `GET` | `/sbom/alerts` | List SBOM change alerts; pass `unacknowledged_only=true` for badge count |
| `POST` | `/sbom/alerts/{alert_id}/acknowledge` | Acknowledge a specific SBOM change alert |
| `POST` | `/sbom/alerts/acknowledge-all` | Acknowledge all unacknowledged SBOM alerts |

**Webhooks**

| Method | Path | Description |
|---|---|---|
| `POST` | `/webhooks/github` | GitHub webhook receiver (push, PR, check suite events) |
| `POST` | `/webhooks/snyk` | Snyk webhook receiver |

**Audit**

| Method | Path | Description |
|---|---|---|
| `GET` | `/audit` | Paginated audit log; filters: `actor`, `action`, `resource_type`, `search`, `date_from`, `date_to` |
| `GET` | `/audit/verify` | Walk the full audit log hash chain and report any tampered, deleted, or inserted entries. Returns `valid: true/false`, counts, and a list of chain breaks with entry ID and timestamp |
| `GET` | `/audit/download` | Download up to 10,000 audit entries as `json` or `csv`. Pass `?fmt=json\|csv` and `?include_hashes=true` to include `entry_hash`/`prev_hash` for out-of-band verification |

**Regression Auto-Sort Alerts**

| Method | Path | Description |
|---|---|---|
| `GET` | `/regression-alerts` | List regression auto-sort alerts; pass `unacknowledged_only=true` for badge count |
| `POST` | `/regression-alerts/{id}/acknowledge` | Acknowledge a specific alert |
| `POST` | `/regression-alerts/acknowledge-all` | Acknowledge all unacknowledged alerts |

**API Keys**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api-keys` | List all API keys — returns name, scopes, expiry, last-used, created-by. Never returns plaintext key or hash |
| `POST` | `/api-keys` | Create a new key. Body: `{"name": "ci-pipeline", "expires_in_days": 365, "scopes": "scanner"}`. Valid scopes: `scanner`, `readonly`, `analyst`, `admin`. Requires `admin` scope. Returns the plaintext key **once** — store it immediately |
| `DELETE` | `/api-keys/{key_id}` | Deactivate a key (soft delete — preserves audit trail). Requires `admin` scope. Rejected immediately on next use |

</details>

---

## Production Deployment

### Switch to PostgreSQL

A ready-to-use Compose override file is included:

```bash
# 1. Set the DATABASE_URL in .env
DATABASE_URL=postgresql+asyncpg://nyx:your-password@postgres:5432/nyx

# 2. Start with the postgres override (adds a postgres:16-alpine service and wires DATABASE_URL)
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
```

`docker-compose.postgres.yml` provides a `postgres:16-alpine` service with a health check, a named `postgres_data` volume, and wires `DATABASE_URL` in the backend service — no manual edits to `docker-compose.yml` required.

### Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name nyx.your-org.com;

    ssl_certificate /etc/letsencrypt/live/nyx.your-org.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nyx.your-org.com/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 50M;
    }
}

server {
    listen 80;
    server_name nyx.your-org.com;
    return 301 https://$server_name$request_uri;
}
```

```bash
# TLS certificate
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d nyx.your-org.com
```

### Production Environment Settings

```bash
ENVIRONMENT=production
HTTPS_ONLY=true
DEBUG=false
LOG_FORMAT=json
LOG_LEVEL=INFO
```

### Database Migrations

Migrations run automatically on container startup. To run manually:

```bash
# Apply all pending migrations
docker compose exec backend alembic upgrade head

# Check current status
docker compose exec backend alembic current

# Rollback one migration
docker compose exec backend alembic downgrade -1
```

### Backups

```bash
# SQLite
docker compose exec backend cp /app/data/nyx.db /app/data/nyx.db.backup.$(date +%Y%m%d)

# PostgreSQL
docker compose exec postgres pg_dump -U nyx nyx | gzip > nyx-backup-$(date +%Y%m%d).sql.gz

# Restore PostgreSQL
gunzip < nyx-backup-20260101.sql.gz | docker compose exec -T postgres psql -U nyx nyx
```

---

## Development Guide

### Local Setup (without Docker)

**Backend:**

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
python ../scripts/seed_demo_data.py  # optional demo data
uvicorn app.main:app --reload --port 8000
```

**Frontend:**

```bash
cd frontend
npm install
npm run dev  # proxies /api to localhost:8000
```

### Running Tests

```bash
cd backend
pip install -e ".[dev]"
pytest
pytest --cov=app --cov-report=html  # with coverage
```

### Code Quality

```bash
cd backend
ruff check .
ruff format .
```

### Adding a New Scanner

1. Create `backend/app/services/normalizers/your_scanner.py`
2. Implement `normalize(raw: dict, repository_id: str, git_ref: str) -> list[FindingCreate]`
3. Register in `backend/app/services/normalizers/__init__.py`
4. Add the scanner name to `ScannerType` enum in `backend/app/constants.py`
5. Add to `DEFAULT_ENABLED_SCANNERS_STR` in `.env.example`

---

## Troubleshooting

<details>
<summary><strong>Webhook not firing</strong></summary>

1. Verify the public URL is reachable:
   ```bash
   curl -I https://your-nyx-url/api/v1/webhooks/github
   ```
2. Check the webhook is installed: **GitHub → Repository → Settings → Webhooks**
3. Review recent webhook deliveries in GitHub — failed deliveries show the full response body
4. Check backend logs:
   ```bash
   docker compose logs backend -f --tail=50
   ```

</details>

<details>
<summary><strong>JIRA ticket creation failing</strong></summary>

1. Verify credentials:
   ```bash
   curl -u "your-email:your-api-token" \
     "https://your-org.atlassian.net/rest/api/3/project/SEC"
   ```
2. Ensure the Jira user has **Create Issues** permission in the target project
3. Confirm `JIRA_DEFAULT_PROJECT_KEY` matches a real project key exactly (case-sensitive)
4. Temporarily enable `JIRA_MOCK_MODE=true` to test the rest of the flow without real tickets

</details>

<details>
<summary><strong>AI fix generation failing</strong></summary>

1. Verify the Anthropic API key:
   ```bash
   curl -X POST "https://api.anthropic.com/v1/messages" \
     -H "x-api-key: $ANTHROPIC_API_KEY" \
     -H "anthropic-version: 2023-06-01" \
     -H "content-type: application/json" \
     -d '{"model":"claude-sonnet-4-6","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
   ```
2. Check account credit balance at https://console.anthropic.com
3. Review logs for prompt or token limit errors

</details>

<details>
<summary><strong>Findings not deduplicating</strong></summary>

Nyx deduplicates by fingerprint: `(rule_id, scanner, file_path, line_start, repository_id)`.

- Verify that scanner and rule ID are consistent between scans
- Ensure the file path is relative, not absolute
- Review scan worker logs for deduplication skip messages

</details>

<details>
<summary><strong>ZAP findings not appearing</strong></summary>

ZAP runs as a Docker container with uid `zap` (1000). The GitHub Actions runner workspace is owned by `runner`, so ZAP cannot write its output file — causing the step to fail silently and all downstream steps (Trivy, SBOM submit) to be skipped.

**Fix:** Use the **Push Workflow** button in Nyx. The canonical `nyx-scan.yml` includes a `chmod -R 777 .` step before ZAP runs. If you manage the workflow manually, add:

```yaml
- name: Fix workspace permissions for ZAP
  run: chmod -R 777 .
```

immediately before the ZAP step.

</details>

<details>
<summary><strong>Push Workflow returns 403</strong></summary>

GitHub requires the `workflow` scope on your PAT to write workflow files. Edit your token at **GitHub → Settings → Developer settings → Personal access tokens**, check the **Workflow** box, and click **Update token**. The token value stays the same — just re-save it in your `.env`.

</details>

<details>
<summary><strong>Backend becomes unhealthy / restarts needed</strong></summary>

The compose stack includes `willfarrell/autoheal` which monitors the backend's Docker healthcheck and automatically calls `docker restart` when it goes unhealthy. No manual intervention needed.

To check autoheal activity:
```bash
docker logs nyx-autoheal-1 -f
```

To check why the backend became unhealthy:
```bash
docker logs nyx-backend-1 --tail=50
```

> [!NOTE]
> The `autoheal` container mounts `/var/run/docker.sock`. This is standard for container management sidecars but means the autoheal container has host-level Docker access. On multi-tenant or production hardened hosts, consider restricting socket permissions or using a Docker socket proxy.

</details>

<details>
<summary><strong>Accessing persistent backend logs</strong></summary>

Nyx writes logs to both stdout (Docker logs) and a rotating file at `/app/logs/nyx.log` inside the backend container. The file is stored in the `nyx_logs` Docker volume, which survives `docker compose down`.

```bash
# Stream live logs (stdout)
docker compose logs backend -f --tail=100

# Read the persistent log file directly
docker compose exec backend tail -f /app/logs/nyx.log

# Copy logs to the host for analysis
docker compose cp backend:/app/logs/nyx.log ./nyx.log
```

Log rotation: 50 MB max file size, 5 backup files. Log format is JSON when `LOG_FORMAT=json` (default) for easy ingestion into Loki, Datadog, or any log aggregator.

</details>

<details>
<summary><strong>Scanner auto-detection not suggesting expected scanners</strong></summary>

Nyx inspects files in the repository via the GitHub API. If the detection misses a scanner:

1. Ensure `GITHUB_TOKEN` has **Contents: Read** access on the repository
2. Use the **Detect Scanners** button in the repository card (Repositories page) to re-run detection and review the `detection_reasons` in the response
3. Manually override via the repository edit dialog or:
   ```bash
   curl -X PATCH "https://your-nyx-url/api/v1/repositories/{id}" \
     -H "X-API-Key: $NYX_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"enabled_scanners": ["SEMGREP","TRIVY","SNYK","GITLEAKS"]}'
   ```

</details>

<details>
<summary><strong>API authentication returning 401</strong></summary>

1. Confirm the key you are sending matches one in **Settings → API Keys** (active, not expired)
2. Check that you are sending `X-API-Key: <value>` as a header — not a query parameter or body field
3. Inspect backend logs for the AUTH_FAILURE line:
   ```bash
   docker compose logs backend | grep AUTH_FAILURE
   ```
   The log line shows `reason=missing|invalid|expired` and the client IP.
4. If the key was recently deactivated, create a new one from the Settings page.
5. If you have no active keys and cannot authenticate, temporarily set a new `NYX_API_KEY` in `.env` and restart — Nyx will seed it as a new bootstrap key if no active keys exist.

</details>

<details>
<summary><strong>API returning 403 on a valid key</strong></summary>

A 403 (vs 401) means the key is valid but lacks the required scope for that endpoint.

1. Check the key's scope in **Settings → API Keys** — the scope column shows `scanner`, `readonly`, `analyst`, or `admin`
2. Match the required scope to the operation:
   - Submitting scans → `scanner` or `analyst`
   - Suppressing findings → `analyst` or `admin`
   - Creating/deactivating API keys → `admin` only
3. If the key needs broader access, deactivate it and create a new key with the appropriate scope. Scopes cannot be edited on existing keys.
4. The bootstrap key and env-var fallback always have `admin` scope.

</details>

<details>
<summary><strong>High memory / CPU usage</strong></summary>

For repositories with thousands of findings:

1. Switch to PostgreSQL (SQLite is not optimized for high concurrency)
2. Increase Docker resource limits in `docker-compose.yml`
3. Disable unused background tasks: `CODE_SCANNING_SYNC_ENABLED=false`

> [!WARNING]
> If you see "database is locked" errors, migrate to PostgreSQL immediately — SQLite does not handle high concurrency. Set `DATABASE_URL=postgresql+asyncpg://...`.

</details>

---

## Security Considerations

Nyx is designed to be deployed in security-sensitive environments and holds data that is directly relevant to your risk posture. The controls below describe the security measures built into Nyx and the configuration steps required to activate them in production.

### Authentication

| Area | Detail |
|---|---|
| **API keys** | Database-backed. When `NYX_SECRET_KEY` is set, each key is stored as `HMAC-SHA256(NYX_SECRET_KEY, raw_key)` — defeating rainbow table attacks even if the DB is leaked. Falls back to SHA-256 with a warning if `NYX_SECRET_KEY` is not configured. The plaintext key is never persisted. |
| **HTTP-only session cookie** | The dashboard Settings page exchanges the API key for an HTTP-only, SameSite=Strict session cookie via `POST /auth/session`. The key is never stored in `localStorage` or any JS-accessible storage — XSS cannot steal it. CI/CD tooling continues to use the `X-API-Key` header. |
| **Brute-force lockout** | After 20 failed authentication attempts from a single IP within a 10-minute window, that IP is blocked for 15 minutes with HTTP 429. Lockout state is persisted in the database and rehydrated on startup — container restarts do not reset active lockouts. |
| **Key scopes** | Every API key is assigned a scope: `scanner` (submit scans only), `readonly` (read-only access to findings and remediations), `analyst` (update/suppress findings, request/approve/reject remediations), or `admin` (full access including audit log and key management). Scope is enforced on every endpoint. **New keys default to `readonly` scope** — explicit escalation required. |
| **Scope enforcement** | `GET /findings`, `GET /findings/{id}`, and `GET /findings/export` require at least `readonly` scope — scanner keys cannot read findings. All audit log endpoints (`GET /audit`) require `admin` scope. Remediation approval, rejection, regeneration, and bulk dispatch require `analyst` or `admin` scope. |
| **Bootstrap key** | `NYX_API_KEY` in `.env` is seeded into the DB on first startup as the `bootstrap` key with `admin` scope. You can rotate it out via the Settings page without downtime. |
| **Key rotation** | Create a new key via Settings → API Keys with the appropriate scope, distribute it, then deactivate the old key. Zero downtime; old key is rejected immediately after deactivation. |
| **Key lifetime** | Set `API_KEY_MAX_LIFETIME_DAYS` to enforce a maximum key age. In production, leaving this at `0` (never expire) emits a startup warning. A daily background task emits `api_key.expiry_warning` audit events for keys expiring within 7 days. |
| **Auth failures** | Every failed authentication attempt is logged with the client IP, endpoint path, and failure reason (`missing` / `invalid` / `expired`). Forward backend logs to your SIEM to alert on spraying attempts. |
| **Dev mode** | If `NYX_API_KEY` is blank, the API is unauthenticated in development mode and logs a warning per request. In `ENVIRONMENT=production`, a missing `NYX_API_KEY` raises `RuntimeError` at startup. |

### Webhook Security

| Area | Detail |
|---|---|
| **Per-repo HMAC** | Each registered repository gets a unique 32-byte hex webhook secret stored encrypted in the database (when `NYX_SECRET_KEY` is set). Nyx verifies the `X-Hub-Signature-256` header on every delivery before processing the payload. |
| **Webhook secrets encrypted at rest** | When `NYX_SECRET_KEY` is configured, `Repository.webhook_secret` is encrypted with Fernet (AES-128-CBC + HMAC-SHA256). A DB breach does not expose secrets that could be used to forge future payloads. |
| **Pre-auth global HMAC** | Optionally set `NYX_WEBHOOK_SECRET` for a global pre-check before any database lookup, preventing unauthenticated repository enumeration. |
| **Replay deduplication** | GitHub's `X-GitHub-Delivery` ID is stored on each scan record. Duplicate delivery IDs are rejected idempotently — re-deliveries from GitHub do not create duplicate scans. |
| **Timestamp validation** | GitHub push events are checked against `repository.pushed_at`. Payloads older than 10 minutes are rejected with `403`. This limits the replay window beyond what delivery ID deduplication covers. PR and check_run events are not time-gated. |
| **Scan submission HMAC** | CI workflows can include an `X-Nyx-Submission-HMAC: sha256=<hmac>` header — `HMAC-SHA256(key=repo_webhook_secret, msg=SHA256(request_body))`. Nyx verifies this on import. Verified scans are flagged `submission_verified=true`; absent header accepted but flagged unverified. A compromised CI API key cannot fabricate a verified scan without also knowing the webhook secret. |
| **Snyk signatures** | `SNYK_WEBHOOK_SECRET` enables HMAC verification of Snyk payloads. In production mode, Nyx rejects all Snyk webhooks if this secret is not configured. |

### Audit Integrity

| Area | Detail |
|---|---|
| **HMAC hash chain** | Every audit log entry carries `entry_hash` — `HMAC-SHA256(NYX_SECRET_KEY, actor|action|resource_type|resource_id|metadata|ip|timestamp|prev_hash)` — and `prev_hash` (previous entry's hash). Modifying, deleting, or inserting any entry breaks the chain. |
| **Chain verification** | `GET /api/v1/audit/verify` walks the full chain and returns a machine-readable report. Run this on a schedule or before compliance reviews to confirm log integrity. |
| **Weak-key fallback** | If `NYX_SECRET_KEY` is not set in development, entries carry hashes using a fixed internal fallback key — tamper-evident but not cryptographically authenticated. In `ENVIRONMENT=production`, missing `NYX_SECRET_KEY` raises `RuntimeError` at startup to prevent this insecure state. |
| **Export verification** | JSON exports with `?include_hashes=true` include a `chain_tip` field — the hash of the last exported entry. Retain this value to verify future re-exports against a consistent baseline. |

### AI Integrity

| Area | Detail |
|---|---|
| **Prompt injection protection** | File content is wrapped in `<<<NYX_FILE_CONTENT_BEGIN/END>>>` delimiters; engineer-supplied context is wrapped in `<!-- BEGIN/END ENGINEER CONTEXT -->` markers. The system prompt explicitly instructs Claude to treat both sections as data only — not instructions. Scanner-sourced fields (title, rule ID, CWE IDs, severity, etc.) are validated and sanitized before interpolation. CWE IDs are validated against `CWE-\d+`; invalid values are dropped. |
| **Diff scope validation** | AI-generated diffs are checked to ensure they only touch the expected file (`finding.file_path`). Diffs touching CI/CD configuration (`.github/`), dependency manifests, Dockerfiles, or `.env` files are rejected. Path traversal sequences (`..`) in diff headers are also blocked. |
| **Diff integrity re-check** | Before applying a stored diff to create a PR, its SHA-256 is recomputed and compared against `ai_diff_sha256`. A mismatch (indicating DB tampering between generation and application) aborts PR creation with an error. |
| **Auto-merge requires admin** | The `auto_merge` flag in remediation approval is gated on `admin` scope — an analyst cannot trigger auto-merge; they can only approve for human review. |
| **Daily AI cost limit** | Each API key is limited to 50 AI remediation requests per 24-hour window (tracked via the audit log). Exceeding this returns HTTP 429. This prevents unbounded Anthropic API spend from a compromised or misbehaving key. |
| **Prompt storage** | The full rendered prompt is stored on each remediation record (DB-only; not exposed via API). Auditors can query the DB to verify exactly what context Claude was given. |
| **ai_prompt not in API responses** | The AI prompt is stored in the database for audit purposes but excluded from API responses to prevent information disclosure. |
| **AI output truncation** | If the explanation JSON from Claude cannot be parsed, the raw text is stored but capped at 2,000 characters — preventing unbounded AI output from filling the database. |
| **Analyst scope required** | Requesting, approving, rejecting, regenerating, and bulk-dispatching AI remediations all require `analyst` or `admin` scope. |
| **PR body sanitization** | All scanner-sourced fields included in the GitHub PR body (title, rule ID, CWE, file path) are sanitized to strip markdown injection characters before submission to GitHub. |

### Suppression Governance

| Area | Detail |
|---|---|
| **Scope enforcement** | Suppressing findings requires `analyst` or `admin` scope. A `scanner`-scoped CI key cannot suppress findings even if it has API access. |
| **Minimum reason length** | Suppressing a `CRITICAL` or `HIGH` finding requires a minimum 50-character justification. One-word reasons (`"fp"`, `"ok"`) are rejected. |
| **CRITICAL/HIGH escalation** | Suppressing any `CRITICAL` or `HIGH` finding fires two additional actions: a dedicated `finding.critical_suppressed` audit event (separate from the standard `finding.suppressed` — easier to alert on) and an outbound Slack notification via `NOTIFICATION_WEBHOOK_URL` including the actor, severity, title, repository, and truncated reason. This ensures CRITICAL suppressions are never silent. |
| **ACCEPTED_RISK expiry** | Accepting risk requires an expiry date (maximum 180 days). Nyx automatically reopens findings when the expiry passes, forcing periodic re-review rather than indefinite deferral. |
| **Suppression audit trail** | Every suppression records the actor's key name, the reason, the finding's severity, and the title in the audit log — meeting the evidence requirements for SOC 2 and ISO 27001 reviews. All audit entries are HMAC-signed and chain-linked for tamper detection. |

### Network & Infrastructure

| Area | Detail |
|---|---|
| **SSRF protection** | Outbound webhook calls (`NOTIFICATION_WEBHOOK_URL`) and Jira API calls (`JIRA_URL`) are checked against a blocklist of private IP ranges (RFC-1918, loopback, link-local, AWS metadata `169.254.169.254`) before any HTTP request is made. |
| **Rate limiting** | Client IP is resolved using only trusted reverse proxies (`TRUSTED_PROXY_CIDRS`). `X-Forwarded-For` is trusted only when the direct peer is in the configured CIDR list — preventing clients from spoofing their IP to bypass per-IP limits. Export: 10/min. Bulk update: 30/min. Webhook receivers: 60/min. |
| **Request size limit** | Incoming request bodies are capped at 50 MB. The import endpoint enforces this to prevent OOM attacks via oversized scanner payloads. |
| **JSON depth limit** | The JSON scan import endpoint rejects payloads with more than 20 levels of nesting — preventing JSON bomb / stack-overflow DoS via a crafted payload. |
| **Scanner field sanitization** | All scanner-sourced finding fields (title, description, file path, code snippet, URL, remediation guidance) are sanitized before DB storage: control characters (including Unicode bidi-overrides) are stripped, lengths are capped, and file paths are checked for absolute paths and traversal sequences. Only whitelisted scanner identifiers are accepted. |
| **Security headers** | `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and a strict `Content-Security-Policy: default-src 'none'` are set on all API responses. |
| **HTTPS enforcement** | Set `HTTPS_ONLY=true` to redirect all HTTP traffic and add `Strict-Transport-Security: max-age=31536000; includeSubDomains`. |
| **CORS** | Set `CORS_ORIGINS_STR` to exactly your frontend domain in production — `http://localhost:3000` is the default and must not be left in place. |
| **BREACH mitigation** | gzip compression is disabled on `/api/` proxy routes in nginx. Only static asset types (`text/css`, `application/javascript`, etc.) are gzip-compressed. This eliminates the BREACH attack surface on JSON API responses over HTTPS. |
| **Container hardening** | Both backend and frontend containers run as non-root users (`nyx` for backend, `nginx` for frontend). No `gosu` or setuid required — fully compatible with `no-new-privileges: true`. Both containers use `cap_drop: ALL` (nginx adds back only `NET_BIND_SERVICE`). |
| **No Docker socket mount** | The `autoheal` sidecar — which required mounting `/var/run/docker.sock` and granting container escape capability — has been removed. Container self-healing uses Docker's native `restart: unless-stopped` policy instead. |
| **Production startup checks** | In `ENVIRONMENT=production`, startup raises `RuntimeError` if: `NYX_API_KEY` is not set, `NYX_SECRET_KEY` is not set, `NYX_WEBHOOK_SECRET` is not set, `DEBUG=true`, or `DATABASE_URL` points to SQLite. The process will not start in an unsafe configuration. |
| **API docs hidden in production** | `/docs` and `/redoc` are only served when `ENVIRONMENT != production`. This prevents CSP relaxation and Swagger UI CDN asset loading in production environments. |

### Supply Chain

| Area | Detail |
|---|---|
| **CI tool checksums** | The generated `nyx-scan.yml` workflow verifies SHA-256 checksums for Gitleaks (against the published `checksums.txt`) and Hadolint (against the `.sha256` sidecar file) before executing either binary. A checksum mismatch fails the CI step with an explicit error. |
| **Actions pinned to SHA** | `actions/checkout`, `aquasecurity/trivy-action`, and `zaproxy/action-baseline` are all pinned to specific commit SHAs in `nyx-scan.yml`, preventing supply chain attacks via compromised upstream branches or force-pushed tags. |
| **Dynamic repo ID** | The `NYX_REPO_ID` used in `nyx-scan.yml` is read from a GitHub Actions variable (`vars.NYX_REPO_ID`) rather than hardcoded — set this in your repo's **Settings → Variables → Actions**. |
| **Bundled GHA scanning workflows** | Two GitHub Actions workflow templates are included in `.github/workflows/`: `nyx-scan-gitleaks.yml` (secret scanning with full history checkout on push, PR, and weekly schedule) and `nyx-scan-container.yml` (Trivy container image + IaC scanning on Dockerfile changes and daily schedule, results submitted to Nyx). Both are pinned to action commit SHAs. |
| **Preflight integration check** | Run `./nyx.sh check` to probe all integrations (database, Anthropic, GitHub, JIRA, Slack). Reports per-integration status with colour-coded output — useful in CI/CD before deploying a new environment. |
| **Debug output gated** | The ZAP debug output step (which prints scan finding counts) is only active when `vars.NYX_DEBUG == 'true'`. Set this variable only when actively debugging. |
| **Secrets detection** | A `.gitleaks.toml` configuration is included in the repo. Install gitleaks and add a pre-commit hook: `echo '#!/bin/sh\ngitleaks protect --staged' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit` |
| **Dependency upper bounds** | All Python dependencies in `requirements.txt` now have both lower and upper version bounds (e.g., `fastapi>=0.115.0,<1.0.0`) to prevent silent major-version upgrades. For production, generate a pinned lockfile: `pip install pip-tools && pip-compile requirements.txt`. |
| **GitHub Token** | Store in `.env` only — never commit. Rotate annually or on suspected exposure. Use GitHub Apps for production deployments at scale (higher rate limits, installation-scoped access). |
| **JIRA Token** | Treat as a password — it has write access to your Jira projects. Rotate via Atlassian account settings if exposed. |

---

## Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for development setup, coding standards, and the pull request process.

---

## Security Policy

If you discover a security vulnerability, please report it responsibly. See **[SECURITY.md](SECURITY.md)** for our disclosure process and supported versions.

---

<div align="center">

<br/>

**Nyx** — *goddess of night, illuminating what others cannot see*

<br/>

Built by Le Spooky Hacker (wanderersgrimoire@gmail.com)

</div>
