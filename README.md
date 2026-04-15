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

**[Documentation](wiki/Home.md)** · **[Quick Start](#quick-start)** · **[Features](wiki/Features.md)** · **[Release Notes](wiki/Release-Notes.md)**

</div>

---

<div align="center">

![Nyx Dashboard](wiki/images/walkthrough-demo-data.png)

</div>

---

## Why Nyx?

Security tooling generates noise. **Nyx converts it into signal.**

Dozens of scanners, thousands of findings, hundreds of repositories — and no coherent view of what matters. Nyx sits between your scanners and your engineers: it deduplicates results, scores them by real-world exploitability, generates fix PRs with Claude, tracks SLA compliance, and maps everything to regulatory frameworks.

> **Zero friction from "vulnerability detected" to "vulnerability fixed"** — with a full audit trail at every step.

---

## Highlights

- 🔍 **Multi-scanner ingestion** — Semgrep, Bandit, Trivy, Snyk, Grype, Checkov, ZAP, GitHub Code Scanning
- 🧠 **Intelligent deduplication** across overlapping tools with cross-scanner fingerprinting
- 📊 **Priority scoring** combining CVSS, EPSS, fix age, and SLA breach factors
- 🤖 **AI remediation** — Claude generates fix PRs with explanations, tests, and confidence gating
- ⏱️ **SLA policy engine** with per-severity, per-repo deadlines and auto-escalation
- 🎫 **JIRA + GitHub integrations** — bidirectional ticket sync, PR merge detection, Check Runs
- 📋 **Compliance mapping** — PCI DSS, SOC 2, NIST 800-53, CIS, OWASP Top 10 + custom frameworks
- 📄 **Executive reporting** — printable PDFs, MTTR, velocity, AI cost, risk-over-time
- 🔑 **Scoped API keys** (`scanner`/`readonly`/`analyst`/`admin`) with tamper-evident audit chain

**[→ Full feature list](wiki/Features.md)**

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

**External scanners** push results via API: `SEMGREP` · `BANDIT` · `TRIVY` · `SNYK` · `GRYPE` · `CHECKOV` · `ZAP`

### End-to-end data flow

```
1.  Developer pushes code to GitHub
2.  GitHub webhook fires → Nyx webhook receiver
3.  Nyx triggers configured scanner(s) against the new commit
4.  Scanners push JSON results to POST /scans/import-json
5.  scan_worker processes results:
      a. Normalise raw output → Finding schema
      b. Deduplicate against existing findings (fingerprint match)
      c. Detect regressions (FIXED finding reappears → check auto_close_status:
         auto-restore to ACCEPTED_RISK/SUPPRESSED if set, otherwise flag as
         regression with is_regression=True)
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

**[→ Deep-dive: Architecture](wiki/Architecture.md)**

---

## Quick Start

> **Prerequisites:** Docker with Compose v2, Python 3, and curl.

```bash
git clone https://github.com/LeSpookyHacker/nyx.git
cd nyx
./setup.sh
```

The wizard checks prerequisites, generates secrets, prompts for your GitHub and Anthropic keys, then starts the stack. When it finishes, open **http://localhost:3000** and sign in with the printed API key.

| URL | What |
|---|---|
| **http://localhost:3000** | Dashboard |
| **http://localhost:8000/docs** | Interactive API docs |

Day-to-day management uses `./nyx.sh` (`status`, `stop`, `restart`, `logs`, `check`, `doctor`, `refresh`).

> ⚠️ If `NYX_API_KEY` is left blank, the API is unauthenticated. Fine for local evaluation — **never deploy publicly without a key set.**

**[→ Full installation guide](wiki/Installation.md)** · **[→ First-time walkthrough](wiki/First-Time-Walkthrough.md)**

---

## Documentation

The [**Nyx Wiki**](wiki/Home.md) is the long-form companion to this README. Every topic has its own page so you can find what you need without scrolling.

| Getting started | Integrations | Day-to-day | Operations |
|---|---|---|---|
| [Installation](wiki/Installation.md) | [GitHub](wiki/GitHub-Integration.md) | [AI Remediation](wiki/AI-Remediation.md) | [Deployment](wiki/Deployment.md) |
| [Configuration](wiki/Configuration.md) | [JIRA](wiki/JIRA-Integration.md) | [Findings](wiki/Findings-Management.md) | [Security](wiki/Security.md) |
| [First-time walkthrough](wiki/First-Time-Walkthrough.md) | [Scanners](wiki/Scanners.md) | [SLA Policies](wiki/SLA-Policies.md) | [Troubleshooting](wiki/Troubleshooting.md) |
| [Features](wiki/Features.md) | [CI/CD](wiki/CICD-Integration.md) | [Compliance](wiki/Compliance.md) | [Upgrading](wiki/Upgrading.md) |

**Developer reference:** [API Reference](wiki/API-Reference.md) · [Development Guide](wiki/Development.md) · [Adding a Scanner](wiki/Adding-a-Scanner.md) · [FAQ](wiki/FAQ.md)

---

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Contributing wiki page](wiki/Contributing.md) for branching, PR, and review expectations.

## Security

Found a vulnerability? Please see [SECURITY.md](SECURITY.md) for coordinated disclosure. Do **not** file security issues in the public tracker.

## License

See the repository root for license details.

<br/>

<div align="center">

**[📖 Read the Wiki](wiki/Home.md)** · **[🐛 Report an Issue](https://github.com/LeSpookyHacker/nyx/issues)** · **[🔐 Security Policy](SECURITY.md)**

<br/>

---

<br/>

Built by Le Spooky Hacker (wanderersgrimoire@gmail.com)

<br/>

**Nyx** — *goddess of night, illuminating what others cannot see*


</div>
