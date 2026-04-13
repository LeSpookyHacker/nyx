# Nyx Wiki

> **Unified security findings management, AI-powered remediation, and compliance visibility for engineering teams.**

<!-- IMAGE: Hero screenshot of the Nyx dashboard landing view.
     Recommended: 1600x900, PNG, light-weight. Drop file into wiki/images/ and replace the path below. -->
![Nyx Dashboard Hero](images/hero-dashboard.png)
<!-- /IMAGE -->

Welcome to the **Nyx wiki** — the long-form companion to the project [README](../README.md). Where the README is a single reference document, this wiki splits every topic into a dedicated page so you can onboard, deploy, and extend Nyx without scrolling past anything you do not need.

---

## What is Nyx?

Security tooling generates noise. **Nyx converts it into signal.**

Engineering and security teams face a common problem: dozens of scanners produce thousands of findings across hundreds of repositories, with no coherent view of what matters, what is progressing, or what has regressed. Tickets fall through the cracks. Critical vulnerabilities linger for months. Compliance audits become crisis events.

Nyx sits between your scanners and your engineers. It ingests results from every scanner you already use — SAST, DAST, SCA, container, IaC — deduplicates them, scores them by real-world exploitability, surfaces what matters first, uses Claude AI to generate fix pull requests, tracks SLA compliance, maps findings to regulatory frameworks, and produces clean executive reports.

> **Zero friction from "vulnerability detected" to "vulnerability fixed"** — with a full audit trail at every step.

<!-- IMAGE: Short animated GIF or screenshot showing a finding → AI fix → PR flow.
     Suggested: wiki/images/flow-overview.gif -->
![End-to-end remediation flow](images/flow-overview.gif)
<!-- /IMAGE -->

---

## Wiki Index

### Getting started
- **[Installation](Installation.md)** — prerequisites, one-command setup, manual setup, first-run walkthrough
- **[Configuration Reference](Configuration.md)** — every `.env` variable explained
- **[First-Time Walkthrough](First-Time-Walkthrough.md)** — register a repo, push a scan, request your first AI fix

### Core concepts
- **[Features Overview](Features.md)** — everything Nyx does, grouped by category, with screenshots
- **[Architecture](Architecture.md)** — system design, data flow, components, storage
- **[Dashboard Guide](Dashboard-Guide.md)** — page-by-page tour of the UI with annotated screenshots

### Integrations
- **[GitHub Integration](GitHub-Integration.md)** — PAT vs GitHub App, webhooks, Check Runs, Code Scanning sync
- **[JIRA Integration](JIRA-Integration.md)** — API token, project mapping, bidirectional sync
- **[Scanner Integrations](Scanners.md)** — Semgrep, Bandit, Trivy, Snyk, Grype, Checkov, ZAP, GitHub Code Scanning
- **[CI/CD Integration](CICD-Integration.md)** — GitHub Actions template, scanner-scoped API keys, push-on-merge flow

### Day-to-day use
- **[AI Remediation](AI-Remediation.md)** — how Claude generates, scores, and streams fixes
- **[Findings Management](Findings-Management.md)** — triage, suppression, assignment, risk acceptance
- **[SLA Policies](SLA-Policies.md)** — per-severity deadlines, escalation, breach reporting
- **[Compliance Mapping](Compliance.md)** — PCI DSS, SOC 2, NIST 800-53, CIS, OWASP Top 10, custom frameworks
- **[Reports & Analytics](Reports.md)** — executive PDFs, velocity, MTTR, AI cost, risk-over-time

### Operations
- **[Production Deployment](Deployment.md)** — PostgreSQL, Nginx + TLS, backups, migrations
- **[Security Hardening](Security.md)** — authentication, webhook verification, audit chain, supply chain
- **[Troubleshooting](Troubleshooting.md)** — common errors and fixes
- **[Upgrading Nyx](Upgrading.md)** — safe upgrade procedure

### Developer reference
- **[API Reference](API-Reference.md)** — REST endpoints grouped by router
- **[Development Guide](Development.md)** — local dev without Docker, tests, code style
- **[Adding a Scanner](Adding-a-Scanner.md)** — implement `AbstractNormalizer` and wire it in
- **[Contributing](Contributing.md)** — branching, PRs, code review expectations
- **[FAQ](FAQ.md)** — common questions

---

## Quick navigation by role

| I am a... | Start here |
|---|---|
| **Developer** evaluating Nyx | [Installation](Installation.md) → [First-Time Walkthrough](First-Time-Walkthrough.md) |
| **Security engineer** deploying for a team | [GitHub Integration](GitHub-Integration.md) → [Scanners](Scanners.md) → [SLA Policies](SLA-Policies.md) |
| **Platform/DevOps** shipping Nyx to prod | [Production Deployment](Deployment.md) → [Security Hardening](Security.md) |
| **Engineering leader** reading results | [Reports & Analytics](Reports.md) → [Compliance Mapping](Compliance.md) |
| **Contributor** extending Nyx | [Development Guide](Development.md) → [Adding a Scanner](Adding-a-Scanner.md) |

---

## Project links

- **Repository:** https://github.com/LeSpookyHacker/nyx
- **Issues:** https://github.com/LeSpookyHacker/nyx/issues
- **Security policy:** [SECURITY.md](../SECURITY.md)
- **License:** see repository root

---

## A note on images

This wiki includes `<!-- IMAGE: ... -->` markers throughout. Each one is a placeholder for a screenshot or diagram — drop the file into `wiki/images/` with the filename shown, and the image will render automatically on GitHub. Every image is optional; pages remain readable without them.
