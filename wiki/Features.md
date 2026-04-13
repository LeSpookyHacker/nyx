# Features

A full tour of what Nyx does, grouped by category. Each section has space for an annotated screenshot so you can drop in visuals that match your environment.

> For the terse feature matrix, see the project README. This page is the **long-form** walk-through — what each feature is, why it exists, how to use it, and where it lives in the UI.

---

## 1. Finding ingestion and consolidation

### Multi-scanner ingestion
Nyx accepts raw JSON output from eight first-class scanners and converts each into a unified `Finding` record. Supported today:

| Scanner | Type | Languages / targets |
|---|---|---|
| **Semgrep** | SAST | All major languages, rules-based |
| **Bandit** | SAST | Python |
| **Trivy** | Container + IaC + FS | Images, Kubernetes, Terraform |
| **Snyk** | SCA | Package manifests |
| **Grype** | SCA | Images, dir scans |
| **Checkov** | IaC | Terraform, K8s, Dockerfile |
| **OWASP ZAP** | DAST | Any HTTP endpoint |
| **GitHub Code Scanning** | SAST (polled) | Whatever CodeQL / partners are configured |

Each scanner has a dedicated **normalizer** under `backend/app/services/normalization/` that maps its schema onto Nyx's `Finding` shape. Adding a new scanner is a matter of implementing one class — see **[Adding a Scanner](Adding-a-Scanner.md)**.

<!-- IMAGE: Side-by-side mock showing raw Semgrep JSON → normalized Finding record.
     File: wiki/images/normalization-diagram.png -->
![Scanner normalization](images/normalization-diagram.png)
<!-- /IMAGE -->

### Cross-scanner deduplication
Nyx fingerprints findings by `(repository, file, line, rule_id, cwe)` plus a content hash of the surrounding code. When Trivy and Grype both report the same `CVE-2024-XXXX` on the same package, Nyx stores **one** finding with both scanners listed as corroborating sources. Dedup runs on every ingest in `deduplication_service.py`.

### Priority scoring (0–100)
Each finding gets a composite score combining:
- **CVSS base score** (30 %)
- **EPSS exploit probability** (25 %)
- **Finding age** (15 %)
- **SLA breach proximity** (20 %)
- **Exploitability modifiers** — public internet reachability, authentication requirements (10 %)

The dashboard sorts by priority score by default; you can override ordering on the Findings page.

<!-- IMAGE: Findings page sorted by priority score with the score column highlighted.
     File: wiki/images/findings-priority-sort.png -->
![Priority scoring](images/findings-priority-sort.png)
<!-- /IMAGE -->

### Regression detection
When a finding that was previously `FIXED` reappears, it is flagged `is_regression=True` and surfaced on both the dashboard regression banner and the regression-alerts bell tab. If the original finding had been `ACCEPTED_RISK` or `SUPPRESSED` with `auto_close_status`, the regression is **auto-sorted** back to that status — no engineer action required — and a batched alert is recorded with per-finding detail.

---

## 2. AI-powered remediation

### Single-finding fix
From any finding detail page, click **Request AI Fix**. Nyx gathers:

- The vulnerable code snippet and its surrounding context
- The file's existing test files (detected via conventional naming: `test_foo.py`, `foo.test.ts`, `tests/foo_test.go`)
- CWE and CVE metadata, CVSS + EPSS scores
- Any existing suppression hints for similar findings

…then prompts Claude for a targeted fix. The returned diff is stored, displayed inline, and optionally pushed as a pull request.

<!-- IMAGE: Finding detail page showing the "Request AI Fix" button and the streaming fix panel.
     File: wiki/images/ai-fix-request.png -->
![AI fix in progress](images/ai-fix-request.png)
<!-- /IMAGE -->

### SSE fix streaming
`GET /remediation/{id}/stream` streams progress as Server-Sent Events — the UI shows tokens appearing as Claude works, so engineers do not have to poll or wait blindly.

### Alternative fix suggestions
`POST /remediation/{id}/alternatives` requests 2–3 independently reasoned fix approaches with trade-off analysis. Useful when the first fix is correct but stylistically wrong for your codebase, or when you want to see a riskier / safer tradeoff pair.

### AI confidence gating
Every fix comes back with a self-reported confidence score. Fixes below `AI_MIN_CONFIDENCE_THRESHOLD` (default `0.7`) are tagged `REVIEW_LOW_CONFIDENCE` and surfaced for human review before they can be turned into a PR.

### Diff security scanning
Before any generated diff is stored, it is scanned for dangerous patterns:
- `os.system`, `eval`, `exec`
- Hardcoded secrets (API keys, tokens, passwords)
- Shell injection primitives
- Disabling TLS verification

Warnings are attached to the remediation record and shown in the UI — a gatekeeper against prompt-injected or hallucinated fixes.

### Bulk AI fix requests
Select up to 20 findings on the Findings page and click **Bulk AI Fix**. Each finding is queued with its own remediation worker; progress is visible in the Remediation page.

### Claude Code prompt generator
For fixes you want to hand-edit, Nyx can produce a structured, copy-ready prompt for **Claude Code** (the CLI). Select findings → **Generate Claude Code Prompt** → copy → paste into your terminal. The prompt is grouped by scanner category and includes code context, CVE data, and a completion-report template.

<!-- IMAGE: The Claude Code prompt modal with a populated prompt.
     File: wiki/images/claude-code-prompt.png -->
![Claude Code prompt generator](images/claude-code-prompt.png)
<!-- /IMAGE -->

---

## 3. Workflow and integrations

### GitHub
- **Automatic webhooks** on every registered repo (push, PR, check_suite)
- **Check Runs** with inline PR annotations for findings introduced on the branch
- **One-click workflow push** — deploy `nyx-scan.yml` to any registered repo via the GitHub API
- **Code Scanning sync** — poll the GitHub Code Scanning API and ingest findings automatically
- **Merge detection** — when a fix PR is merged, the linked finding closes itself

### JIRA
- **Per-finding tickets** with CVSS, description, diff, and PR link
- **Bulk ticket creation** for CRITICAL / HIGH findings in a repo
- **Bidirectional sync** — Nyx polls JIRA for status, assignee, and priority
- **Per-policy routing** — different repos / severities can go to different projects

### Notifications
Slack, Microsoft Teams, or any webhook URL. Events include new critical findings, SLA breaches imminent, regressions detected, SBOM drift, and AI-cost thresholds exceeded.

<!-- IMAGE: Sample Slack notification for a new critical finding.
     File: wiki/images/slack-notification.png -->
![Slack notification](images/slack-notification.png)
<!-- /IMAGE -->

---

## 4. SLA and governance

### SLA policy engine
Define per-repository, per-severity SLA windows. Example policy:

| Severity | Fix deadline |
|---|---|
| CRITICAL | 3 days |
| HIGH | 7 days |
| MEDIUM | 30 days |
| LOW | 90 days |

Each finding gets an `sla_deadline` computed on ingest. The hourly SLA checker worker escalates breaches via Slack/JIRA and tags the dashboard **SLA Status** card.

### Risk acceptance workflow
When a finding is a known, accepted risk, engineers can file a formal **risk acceptance** with:

- Business justification
- Compensating controls
- Evidence URL
- Approver
- Expiry date

Acceptances are auditable, revocable, and expire automatically.

### Suppression with governance
Suppressing a finding stores a pattern (`rule_id`, `file_glob`, `reason`). Future identical findings inherit the suppression automatically but are still tracked — nothing is silently dropped. Suppressions expire after `SUPPRESSION_MAX_AGE_DAYS` unless renewed.

### Audit log with HMAC hash chain
Every state-changing action is logged with `entry_hash` and `prev_hash` — walk the chain via `GET /audit/verify` to detect any modification, insertion, or deletion. This is a cryptographic guarantee, not a reputation score.

<!-- IMAGE: Audit page with the hash-chain verification result card.
     File: wiki/images/audit-verify.png -->
![Audit chain verification](images/audit-verify.png)
<!-- /IMAGE -->

---

## 5. Compliance and reporting

### Compliance mapping
Findings are mapped to controls in:

- **PCI DSS** (4.0)
- **SOC 2** Trust Services Criteria
- **NIST 800-53** Rev 5
- **CIS Controls** v8
- **OWASP Top 10** (2021)

Custom frameworks can be defined in the DB — see **[Compliance](Compliance.md)**.

### Executive PDF report
A print-ready report covers KPIs, trends, scanner breakdown by severity, SLA status (overdue / due soon / on track), per-repository breakdown, and compliance summary. Generate from the Reports page or `GET /reports/executive`.

<!-- IMAGE: First page of the executive PDF report.
     File: wiki/images/exec-report-cover.png -->
![Executive PDF report](images/exec-report-cover.png)
<!-- /IMAGE -->

### Velocity analytics
- Net-new vs fixed per day
- MTTR broken down by severity, scanner, and category
- Burndown estimate — "at current velocity, your backlog clears by X"
- Weekly trend

### AI cost dashboard
Token usage totals, estimated Claude API spend (using published pricing), daily time series, and top-10 most expensive remediations.

### SBOM generation and drift
Trivy produces a CycloneDX SBOM per repository on every scan. Nyx stores the latest and the previous, diffs them, and alerts on new components, removed components, or version bumps to vulnerable versions.

---

## 6. Platform and operations

### API key management
Database-backed API keys with four scopes:

| Scope | Allowed |
|---|---|
| `scanner` | Submit scans only |
| `readonly` | Read all data |
| `analyst` | Update / suppress findings, file acceptances |
| `admin` | Everything including key management |

Keys carry a name, optional expiry, last-used timestamp, and scope. The bootstrap key seeded from `NYX_API_KEY` gets `admin` scope on first start.

### Integration health check
`GET /health/integrations` probes database, Anthropic, GitHub, JIRA, and the notification webhook — used by uptime monitoring and Grafana.

### Autoheal
A companion container watches the backend's Docker healthcheck and restarts it if unhealthy. No more Monday-morning "why is the dashboard white."

### Log persistence
Backend logs survive `docker compose down` via a named volume, with a rotating handler capped at 50 MB × 5 files.

---

## 7. Visibility features

### Unified alert bell
Top-bar notification bell with two tabs — **SBOM component changes** and **Regression Auto-Sort batches**. Unread counts aggregate into the bell badge.

<!-- IMAGE: Alert bell dropdown showing both tabs with unread items.
     File: wiki/images/alert-bell.png -->
![Unified alert bell](images/alert-bell.png)
<!-- /IMAGE -->

### Hot repos
"Which repos got worse this week?" — lists repositories with the most new findings in the last 7 days.

### Scanner coverage gaps
Identifies repositories that are stale, unconfigured, or only partially covered by the scanner fleet — the report you want to hand to leadership when arguing for wider rollout.

### Custom compliance frameworks
Define your own frameworks (control IDs, CWE mappings, OWASP mappings). They appear alongside built-ins in every compliance view and report.

---

## Full feature matrix

For a terse one-line-per-feature matrix (useful when you already know what you are looking for), see the **Features** section at the top of the project [README](../README.md#features).

---

## What next

- **See each feature in action →** [Dashboard Guide](Dashboard-Guide.md)
- **Learn how to configure each one →** [Configuration Reference](Configuration.md)
- **Understand the system design →** [Architecture](Architecture.md)
