# CI/CD Integration

Wire Nyx into your continuous integration so every push triggers the right scans, pushes results back, and annotates PRs — without any manual intervention.

---

## The canonical workflow

Nyx ships a ready-to-use GitHub Actions workflow at `.github/workflows/nyx-scan.yml`. It runs five scanners in parallel (Semgrep, Bandit, Trivy, Grype, Checkov), pushes each result to Nyx via `POST /scans/import`, and fails the build if critical findings regress.

### Push it with one click

1. Dashboard → **Repositories** → pick a repo → **Push Workflow**
2. Pick the target branch (default `main`)
3. Nyx commits the workflow file via the GitHub Contents API

That's the entire deployment. No local `git` operations required.

> Requires the **Workflows** permission on your GitHub token — see [GitHub Integration](GitHub-Integration.md).


---

## Required GitHub repository settings

After clicking **Push Workflow**, configure these in the target repository under **Settings → Secrets and variables → Actions**:

### Secrets (Settings → Secrets and variables → Actions → Secrets)

| Secret | Value | Required |
|---|---|---|
| `NYX_API_KEY` | A **scanner-scoped** Nyx API key — create one from Nyx **Settings → API Keys** with `scanner` scope | Yes |
| `SNYK_TOKEN` | Snyk API token from [app.snyk.io/account](https://app.snyk.io/account) — enables the Snyk SCA step | Optional |

> **Never use an admin-scope key in CI.** A `scanner`-scoped key can submit scans but cannot suppress findings, manage keys, or access audit exports — limiting blast radius if a CI secret is ever compromised.

### Variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Value | Required |
|---|---|---|
| `NYX_URL` | Public URL of your Nyx instance, no trailing slash — e.g. `https://nyx.example.com` | Yes |
| `NYX_ZAP_TARGET` | Full URL of the deployed application to DAST scan — e.g. `https://myapp.com`. Setting this enables the separate `nyx-zap` job. | Optional |

> **Why variables instead of secrets for URLs?** GitHub Actions variables are not masked in logs — that's intentional here. URLs are not sensitive, and using a variable means they appear in workflow run logs which makes debugging easier. Only `NYX_API_KEY` and `SNYK_TOKEN` need to be secrets.

> **Note on `NYX_REPO_ID`:** You do **not** need to set a `NYX_REPO_ID` secret or variable. Nyx bakes the repository UUID directly into the workflow file at push time — it is a hardcoded string in the YAML, not read from the environment at runtime.

---

## Manual CI — if you don't use GitHub Actions

The endpoint is the same regardless of CI system. Here's a generic shell template that works anywhere:

```bash
# Assumes $NYX_URL, $NYX_API_KEY, $NYX_REPO_ID are set in env

semgrep --config=auto --json --output=semgrep.json .

curl -sf -X POST "$NYX_URL/api/v1/scans/import" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NYX_API_KEY" \
  --data-binary @- <<JSON
{
  "repository_id": "$NYX_REPO_ID",
  "scanner": "SEMGREP",
  "git_ref": "$(git rev-parse --abbrev-ref HEAD)",
  "git_sha": "$(git rev-parse HEAD)",
  "trigger": "push",
  "results": $(cat semgrep.json)
}
JSON
```

Adapt for GitLab CI, CircleCI, Jenkins, Bitbucket Pipelines, or whatever you run.

---

## Block merges on critical findings

Set on the Nyx side:

```bash
BLOCK_MERGE_ON_CRITICAL=true
```

When a scan on a PR introduces a CRITICAL finding, the `Nyx Security` Check Run transitions to `failure`. Combined with a GitHub branch protection rule requiring that check to pass, the PR becomes unmergeable until the finding is fixed, suppressed, or accepted.

---

## Fail-fast vs fail-last

`nyx-scan.yml` is configured with `fail-fast: false` so that a Semgrep failure doesn't skip Trivy. You get complete coverage on every run — findings from one scanner don't mask another. The **Check Run** aggregates across all scanners so engineers see the full picture on the PR.

---

## Recurring scans with Scan Schedules

CI covers push-time scans. For scheduled scans (nightly, weekly, ad-hoc), use the Nyx **Scan Schedules** feature instead of CI cron:

1. Repositories → pick a repo → **Schedules** tab
2. **Add Schedule** → pick interval (6h–1w)
3. The schedule worker triggers scans automatically

Scheduled scans don't require a PR to exist — useful for dependency scans that catch newly disclosed CVEs on code that hasn't changed.

---

## Dependabot integration

If the repository uses Dependabot, Nyx automatically picks up Dependabot alerts via the GitHub API and dedups them against Snyk/Grype findings. No CI step needed — the `dependabot_service.py` polls on the same interval as Code Scanning sync.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| CI passes but no findings appear | Check `NYX_URL` is reachable from the runner; check `NYX_API_KEY` scope |
| `202 Accepted` but nothing in Nyx | Check backend logs — payload may have failed schema validation |
| `401 Unauthorized` | Wrong or revoked API key |
| `403 Forbidden` | Key lacks `scanner` scope |
| `429 Too Many Requests` | Raise `RATE_LIMIT_PER_MINUTE` or stagger CI concurrency |

---

## What next

- **Scanner-specific commands →** [Scanners](Scanners.md)
- **SLA policy for CI gating →** [SLA Policies](SLA-Policies.md)
