# CI/CD Integration

Wire Nyx into your continuous integration so every push triggers the right scans, pushes results back, and annotates PRs — without any manual intervention.

---

## The canonical workflow

Nyx ships a ready-to-use GitHub Actions workflow at `.github/workflows/nyx-scan.yml`. It runs seven scanners in parallel (Semgrep, Bandit, Trivy, Grype, Checkov, Hadolint, Gitleaks), pushes each result to Nyx via `POST /scans/import-json`, and fails the build if critical findings regress. A second shipped workflow, `nyx-scan-gitleaks.yml`, is a dedicated secrets-only pipeline for teams that want to scan the full git history on a different cadence than the main workflow.

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
| `NYX_WEBHOOK_SECRET` | The **per-repo** webhook secret — find it in Nyx: **Repositories → [your repo] → Reveal NYX_WEBHOOK_SECRET** button. **This is NOT the same as `NYX_WEBHOOK_SECRET` in `.env`** — see callout below. | Strongly recommended |
| `SNYK_TOKEN` | Snyk API token from [app.snyk.io/account](https://app.snyk.io/account) — enables the Snyk SCA step | Optional |

> ⚠️ **Name collision — `NYX_WEBHOOK_SECRET` means different things in two places:**
> - **In Nyx's `.env`:** a *global* pre-auth guard, intentionally left **empty** in standard setups
> - **In GitHub Actions secrets:** the *per-repo* HMAC signing key for this specific repository — get it from the **Reveal NYX_WEBHOOK_SECRET** button on the repository detail page in Nyx
>
> Never copy the value from `.env` into GitHub Actions, and never set the `.env` value to the per-repo secret. They serve different purposes. See [`.env.example`](../.env.example) for the full explanation.

> **Never use an admin-scope key in CI.** A `scanner`-scoped key can submit scans but cannot suppress findings, manage keys, or access audit exports — limiting blast radius if a CI secret is ever compromised.

### Variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Value | Required |
|---|---|---|
| `NYX_URL` | Public URL of your Nyx instance, no trailing slash — e.g. `https://nyx.example.com` | Yes |
| `NYX_ZAP_TARGET` | Full URL of the deployed application to DAST scan — e.g. `https://myapp.com`. Setting this enables the separate `nyx-zap` job. | Optional |

> **Why variables instead of secrets for URLs?** GitHub Actions variables are not masked in logs — that's intentional here. URLs are not sensitive, and using a variable means they appear in workflow run logs which makes debugging easier. Only `NYX_API_KEY` and `SNYK_TOKEN` need to be secrets.

> **Note on `NYX_REPO_ID`:** You do **not** need to set a `NYX_REPO_ID` secret or variable. Nyx bakes the repository UUID directly into the workflow file at push time — it is a hardcoded string in the YAML, not read from the environment at runtime.

---

## Scan submission verification (X-Nyx-Submission-HMAC)

Every scan submission to `POST /scans/import-json` can be signed so Nyx can verify the payload hasn't been tampered with or injected by someone who discovered your ngrok/public URL and API key.

### How it works

The workflow computes a two-step HMAC for each scanner payload before sending it to Nyx:

```
HMAC = HMAC-SHA256(key=NYX_WEBHOOK_SECRET, msg=request_body)
```

This is sent as the `X-Nyx-Submission-HMAC: sha256=<hex>` request header. Nyx verifies it on arrival using the per-repo `webhook_secret` stored in its database. Verified scans are flagged as `submission_verified: true` in the scan record and audit log.

### Setup

1. Go to the repository detail page in Nyx — the `NYX_WEBHOOK_SECRET` value is shown at the bottom of the header card (hidden by default, click **Reveal** then **Copy**).
2. Add it as a GitHub Actions secret named `NYX_WEBHOOK_SECRET` in the target repo under **Settings → Secrets and variables → Actions → Secrets**.

Each repository has its own webhook secret — set the correct one per repo.

> **Each repo has a unique secret.** Do not share the same `NYX_WEBHOOK_SECRET` across multiple repositories. If you push the Nyx workflow to a new repo, retrieve its specific secret from the Nyx repository detail page.

### Enforcement

By default, Nyx accepts scan submissions with or without the header — `submission_verified` is informational. To make the header mandatory (rejecting unsigned submissions entirely), set `REQUIRE_SUBMISSION_HMAC=true` in your Nyx `.env`. This is recommended for production deployments exposed to the internet.

---

## Manual CI — if you don't use GitHub Actions

The endpoint is the same regardless of CI system. Here's a generic shell template that works anywhere:

```bash
# Assumes $NYX_URL, $NYX_API_KEY, $NYX_REPO_ID, $NYX_WEBHOOK_SECRET are set in env

semgrep --config=auto --json --output=semgrep.json .

jq -n \
  --arg repo "$NYX_REPO_ID" \
  --arg ref "$(git rev-parse --abbrev-ref HEAD)" \
  --arg sha "$(git rev-parse HEAD)" \
  --slurpfile data semgrep.json \
  '{repository_id: $repo, scanner: "SEMGREP", git_ref: $ref, git_sha: $sha, trigger: "push", data: $data[0]}' \
  > /tmp/nyx_payload.json

# Compute submission HMAC: HMAC-SHA256(key=webhook_secret, msg=body)
HMAC=$(openssl dgst -sha256 -hmac "$NYX_WEBHOOK_SECRET" /tmp/nyx_payload.json \
  | awk '{print $NF}')

curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NYX_API_KEY" \
  -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \
  -d @/tmp/nyx_payload.json
```

Adapt for GitLab CI, CircleCI, Jenkins, Bitbucket Pipelines, or whatever you run.

---

## Block merges on critical findings

There is no Nyx-side env var for this — it's pure GitHub branch protection. Two things make it work:

1. Nyx already posts the `Nyx Security` Check Run with conclusion `failure` whenever a scan on a PR introduces a CRITICAL finding (assuming `GITHUB_CHECK_RUNS_ENABLED` is left at its default of `true`).
2. In your GitHub repo → **Settings → Branches → Branch protection rules**, add `Nyx Security` to **Require status checks to pass before merging**.

That combination makes the PR unmergeable until the finding is fixed, suppressed, or accepted as risk in Nyx — at which point the Check Run flips back to `success` on the next push or webhook delivery.

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
| `403 Forbidden` | Key lacks `scanner` scope, or `X-Nyx-Submission-HMAC` is present but invalid |
| `403` with `"Invalid X-Nyx-Submission-HMAC"` | `NYX_WEBHOOK_SECRET` in GitHub doesn't match the per-repo secret in Nyx — retrieve the correct value from the repository detail page and update the secret |
| Scans show `submission_verified: false` | `NYX_WEBHOOK_SECRET` secret is missing from the repo — add it as described in the [Scan submission verification](#scan-submission-verification-x-nyx-submission-hmac) section |
| `429 Too Many Requests` | Raise `RATE_LIMIT_PER_MINUTE` or stagger CI concurrency |

---

## What next

- **Scanner-specific commands →** [Scanners](Scanners.md)
- **SLA policy for CI gating →** [SLA Policies](SLA-Policies.md)
