# Scanner Integrations

Nyx does **not** run scanners for you — it accepts their JSON output and consolidates it. This keeps Nyx scanner-agnostic and plays nicely with whatever CI/CD you already have. Every scanner pushes to the same endpoint:

```
POST /api/v1/scans/import-json
X-API-Key: <your-nyx-key>
Content-Type: application/json

{
  "repository_id": "<nyx-repo-uuid>",
  "scanner": "SEMGREP",
  "git_ref": "main",
  "data": { ...raw scanner JSON... }
}
```

> Nyx also exposes a multipart `POST /api/v1/scans/import` endpoint for direct file uploads (`curl -F file=@results.json`). For CI/CD the JSON endpoint above is easier — that's what the Nyx-shipped workflow uses.

> **Scanner-scoped API keys:** create a key with scope `scanner` from **Settings → API Keys** and use it in CI. It can submit scans but cannot read findings, manage keys, or touch the AI endpoints.

---

## Semgrep — SAST, all languages

```bash
pip install semgrep
semgrep --config=auto --json --output=semgrep-results.json .
```

**Recommended rulesets:** `p/owasp-top-ten`, `p/secrets`, `p/python`, `p/javascript`, `p/supply-chain`.

```bash
jq -n \
  --arg repo "$NYX_REPO_ID" \
  --arg ref "$(git branch --show-current)" \
  --arg sha "$(git rev-parse HEAD)" \
  --slurpfile data semgrep-results.json \
  '{repository_id: $repo, scanner: "SEMGREP", git_ref: $ref, git_sha: $sha, trigger: "push", data: $data[0]}' | \
curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NYX_API_KEY" \
  -d @-
```

<!-- IMAGE: Terminal output of a successful Semgrep push returning 202 Accepted.
     File: wiki/images/semgrep-push.png -->
![Semgrep push](images/semgrep-push.png)
<!-- /IMAGE -->

---

## Bandit — Python SAST

```bash
pip install bandit
bandit -r . -f json -o bandit-results.json
# Push with scanner: "BANDIT"
```

---

## Trivy — container, IaC, filesystem

```bash
# macOS
brew install aquasecurity/trivy/trivy

# Container image
trivy image --format json --output trivy-results.json your-org/your-image:latest

# Filesystem / source tree
trivy fs --format json --output trivy-results.json .

# Kubernetes / Terraform manifests
trivy config --format json --output trivy-results.json ./infra/

# Push with scanner: "TRIVY"
```

Trivy output also seeds **SBOM generation** — the `CycloneDX` output is stored and diffed against the previous SBOM for drift alerts.

---

## Grype — SCA, dependency vulnerabilities

```bash
# macOS
brew install anchore/grype/grype

grype dir:. -o json > grype-results.json
# or container:
grype your-org/your-image:latest -o json > grype-results.json

# Push with scanner: "GRYPE"
```

---

## Snyk — SCA

```bash
npm install -g snyk
snyk auth
snyk test --json > snyk-results.json

# Push with scanner: "SNYK"
```

> Snyk also supports a direct webhook receiver. Set `SNYK_WEBHOOK_SECRET` in `.env` and configure a Snyk webhook pointing to `/api/v1/webhooks/snyk`.

---

## Checkov — IaC misconfigurations

```bash
pip install checkov

checkov -d ./terraform --output json > checkov-results.json
checkov -d ./k8s --output json > checkov-results.json
checkov -f Dockerfile --output json > checkov-results.json

# Push with scanner: "CHECKOV"
```

---

## Hadolint — Dockerfile linting

```bash
# macOS
brew install hadolint

hadolint -f json Dockerfile > hadolint-results.json

# Push with scanner: "HADOLINT"
```

Catches Dockerfile best-practice violations (pinned base images, `USER` directive present, no `ADD` when `COPY` would do, shell form vs exec form, etc.). The shipped `nyx-scan.yml` runs Hadolint automatically when a `Dockerfile` is present.

---

## Gitleaks — secrets detection across full git history

```bash
# macOS
brew install gitleaks

gitleaks detect --source . --report-format json --report-path gitleaks-results.json

# Push with scanner: "GITLEAKS"
```

Gitleaks scans the **entire git history**, not just the current working tree — so it catches secrets that were committed and later removed without rotation. This is why the shipped `nyx-scan-gitleaks.yml` workflow uses `fetch-depth: 0` on the checkout step. Running it on shallow clones silently misses findings.

> If you set `GITLEAKS_CONFIG` to a path, Gitleaks reads custom rules from there. Useful for suppressing known-safe placeholders without polluting the default rule set.

---

## OWASP ZAP — DAST

```bash
docker run --rm -v $(pwd):/zap/wrk owasp/zap2docker-stable \
  zap-baseline.py -t https://your-app.example.com -J zap-results.json

# Push with scanner: "ZAP"
```

---

## GitHub Code Scanning — automatic pull

No CI step required. Enable in `.env`:

```bash
CODE_SCANNING_SYNC_ENABLED=true
CODE_SCANNING_POLL_INTERVAL=3600  # seconds
```

Nyx polls the GitHub Code Scanning API for every registered repo and imports alerts as findings.

---

## Dependabot — automatic pull

Also no CI step. Dependabot alerts are pulled from GitHub's API on the same schedule as Code Scanning and dedup against Snyk/Grype by CVE. As long as Dependabot is enabled on the repo and your GitHub token carries the `security_events` scope, Nyx picks them up automatically. See **[CI/CD Integration](CICD-Integration.md)** for the Dependabot-specific notes.

---

## All-in-one GitHub Actions workflow

The canonical `nyx-scan.yml` that runs Semgrep, Bandit, Trivy, Grype, Checkov, Hadolint, and Gitleaks in parallel and pushes results to Nyx lives at `.github/workflows/nyx-scan.yml`. Deploy it to any registered repository with the **Push Workflow** button (Repositories → repo → Push Workflow). A dedicated `nyx-scan-gitleaks.yml` is also shipped for teams that want secrets scanning on a separate schedule (for example, scanning the full history weekly while the main workflow runs on every push). See **[CI/CD Integration](CICD-Integration.md)** for the full breakdown.

<!-- IMAGE: A GitHub Actions run of nyx-scan.yml with all scanners green.
     File: wiki/images/github-actions-run.png -->
![GitHub Actions workflow run](images/github-actions-run.png)
<!-- /IMAGE -->

---

## Auto scanner detection

When you register a repo, Nyx inspects its contents and recommends the best scanner set:

| File detected | Scanner suggested |
|---|---|
| Any repo with a `.git` directory | Gitleaks |
| `requirements.txt`, `pyproject.toml` | Bandit, Semgrep, Grype |
| `package.json` | Semgrep, Snyk, Grype |
| `go.mod` | Semgrep, Grype |
| `Dockerfile` | Trivy, Checkov, Hadolint |
| `*.tf`, `terraform/` | Checkov, Trivy |
| `k8s/`, `*.yaml` (manifests) | Checkov, Trivy |
| Any web-facing app | ZAP (manual configuration) |

Apply the recommendation with one click, or set `SCANNER_DETECTION_AUTO_APPLY=true` to adopt automatically.

---

## Adding a scanner

Implement `AbstractNormalizer` in `backend/app/services/normalization/<your_scanner>.py`, register it in `NORMALIZERS`, and you are done. Full walkthrough at **[Adding a Scanner](Adding-a-Scanner.md)**.

---

## What next

- **Wire scans into CI/CD →** [CI/CD Integration](CICD-Integration.md)
- **Review ingested findings →** [Dashboard Guide](Dashboard-Guide.md)
- **Get AI fixes for what is found →** [AI Remediation](AI-Remediation.md)
