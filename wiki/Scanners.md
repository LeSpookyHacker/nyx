# Scanner Integrations

Nyx does **not** run scanners for you — it accepts their JSON output and consolidates it. This keeps Nyx scanner-agnostic and plays nicely with whatever CI/CD you already have. Every scanner pushes to the same endpoint:

```
POST /api/v1/scans/import
X-API-Key: <your-nyx-key>
Content-Type: application/json

{
  "repository_id": "<nyx-repo-uuid>",
  "scanner": "SEMGREP",
  "git_ref": "main",
  "git_sha": "<commit-sha>",
  "trigger": "push",
  "results": { ...raw scanner JSON... }
}
```

> **Scanner-scoped API keys:** create a key with scope `scanner` from **Settings → API Keys** and use it in CI. It can submit scans but cannot read findings, manage keys, or touch the AI endpoints.

---

## Semgrep — SAST, all languages

```bash
pip install semgrep
semgrep --config=auto --json --output=semgrep-results.json .
```

**Recommended rulesets:** `p/owasp-top-ten`, `p/secrets`, `p/python`, `p/javascript`, `p/supply-chain`.

```bash
curl -s -X POST "$NYX_URL/api/v1/scans/import" \
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

## All-in-one GitHub Actions workflow

The canonical `nyx-scan.yml` that runs Semgrep, Bandit, Trivy, Grype, and Checkov in parallel and pushes results to Nyx lives at `.github/workflows/nyx-scan.yml`. Deploy it to any registered repository with the **Push Workflow** button (Repositories → repo → Push Workflow). See **[CI/CD Integration](CICD-Integration.md)** for the full breakdown.

<!-- IMAGE: A GitHub Actions run of nyx-scan.yml with all scanners green.
     File: wiki/images/github-actions-run.png -->
![GitHub Actions workflow run](images/github-actions-run.png)
<!-- /IMAGE -->

---

## Auto scanner detection

When you register a repo, Nyx inspects its contents and recommends the best scanner set:

| File detected | Scanner suggested |
|---|---|
| `requirements.txt`, `pyproject.toml` | Bandit, Semgrep, Grype |
| `package.json` | Semgrep, Snyk, Grype |
| `go.mod` | Semgrep, Grype |
| `Dockerfile` | Trivy, Checkov |
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
