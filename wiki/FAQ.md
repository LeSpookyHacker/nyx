# FAQ

---

### What does Nyx actually do?

It ingests scanner output (Semgrep, Bandit, Trivy, Snyk, Grype, Checkov, ZAP, GitHub Code Scanning), deduplicates across scanners, ranks findings by a composite priority score, uses Claude to generate fix PRs, tracks SLAs, maps findings to compliance frameworks, and produces reports for leadership. Short version: a single pane of glass for security findings across every repo and scanner, with an AI doing the boring part.

---

### Does Nyx run scanners for me?

No. Nyx is scanner-agnostic and receives results via `POST /scans/import-json`. This keeps it flexible and avoids reinventing CI orchestration. The `nyx-scan.yml` workflow it ships runs the scanners inside your GitHub Actions.

---

### Do I need Docker?

Docker is the default deployment path and is strongly recommended. Running without Docker is supported for development — see [Development Guide](Development.md).

---

### SQLite or PostgreSQL?

- **SQLite** for evaluation, local dev, or tiny personal use.
- **PostgreSQL** for anything real — multi-user, multi-repo, or production. Switch with `docker-compose.postgres.yml`.

---

### Can I use a local LLM instead of Claude?

Not out of the box. The AI service is hard-coded against the Anthropic SDK today. Swapping it is a ~100-line change in `services/ai_service.py`, but you'll need to handle prompt format, token counting, streaming, and confidence gating yourself.

---

### How much does Claude cost to run?

Depends on fix volume. As a rough order: a Sonnet fix request consumes ~5–15k input tokens and ~1–3k output tokens. Check the **AI Cost dashboard** for real numbers on your usage. Set `AI_COST_ALERT_DAILY_USD` to get notified before a runaway batch costs real money.

---

### Is my code sent to Anthropic?

Yes, when you request an AI fix. Only the specific code context needed for the fix is sent, not the whole repo. Review your organization's AI policies before enabling. You can disable the AI features entirely by leaving `ANTHROPIC_API_KEY` unset.

---

### Does Nyx store my scanner raw output?

Yes, the raw JSON is stored on the `Scan` record so you can replay normalization if you upgrade the normalizer or diagnose a bug. If storage is a concern, add a lifecycle job that prunes raw payloads older than N days.

---

### Can Nyx run behind a corporate proxy?

Yes. Set `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` in the backend container environment. Both the GitHub SDK and the Anthropic SDK honor them.

---

### How do I give my CI pipeline access without giving it admin rights?

Create an API key with scope `scanner` (Settings → API Keys). It can submit scans and nothing else. See [CI/CD Integration](CICD-Integration.md).

---

### My scanner isn't supported. What do I do?

Implement a normalizer for it. It's a ~100 line file. See [Adding a Scanner](Adding-a-Scanner.md) for a complete walkthrough.

---

### Can I customize the AI prompt?

Yes — edit `backend/app/services/ai_service.py`. The system prompt and response schema live there. Any change should be paired with tests that verify existing fixes still parse.

---

### How do I trust the AI fixes?

Three layers: (1) confidence gating rejects low-confidence fixes, (2) diff security scanner blocks dangerous patterns, (3) no fix reaches a PR without a human clicking Approve. See [AI Remediation → Diff security scanning](AI-Remediation.md#diff-security-scanning).

---

### Can multiple teams use one Nyx instance?

Yes — use tags on repositories and per-policy routing to JIRA projects. Fully multi-tenant isolation is not a current feature; all data is visible to anyone with an API key or dashboard session.

---

### Does Nyx support SSO / SAML / OIDC?

Not yet. Current auth is cookie sessions + API keys. SSO is on the roadmap — open an issue if you need it and describe your IdP setup.

---

### How do I delete a finding?

You can't, on purpose. Findings transition through states but are never hard-deleted — the audit log requires them to stay for integrity. If you need to exclude a finding from reporting, suppress it.

---

### Where are the logs?

`./nyx.sh logs` tails backend logs. Files live under `/app/logs/` inside the container, backed by a named volume so they survive `docker compose down`. Rotation caps at 50 MB × 5 files.

---

### Does Nyx support on-prem Jira Server?

Nyx is tested against Jira Cloud. On-prem Jira Server/Data Center works for most endpoints but is not first-class — the ADF-formatted description bodies might need tweaking for older API versions.

---

### How do I contact someone about security issues?

See [SECURITY.md](../SECURITY.md). **Don't** open a public issue.

---

### Where can I see what's planned next?

The issue tracker on GitHub. Issues labeled `roadmap` are committed; `ideas` are candidates; `good-first-issue` is where contributors should start.
