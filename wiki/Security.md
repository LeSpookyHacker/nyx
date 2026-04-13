# Security Hardening

Nyx is a security tool. It should not itself be a liability. This page is the threat model plus the exact controls you can turn on or verify.

> For responsible disclosure, see [SECURITY.md](../SECURITY.md) in the repo root.

---

## Threat model

| Asset | Threat | Control |
|---|---|---|
| **API keys** | Leakage → unauthorized scan ingest, data exfiltration | Scope-limited keys, optional expiry, last-used tracking, audit log on create/revoke |
| **Session cookies** | XSS → account takeover | `HttpOnly`, `Secure`, `SameSite=Lax`, CSRF tokens on state-changing routes |
| **Webhooks** | Forged payloads → fake findings, poisoned fixes | HMAC verification on every webhook receiver |
| **AI-generated diffs** | Prompt-injected or hallucinated malicious code | Diff security scanner, confidence gating, human approval before PR |
| **Audit log** | Tampering to erase actions | HMAC hash chain, append-only, verifiable via `/audit/verify` |
| **GitHub token** | Compromise → arbitrary writes to repos | Fine-grained PAT / GitHub App, scoped permissions, short expiry |
| **Anthropic key** | Compromise → cost explosion, data leakage | Daily spend alert, scoped use, environment-only storage |
| **Supply chain** | Compromised dependency | SBOM on Nyx itself, signed images, CI trivy scan |

---

## Authentication

- **Cookie sessions** for the dashboard — `HttpOnly`, `Secure` in prod, `SameSite=Lax`, signed with `NYX_SECRET_KEY`, default TTL 24 hours.
- **API keys** for programmatic access — database-backed, scoped, optional expiry.
- **Auth lockout** — after `AUTH_LOCKOUT_MAX_ATTEMPTS` (default 5) failed key attempts in `AUTH_LOCKOUT_WINDOW` seconds, the source IP is temporarily blocked. Lockout events are audited.
- **CSRF** — double-submit cookie on all state-changing routes. Disable only if you understand what you are turning off.

**Key rotation:** from Settings → API Keys → click a key → **Rotate**. The old value is invalidated immediately; any CI job using it will get `401` until updated. Use `last_used_at` to find stale keys before rotating.

---

## Webhook security

Every incoming webhook is HMAC-verified:

- **GitHub** — `X-Hub-Signature-256`, per-repo secret generated on webhook install
- **Snyk** — `X-Snyk-Signature`, global secret from `SNYK_WEBHOOK_SECRET`
- **Generic** — `X-Nyx-Signature`, secret from `NYX_WEBHOOK_SECRET`

Unsigned or invalid-signature deliveries get `401`, are logged, and **do not** trigger any downstream processing. The webhook handler is also idempotent on delivery ID — replay attacks are caught before they touch the database.

---

## Audit integrity

The audit log is append-only and cryptographically chained:

```
entry_N.prev_hash = HMAC(NYX_SECRET_KEY, entry_{N-1}.entry_hash)
entry_N.entry_hash = HMAC(NYX_SECRET_KEY, entry_N.payload || entry_N.prev_hash)
```

Any modification, insertion, or deletion breaks the chain. Verify with:

```bash
curl -s -H "X-API-Key: $NYX_API_KEY" \
  https://your-nyx-url/api/v1/audit/verify | jq
```

Schedule this as a cron and page on `valid: false`.

<!-- IMAGE: Audit chain verification returning valid: true.
     File: wiki/images/audit-verify-result.png -->
![Audit verify result](images/audit-verify-result.png)
<!-- /IMAGE -->

---

## AI integrity

Three layers sit between a Claude response and a merged PR:

1. **Diff security scanner** — heuristic pattern matching for `os.system`, `eval`, hardcoded secrets, shell injection, TLS-disable, auth-middleware removal. Matches become `diff_warnings` and require human acknowledgement.
2. **Confidence gating** — fixes below `AI_MIN_CONFIDENCE_THRESHOLD` are tagged `REVIEW_LOW_CONFIDENCE` and cannot be auto-PR'd.
3. **Human approval** — low-confidence and warning-flagged fixes require an engineer to click **Approve & Open PR** before anything is pushed to GitHub.

There is no path where an AI fix becomes a merged commit without at least one human click.

---

## Suppression governance

Suppressions are **soft**, not hard:

- Every suppression records a pattern (`rule_id` + `file_glob` + `reason`) and an expiry.
- Future matching findings inherit the suppression but are still **stored** — nothing is silently dropped.
- Suppressions expire after `SUPPRESSION_MAX_AGE_DAYS` (default 180) unless renewed.
- The audit log captures every suppression create / renew / revoke with the actor and reason.

This means an attacker with `analyst` scope cannot make a finding disappear permanently — the original is always recoverable and the action is always visible.

---

## Network and infrastructure

- **Reverse proxy** is mandatory in production — Nyx does not ship TLS termination.
- **CORS** is locked down via `CORS_ALLOWED_ORIGINS`. Wildcard is never safe.
- **No inbound ports** need to be open from the internet except `443` (and `80` for certbot renewals). The backend listens on `8000` on the internal Docker network only.
- **No database port** should be exposed. `docker-compose.postgres.yml` binds Postgres to the compose network, not the host.
- **Secrets** (GitHub App private key) mount as read-only Docker volumes with `chmod 600`.

---

## Supply chain

- **Nyx's own SBOM** is built on every CI run via Trivy. It lives in the repository release assets.
- **Docker images** are pinned to digests in `docker-compose.yml`, not floating tags.
- **Python dependencies** are locked in `requirements.txt` (generated from `pyproject.toml`).
- **Frontend dependencies** are locked in `frontend/package-lock.json`.
- **CI runs `trivy fs` on the repo** on every push, and on the built images on every release tag.

See `.github/workflows/nyx-scan.yml` for the canonical supply-chain scan that Nyx uses on itself.

---

## What a breach looks like and how to respond

| Indicator | Response |
|---|---|
| `audit/verify` returns `valid: false` | Freeze the system, pull the DB, find the first broken index, investigate |
| Sudden AI cost spike | Disable affected API key, check remediation history for abuse patterns |
| Unknown API key in the keys list | Revoke immediately, audit create events, rotate `NYX_SECRET_KEY` |
| Webhook signature mismatches in logs | Source IP and payload inspection; re-install webhook if legitimate drift |
| Unexpected PR opened by `nyx-bot` | Revert PR, disable GitHub token, audit remediation history |

---

## Responsible disclosure

Found something worrying? Don't open a public issue. Email the address in [SECURITY.md](../SECURITY.md).

---

## What next

- **Production deployment checklist →** [Deployment](Deployment.md)
- **Audit integrity walkthrough →** [API Reference](API-Reference.md#verify-audit-chain)
