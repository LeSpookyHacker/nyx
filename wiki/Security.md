# Security Hardening

Nyx is a security tool. It should not itself be a liability. This page is the threat model plus the exact controls you can turn on or verify.

> For responsible disclosure, see [SECURITY.md](../SECURITY.md) in the repo root.

---

## Threat model

| Asset | Threat | Control |
|---|---|---|
| **API keys** | Leakage → unauthorized scan ingest, data exfiltration | Scope-limited keys, optional expiry, last-used tracking, audit log on create/revoke |
| **Session cookies** | XSS → account takeover | Opaque random token (raw API key is never in the cookie), `HttpOnly`, `Secure` in prod, `SameSite=Strict`, server-side revocation via `user_sessions` table |
| **Scanner raw output at rest** | DB leak → leak of historic finding context and any embedded secrets | `scans.raw_output` is Fernet-encrypted at rest using a key derived from `NYX_SECRET_KEY`. Encryption is transparent on read; first startup runs a blocking backfill migration. |
| **Webhooks** | Forged payloads → fake findings, poisoned fixes | HMAC verification on every webhook receiver |
| **AI-generated diffs** | Prompt-injected or hallucinated malicious code | Diff security scanner, confidence gating, human approval before PR |
| **Audit log** | Tampering to erase actions | HMAC hash chain, append-only, verifiable via `/audit/verify` |
| **GitHub token** | Compromise → arbitrary writes to repos | Fine-grained PAT / GitHub App, scoped permissions, short expiry |
| **Anthropic key** | Compromise → cost explosion, data leakage | Scoped use, environment-only storage, per-fix output cap (`AI_MAX_OUTPUT_TOKENS`), confidence gating to reject speculative fixes |
| **Supply chain** | Compromised dependency | Pinned Python requirements, `package-lock.json` for frontend, Trivy SBOM + `trivy fs` on every push |

---

## Authentication

- **Cookie sessions** for the dashboard — on successful sign-in the backend mints a random opaque token, stores its SHA-256 hash in the `user_sessions` table, and returns only the raw token in an `HttpOnly`, `Secure` (in prod), `SameSite=Strict` cookie. The raw `NYX_API_KEY` never lives in the cookie jar. Revocation is a single row delete — no cryptographic invalidation required.
- **API keys** for programmatic access — database-backed, scoped (`admin` / `analyst` / `readonly` / `scanner`), optional expiry governed by `API_KEY_MAX_LIFETIME_DAYS`.
- **Auth lockout** — repeated invalid-key attempts from the same source IP are tracked in the `auth_lockouts` table and temporarily blocked. Lockout events are written to the audit log.
- **Dev-fallback hardening** — the silent-admin fallback used when `NYX_API_KEY` is unset refuses to activate if the instance looks production-ish (`GITHUB_WEBHOOK_ENDPOINT` set or `HTTPS_ONLY=true`). You cannot accidentally ship an internet-reachable Nyx that auto-grants admin.

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

- Every suppression records a pattern (`rule_id` + `file_glob` + `reason`) and an optional expiry date chosen at creation time (default: 180 days ahead, editable in the UI).
- Future matching findings inherit the suppression but are still **stored** — nothing is silently dropped.
- Suppressions expire at the chosen date unless explicitly renewed.
- The audit log captures every suppression create / renew / revoke with the actor and reason.

This means an attacker with `analyst` scope cannot make a finding disappear permanently — the original is always recoverable and the action is always visible.

---

## Network and infrastructure

- **Reverse proxy** is mandatory in production — Nyx does not ship TLS termination.
- **CORS** is locked down via `CORS_ORIGINS_STR` (comma-separated list). Wildcard is never safe.
- **No inbound ports** need to be open from the internet except `443` (and `80` for certbot renewals). The backend listens on `8000` on the internal Docker network only.
- **No database port** should be exposed. `docker-compose.postgres.yml` binds Postgres to the compose network, not the host.
- **Secrets** (GitHub App private key) mount as read-only Docker volumes with `chmod 600`.

---

## Supply chain

- **Python dependencies** are locked in `backend/requirements.txt` and installed with `pip install --no-deps` in the Dockerfile.
- **Frontend dependencies** are locked in `frontend/package-lock.json`.
- **Trivy scans itself** — the shipped `nyx-scan.yml` workflow runs Trivy filesystem scans on every push, so Nyx catches vulnerabilities in its own supply chain the same way it catches them in yours.

See `.github/workflows/nyx-scan.yml` for the canonical supply-chain scan that Nyx uses on itself.

---

## What a breach looks like and how to respond

| Indicator | Response |
|---|---|
| `audit/verify` returns `valid: false` | Freeze the system, pull the DB, find the first broken index, investigate |
| Sudden AI cost spike | Disable affected API key, check remediation history for abuse patterns |
| Unknown API key in the keys list | Revoke it immediately via Settings → API Keys, audit the `api_key.create` events to find the source, rotate any GitHub/Anthropic tokens the attacker could have seen. **Do not** rotate `NYX_SECRET_KEY` on a live DB — it keys the Fernet encryption for webhook secrets and `scans.raw_output`, and there is no online re-encrypt path. If you must rotate it, dump and re-encrypt those columns offline first. |
| Webhook signature mismatches in logs | Source IP and payload inspection; re-install webhook if legitimate drift |
| Unexpected PR opened by `nyx-bot` | Revert PR, disable GitHub token, audit remediation history |

---

## Responsible disclosure

Found something worrying? Don't open a public issue. Email the address in [SECURITY.md](../SECURITY.md).

---

## What next

- **Production deployment checklist →** [Deployment](Deployment.md)
- **Audit integrity walkthrough →** [API Reference](API-Reference.md#verify-audit-chain)
