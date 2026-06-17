# Security Audit — Nyx — 2026-06-16 (Pass 3)

## Executive summary

- **Scope:** Full repo at commit `461391e`, ~175 source files reviewed (backend Python, frontend TS/TSX, CI/CD workflows, Dockerfiles, manifests).
- **Findings:** Critical **1** · High **11** · Medium **19** · Low **13** · Info **1**
- **Previously-fixed findings (Pass 1 + Pass 2) — all verified clean:** SEC-001 (DOMPurify), SEC-002 (scope enforcement on findings mutations), SEC-003 (Gitleaks checksum), SEC-004 (safeUrl on FindingDetailPage + RemediationPage), SEC-005 (webhooks.py dead try-except), SEC-006 (HKDF-SHA256 v2 prefix), SEC-007 (limiter key function), SEC-008 (GitHub IP fallback), SEC-009 (prompt injection regex), SEC-101 (HTTPS-only SSRF guard), SEC-102 (safeUrl shared util), SEC-103 (posixpath.normpath traversal), SEC-104 (with_for_update), SEC-105 (streaming body size middleware), SEC-106 (add_repository rate limit), SEC-107 (generate_claude_prompt rate limit), SEC-108 (NYX_REPO_ID in env blocks), SEC-109 (snyk webhook type guards), SEC-110 (string literal scope).
- **Top risks:**
  - The SEC-006 crypto rewrite introduced three regressions: an ImportError that silently disables at-rest encryption, a double-encryption bug on every restart, and a key-rotation function that uses the wrong KDF — corrupting all webhook secrets on rotation.
  - The `/auth/session` endpoint has no per-endpoint rate limit and uses the raw TCP peer IP (not the real client IP behind a proxy) for lockout — brute-force protection is effectively bypassed in the default Docker deployment.
  - Broad scope-enforcement gaps across `repositories.py`, `jira.py`, `regression_alerts.py`, and `compliance.py` allow low-privilege SCANNER keys to delete repositories, close security findings via Jira sync, and silence regression alerts.
  - A missed `safeUrl()` call in `RepositoryDetailPage.tsx` leaves one XSS vector open after the SEC-004/SEC-102 fixes.
- **Overall posture:** The codebase has improved significantly after two remediation passes. However, the crypto rewrite (SEC-006) introduced Critical/High regressions that must be addressed immediately, and the scope-enforcement pattern established in `findings.py` needs to be applied consistently across all remaining routers. The auth brute-force protection contains a proxy-bypass bug that undermines a key security control in the standard deployment.

---

## Findings index

| ID | Severity | Confidence | Category | Location | Title |
|----|----------|------------|----------|----------|-------|
| SEC-201 | Critical | Confirmed | A02 Crypto | `database.py:70` | ImportError `_get_fernet` silently disables at-rest encryption backfill |
| SEC-202 | High | Confirmed | A02 Crypto | `database.py:90` | Wrong prefix check double-encrypts v2 tokens on every restart |
| SEC-203 | High | Confirmed | A02 Crypto | `security.py:823` | `rotate_secret_key` uses PBKDF2 — mismatches HKDF, corrupts webhook secrets |
| SEC-204 | High | Confirmed | A07 Auth | `main.py:597` | `/auth/session` lacks per-endpoint rate limit — 300 req/min brute-force window |
| SEC-205 | High | Confirmed | A07 Auth | `main.py:631` | `/auth/session` uses raw peer IP not `get_client_ip()` — lockout bypassed behind proxy |
| SEC-206 | High | Confirmed | A01 Access Control | `repositories.py` | All repo endpoints use `require_api_key` — SCANNER keys can delete repos |
| SEC-207 | High | Confirmed | A01 Access Control | `jira.py:83` | All JIRA mutations use `require_api_key` — SCANNER keys can close findings |
| SEC-208 | High | Confirmed | A03 Injection | `findings.py:431` | `assign_finding` accepts raw `dict` — no max_length, log injection via assignee |
| SEC-209 | High | Confirmed | A04 Design | `scans.py:97` | `/import-json` Content-Length-only guard bypassable via chunked transfer encoding |
| SEC-210 | High | Confirmed | LLM01 Prompt Inj | `ai_service.py:301` | `generate_alternatives()` missing `_PROMPT_INJECTION_RE` on `engineer_context` |
| SEC-211 | High | Confirmed | LLM01 Prompt Inj | `ai_service.py:350` | `stream_fix_generation()` missing `_PROMPT_INJECTION_RE` on `engineer_context` |
| SEC-212 | High | Confirmed | A03 XSS | `RepositoryDetailPage.tsx:492` | JIRA ticket URL rendered without `safeUrl()` |
| SEC-213 | Medium | Confirmed | A05 Misconfig | `main.py:693` | Session cookie `secure=False` by default — transmittable over HTTP |
| SEC-214 | Medium | Confirmed | A05 Misconfig | `main.py:736` | `/health/integrations` returns config detail + error text to any-scope key |
| SEC-215 | Medium | Confirmed | A04 Design | `limiter.py:22` | slowapi in-memory storage — rate limits reset on every container restart |
| SEC-216 | Medium | Confirmed | A06 Components | `requirements.txt:15` | `cryptography<44.0.0` excludes security patches in 44.x/45.x |
| SEC-217 | Medium | Likely | A10 SSRF | `config.py:104` | `EPSS_API_BASE_URL` operator-controlled with no allowlist |
| SEC-218 | Medium | Confirmed | A01 Access Control | `compliance.py:357` | `create_risk_acceptance` allows self-approval via `approved_by` in body |
| SEC-219 | Medium | Confirmed | A01 Access Control | `regression_alerts.py:65` | `acknowledge-all` uses `require_api_key` — any key silences all alerts |
| SEC-220 | Medium | Confirmed | A01 Access Control | `schemas/repository.py:85` | `webhook_secret` returned in `RepositoryResponse` — exposes HMAC signing key |
| SEC-221 | Medium | Confirmed | A04 Design | `findings.py:62` | LIKE wildcard abuse in `search` parameter — performance DoS |
| SEC-222 | Medium | Confirmed | A07 Rate Limit | `remediation.py:208` | `reject`, `dismiss`, and `list` endpoints have no rate limiting |
| SEC-223 | Medium | Confirmed | A04 Design | `sbom.py:66` | `SbomSubmitRequest` has no JSON depth check — JSON bomb window before parse |
| SEC-224 | Medium | Confirmed | A10 SSRF | `jira_service.py:341` | `_validate_jira_url()` allows `http://` — credentials over plaintext |
| SEC-225 | Medium | Confirmed | LLM10 Token Cost | `ai_service.py:320` | `generate_alternatives()` `num_alternatives` uncapped — cost amplification |
| SEC-226 | Medium | Confirmed | A03 Type Confusion | `base.py:94` | `map_severity()` calls `.lower()` without `isinstance` guard — affects all normalizers |
| SEC-227 | Medium | Confirmed | A03 Type Confusion | `gitleaks.py:44` | `', '.join(tags)` on scanner-supplied list without element type guard |
| SEC-228 | Medium | Confirmed | A03 Type Confusion | `snyk.py:113` | `_normalize_vuln()` joins `fixedIn` without `str()` coercion |
| SEC-229 | Medium | Confirmed | A05 Misconfig | `LoginPage.tsx:13` | Unvalidated open redirect via `location.state.from` after login |
| SEC-230 | Medium | Confirmed | A05 Misconfig | `frontend/Dockerfile:25` | Missing HSTS header in nginx config |
| SEC-231 | Low | Confirmed | A09 Logging | `audit_service.py:42` | Hardcoded weak HMAC key `b"nyx-audit-chain-default"` silently used in non-prod |
| SEC-232 | Low | Confirmed | A03 XSS | `reports.py:182` | Executive HTML report interpolates DB values without `html.escape()` — stored XSS |
| SEC-233 | Low | Confirmed | A04 Design | `config.py:86` | `REQUIRE_SUBMISSION_HMAC=False` default — scan payload integrity opt-in not opt-out |
| SEC-234 | Low | Confirmed | A04 Validation | `sla_policies.py:125` | PATCH endpoint skips validators from `SlaPolicyCreate` |
| SEC-235 | Low | Confirmed | A04 Validation | `schemas/finding.py:109` | `FindingSuppressRequest` has no `max_length` on `reason` or bounds on `expires_days` |
| SEC-236 | Low | Confirmed | A09 Logging | `main.py:755` | Internal exception messages (up to 100 chars) returned on `/health/integrations` |
| SEC-237 | Low | Confirmed | A08 Supply Chain | `backend/Dockerfile:1` | Floating base image tag `python:3.12-slim` — no digest pin |
| SEC-238 | Low | Confirmed | A03 Type Confusion | `trivy.py:88` | `CweIDs` passed raw without element string validation |
| SEC-239 | Low | Confirmed | A09 Logging | `ai_service.py:405` | Raw Claude API exception message streamed to client via SSE |
| SEC-240 | Low | Tentative | A03 Type Confusion | `semgrep.py:88` | `lines` field sliced without `isinstance(str)` guard |
| SEC-241 | Low | Confirmed | A06 Components | `frontend/package.json` | All deps use `^` ranges — no version pinning enforcement |
| SEC-242 | Low | Confirmed | A05 Misconfig | `nyx-scan-container.yml:60` | `github.event.inputs.image` passed to Trivy without format validation |
| SEC-243 | Low | Confirmed | A05 Misconfig | `.env.example:56` | `NYX_API_KEY` has guessable non-empty placeholder value |
| SEC-244 | Info | Confirmed | A04 Design | `config.py:69` | `API_KEY_MAX_LIFETIME_DAYS=0` — keys never expire by default |

---

## Findings (detail)

### SEC-201 — ImportError: `_get_fernet` silently disables at-rest encryption backfill

- **Severity:** Critical   **Confidence:** Confirmed
- **Category:** OWASP A02:2021 Cryptographic Failures · CWE-311
- **Location:** `backend/app/database.py:70`

**Evidence** (verbatim from source):
```python
70  from app.core.crypto import encrypt_secret, _get_fernet
```
```python
# crypto.py line 79 — the actual function name:
79  def _get_fernets():
```

- **Why it's a problem:** The SEC-006 fix renamed the internal function from `_get_fernet` (singular) to `_get_fernets` (plural) in `crypto.py`, but `database.py` was not updated. Every call to `_migrate_encrypt_raw_outputs()` raises an `ImportError` that is swallowed by the bare `except Exception: return` block, silently disabling the migration that re-encrypts raw scan output with the v2 key.
- **Impact / attack scenario:** `raw_output` for all scans ingested after the v2 crypto upgrade is stored unencrypted at rest, even when `NYX_SECRET_KEY` is configured. Operators have no visible indication the control is broken.
- **How to verify:** Run `python -c "from app.database import _migrate_encrypt_raw_outputs"` — it will raise `ImportError: cannot import name '_get_fernet' from 'app.core.crypto'`.
- **Remediation:** Fix the import in `database.py:70`: change `_get_fernet` → `_get_fernets` (or remove the private import and have the migration call `encrypt_secret` directly, since that's the only public API needed).
- **References:** OWASP A02:2021; CWE-311

---

### SEC-202 — Wrong ciphertext prefix check double-encrypts v2 tokens on every restart

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A02:2021 Cryptographic Failures · CWE-311
- **Location:** `backend/app/database.py:90`

**Evidence** (verbatim from source):
```python
90  if not raw or raw.startswith("gAAAAA"):
91      continue
```

- **Why it's a problem:** `encrypt_secret()` stores v2 tokens prefixed with `"v2:"` (e.g., `"v2:gAAAAA..."`). The migration guard checks for `"gAAAAA"` (bare Fernet v1 prefix) and would skip already-encrypted values — but a v2 ciphertext starts with `"v2:"`, not `"gAAAAA"`, so the guard fails and the ciphertext is passed to `encrypt_secret()` again, wrapping it in another layer of encryption on every subsequent application startup.
- **Impact / attack scenario:** After the second startup with `NYX_SECRET_KEY` set, all `raw_output` rows contain nested ciphertext that cannot be decrypted, permanently corrupting stored scan data.
- **How to verify:** Check `raw_output` rows in the DB after two restarts — values will begin `"v2:gAAAAA..."` (outer) wrapping `"v2:gAAAAA..."` (inner), producing garbage on decrypt.
- **Remediation:** Update the guard to also skip v2-prefixed tokens: `if not raw or raw.startswith("gAAAAA") or raw.startswith("v2:"):`.
- **References:** OWASP A02:2021; CWE-311

---

### SEC-203 — `rotate_secret_key` uses PBKDF2, mismatches HKDF — corrupts webhook secrets on rotation

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A02:2021 Cryptographic Failures · CWE-326
- **Location:** `backend/app/core/security.py:823-830`

**Evidence** (verbatim from source):
```python
823  new_key_bytes = _hashlib.pbkdf2_hmac(
824      "sha256",
825      new_secret_key.encode(),
826      b"nyx-fernet-salt",
827      100_000,
828      dklen=32,
829  )
830  new_fernet = Fernet(base64.urlsafe_b64encode(new_key_bytes))
```
```python
# crypto.py _derive_key_v2 (used at read time):
57  hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
58      salt=b"nyx-at-rest-kdf-v1", info=b"nyx-fernet-key")
```

- **Why it's a problem:** `rotate_secret_key` re-encrypts column values with a PBKDF2-derived key (salt `"nyx-fernet-salt"`, 100k iterations). But `EncryptedString.process_result_value` always decrypts using the HKDF-derived key (salt `"nyx-at-rest-kdf-v1"`, info `"nyx-fernet-key"`). For the same `new_secret_key` string, PBKDF2 and HKDF produce different bytes, so every decryption attempt post-rotation raises `InvalidToken`. The rotated values also lack the `"v2:"` prefix, so the v1 SHA-256 fallback is tried (also wrong), making the corruption permanent.
- **Impact / attack scenario:** After any key rotation (a standard security practice), all webhook secrets become permanently unreadable — GitHub webhook signature verification fails for every repository, disabling all automated scan triggers and breaking webhook integrity checks.
- **How to verify:** Perform a key rotation and then attempt to verify a GitHub webhook — the HMAC check will fail with `InvalidToken`.
- **Remediation:** Replace the PBKDF2 derivation in `rotate_secret_key` with `_derive_key_v2(new_secret_key)` from `crypto.py`, and store the result with the `"v2:"` prefix via `encrypt_secret()`. Import and reuse the shared crypto primitives instead of re-implementing KDF in-place.
- **References:** OWASP A02:2021; CWE-326

---

### SEC-204 — `/auth/session` lacks per-endpoint rate limit — 300 req/min brute-force window

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A07:2021 Identification and Authentication Failures · CWE-307
- **Location:** `backend/app/main.py:597-598`

**Evidence** (verbatim from source):
```python
597  @app.post("/auth/session", tags=["auth"])
598  async def create_session(request: Request, response: Response):
     # no @limiter.limit decorator
```

- **Why it's a problem:** The global slowapi default limit (300/minute) is the only protection on the highest-value authentication endpoint. Other sensitive endpoints explicitly set `@limiter.limit("5/minute")`. The in-memory lockout triggers only after 20 failures — 19 free attempts per IP before any lockout fires.
- **Impact / attack scenario:** An attacker rotating across IPs (or exploiting the proxy-bypass in SEC-205) can submit continuous API key guessing attempts at 300/minute per IP with only 19-attempt lockout windows.
- **How to verify:** Send >5 requests/minute to `/auth/session` with invalid keys — no 429 is returned until 300 within the minute.
- **Remediation:** Add `@limiter.limit("5/minute")` decorator to `create_session`. Ensure the function signature already has `request: Request` as first parameter (it does at line 598).
- **References:** OWASP A07:2021; CWE-307

---

### SEC-205 — `/auth/session` uses raw peer IP — lockout bypassed behind reverse proxy

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A07:2021 Identification and Authentication Failures · CWE-307
- **Location:** `backend/app/main.py:631`

**Evidence** (verbatim from source):
```python
631  ip = request.client.host if request.client else "unknown"
```
```python
# Correct pattern used in require_api_key (security.py):
301  ip = get_client_ip(request)
```

- **Why it's a problem:** `request.client.host` is the TCP peer address — the nginx/proxy IP in the standard Docker deployment. All session-creation requests from all users share the same "client" IP, meaning the lockout either (a) never triggers (if the proxy IP has no recorded failures) or (b) locks out every user simultaneously when one IP hits the threshold.
- **Impact / attack scenario:** Behind the default nginx reverse proxy (as configured in `docker-compose.yml`), the brute-force lockout on `/auth/session` is completely ineffective — an attacker can submit unlimited attempts without triggering lockout.
- **How to verify:** Deploy behind nginx, send 25 failed auth attempts from different IPs — none are locked out; all share the nginx container IP.
- **Remediation:** Change line 631: `ip = get_client_ip(request)` (already imported in this file's scope via `app.core.security`).
- **References:** OWASP A07:2021; CWE-307

---

### SEC-206 — All repository endpoints use `require_api_key` — SCANNER keys can delete repos

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-285
- **Location:** `backend/app/routers/repositories.py:25-324` (all endpoints)

**Evidence** (verbatim from source):
```python
# list (line 25):
_key: str = Depends(require_api_key),

# delete (line ~115):
_key: str = Depends(require_api_key),

# push-workflow (line ~215):
_key: str = Depends(require_api_key),
```

- **Why it's a problem:** Every endpoint in `repositories.py` — including `DELETE /{repo_id}`, `PATCH /{repo_id}`, `POST /{repo_id}/webhook`, `POST /{repo_id}/push-workflow`, and `POST /detect-scanners` — accepts any valid API key regardless of scope. A SCANNER-scoped key (intended only for CI/CD scan submission) can delete all registered repositories or push malicious workflow files.
- **Impact / attack scenario:** A compromised CI/CD scanner key (commonly embedded in GitHub Actions secrets) can delete all repositories, re-register webhooks pointing at attacker infrastructure, or push malicious `nyx-scan.yml` workflows to every registered repository.
- **How to verify:** Use a `scanner`-scoped API key to call `DELETE /api/v1/repositories/{any_id}` — it succeeds.
- **Remediation:** Apply `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` to all write/delete/mutation endpoints in `repositories.py`. Read endpoints can remain `require_api_key` or be scoped to `SCOPE_READONLY`.
- **References:** OWASP A01:2021; CWE-285

---

### SEC-207 — All JIRA mutations use `require_api_key` — SCANNER keys can close findings

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-285
- **Location:** `backend/app/routers/jira.py:83,175,235`

**Evidence** (verbatim from source):
```python
83   _key: str = Depends(require_api_key),   # create_ticket
175  _key: str = Depends(require_api_key),   # unlink_ticket
235  _key: str = Depends(require_api_key),   # bulk_create_tickets
```
```python
# sync_ticket transitions finding to FIXED (line ~158):
if (ticket.get("status") or "").lower() in done_statuses:
    finding.status = FindingStatus.FIXED.value
```

- **Why it's a problem:** Any valid API key — including SCANNER scope — can create, delete, and sync JIRA tickets. The `sync_ticket` endpoint changes a finding's status to `FIXED` based on the Jira response, giving a scanner key the ability to close security findings without analyst review.
- **Impact / attack scenario:** A leaked CI/CD key can mark critical security findings as FIXED by creating a Jira ticket, then calling sync with a status mapped to `done_statuses`, bypassing the remediation approval workflow.
- **Remediation:** Apply `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` to `create_ticket`, `unlink_ticket`, `sync_ticket`, and `bulk_create_tickets`. The `get_ticket` read endpoint can remain with lower scope.
- **References:** OWASP A01:2021; CWE-285

---

### SEC-208 — `assign_finding` accepts raw `dict` body — no max_length, log injection via assignee

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-20
- **Location:** `backend/app/routers/findings.py:431-459`

**Evidence** (verbatim from source):
```python
435      body: dict,          # raw dict, no Pydantic model
...
444      assignee = (body.get("assignee") or "").strip()
445      finding.assigned_to = assignee or None
```

- **Why it's a problem:** `body: dict` accepts arbitrary JSON without validation — no max_length on `assignee`, no character allowlist, no rejection of unexpected keys. Arbitrary-length strings are stored in `finding.assigned_to` and written into `AuditLog.metadata_json` (line 454), enabling log injection via newlines or JSON-breaking characters.
- **Impact / attack scenario:** An ANALYST-scoped user stores a 100 KB string in `assigned_to`; log injection via `\n` sequences breaks structured log parsing; downstream notification templates consuming `assigned_to` render injected content.
- **Remediation:** Replace `body: dict` with a typed Pydantic model: `class FindingAssignRequest(BaseModel): assignee: Optional[str] = Field(None, max_length=255, pattern=r'^[\w\s@._-]*$')`.
- **References:** OWASP A03:2021; CWE-20

---

### SEC-209 — `/import-json` Content-Length-only guard bypassable via chunked transfer encoding

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-400
- **Location:** `backend/app/routers/scans.py:97-100`

**Evidence** (verbatim from source):
```python
97   content_length = request.headers.get("content-length")
98   if content_length and int(content_length) > _MAX_IMPORT_BYTES:
99       raise HTTPException(status_code=413, detail="Payload too large (max 50 MB)")
100  body_bytes = await request.body()
```

- **Why it's a problem:** A `Transfer-Encoding: chunked` request omits `Content-Length`, bypassing the guard. `await request.body()` then buffers the entire body — unbounded — into memory before any size check applies. **Note:** `main.py`'s `body_size_limit_middleware` now provides a streaming backstop via the ASGI receive wrapper (SEC-105 fix), but the local guard in `scans.py` is still bypassable and should be hardened independently so the defence is not solely in middleware.
- **Impact / attack scenario:** A SCANNER or ANALYST key sends a chunked 500 MB deeply-nested JSON body; before the middleware's streaming check can abort it, `await request.body()` may already be buffering data — the middleware truncates the body to empty, causing a 422, but not before memory pressure is applied on large enough payloads.
- **Remediation:** Remove the `content_length` check and replace `await request.body()` with a streaming read that counts bytes: read up to `_MAX_IMPORT_BYTES + 1` bytes and reject if exceeded, consistent with the multipart endpoint pattern already used at line 164.
- **References:** OWASP A04:2021; CWE-400

---

### SEC-210 — `generate_alternatives()` missing `_PROMPT_INJECTION_RE` on `engineer_context`

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP LLM01:2025 Prompt Injection · CWE-77
- **Location:** `backend/app/services/ai_service.py:301`

**Evidence** (verbatim from source):
```python
301  safe_context = _CTRL_CHARS_RE.sub("", engineer_context)[:2000]
```
```python
# compare with generate_fix() at lines 189-190 (correct):
189  safe_context = _CTRL_CHARS_RE.sub("", engineer_context)
190  safe_context = _PROMPT_INJECTION_RE.sub("", safe_context)[:2000]
```

- **Why it's a problem:** `generate_alternatives()` strips control/bidi characters but does not apply `_PROMPT_INJECTION_RE`, which removes natural-language injection phrases like "ignore all previous instructions". An attacker supplying `engineer_context` to the alternatives endpoint can embed these phrases.
- **Impact / attack scenario:** Injection phrases reach the Claude prompt in the alternatives path, potentially manipulating output to produce a malicious diff or exfiltrate the system prompt.
- **Remediation:** Add `safe_context = _PROMPT_INJECTION_RE.sub("", safe_context)[:2000]` immediately after the `_CTRL_CHARS_RE` substitution at line 301. Apply the same fix to `stream_fix_generation()` (SEC-211).
- **References:** OWASP LLM01:2025; CWE-77

---

### SEC-211 — `stream_fix_generation()` missing `_PROMPT_INJECTION_RE` on `engineer_context`

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP LLM01:2025 Prompt Injection · CWE-77
- **Location:** `backend/app/services/ai_service.py:350`

**Evidence** (verbatim from source):
```python
350  safe_context = _CTRL_CHARS_RE.sub("", engineer_context)[:2000]
```

- **Why it's a problem:** Same gap as SEC-210 — the streaming generation path applies only control-character stripping, not the NLP phrase filter.
- **Impact / attack scenario:** Injection phrases in `engineer_context` reach Claude in streaming mode with no filter, potentially altering the generated patch.
- **Remediation:** Same as SEC-210: add `_PROMPT_INJECTION_RE` substitution after `_CTRL_CHARS_RE` before the length cap.
- **References:** OWASP LLM01:2025; CWE-77

---

### SEC-212 — JIRA ticket URL in `RepositoryDetailPage` rendered without `safeUrl()`

- **Severity:** High   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection / XSS · CWE-79
- **Location:** `frontend/src/pages/RepositoryDetailPage.tsx:492-498`

**Evidence** (verbatim from source):
```tsx
492  <a
493    href={t.jira_issue_url}
494    target="_blank"
495    rel="noopener noreferrer"
```

- **Why it's a problem:** `t.jira_issue_url` from the API response is placed directly into `href` with no call to `safeUrl()`. The SEC-004/SEC-102 fixes applied `safeUrl()` to `FindingDetailPage.tsx` (line 89) and `RemediationPage.tsx` (line 280), but this instance in the `JiraTab` component was missed.
- **Impact / attack scenario:** A Jira link with a `javascript:` scheme returned from the API executes arbitrary JavaScript in the user's browser when clicked on the repository detail page.
- **Remediation:** Change line 493 to `href={safeUrl(t.jira_issue_url)}` and add `import { safeUrl } from '../utils/url'` at the top of the file.
- **References:** OWASP A03:2021; CWE-79

---

### SEC-213 — Session cookie `secure=False` by default

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A05:2021 Security Misconfiguration · CWE-614
- **Location:** `backend/app/main.py:693`

**Evidence** (verbatim from source):
```python
693  secure=settings.HTTPS_ONLY,   # False by default (config.py:34)
```

- **Why it's a problem:** The `Secure` cookie attribute prevents browser transmission over HTTP. With `HTTPS_ONLY=False` (the default), the session cookie can be sent over HTTP connections — even when the Nyx instance is behind TLS termination.
- **Impact / attack scenario:** An on-path attacker (MITM, protocol downgrade) can steal the 7-day session cookie.
- **Remediation:** Default `HTTPS_ONLY` to `True` in `config.py`, or add a separate `SESSION_COOKIE_SECURE: bool = True` setting. Document the HTTP-only mode explicitly for local development.
- **References:** OWASP A05:2021; CWE-614

---

### SEC-214 — `/health/integrations` returns config detail to any-scope key

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A05:2021 Security Misconfiguration · CWE-200
- **Location:** `backend/app/main.py:736-737`

**Evidence** (verbatim from source):
```python
736  @app.get("/health/integrations", tags=["system"])
737  async def integration_health(_key: str = Depends(require_api_key)):
     # returns model name, GitHub login, Jira display name, DB error details
```

- **Why it's a problem:** Any valid key (SCANNER, READONLY) can call this endpoint and receive the Anthropic model in use, the authenticated GitHub identity, the Jira display name, and up to 100 characters of exception detail from database/integration errors.
- **Remediation:** Change the dependency to `require_scope(SCOPE_ADMIN)`. Log detailed errors server-side; return only generic `"status": "error"` to callers.
- **References:** OWASP A05:2021; CWE-200

---

### SEC-215 — slowapi uses in-memory storage — rate limits reset on every restart

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-770
- **Location:** `backend/app/core/limiter.py:22`

**Evidence** (verbatim from source):
```python
22  limiter = Limiter(key_func=_rate_limit_key, default_limits=["300/minute"])
    # no storage= parameter → MemoryStorage (in-process dict)
```

- **Why it's a problem:** All rate limit counters live in process memory. A container restart (OOM kill, deploy) resets them to zero. An attacker can deliberately trigger restarts to reset their counter between bursts.
- **Remediation:** Add `storage_uri="redis://redis:6379"` (or use the Postgres DB via `slowapi`'s storage backends) to persist counters across restarts. At minimum, document the limitation.
- **References:** OWASP A04:2021; CWE-770

---

### SEC-216 — `cryptography<44.0.0` excludes security patches

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A06:2021 Vulnerable & Outdated Components · CWE-1104
- **Location:** `backend/requirements.txt:15`

**Evidence** (verbatim from source):
```
cryptography>=42.0.0,<44.0.0
```

- **Why it's a problem:** The `<44.0.0` upper bound locks the package to a range known to include CVEs fixed in the 44.x series. The `cryptography` library is the foundation for all Fernet/HKDF operations in Nyx.
- **Remediation:** Remove the upper bound or raise it: `cryptography>=44.0.0`.
- **References:** OWASP A06:2021; CWE-1104

---

### SEC-217 — `EPSS_API_BASE_URL` operator-controlled with no allowlist — SSRF

- **Severity:** Medium   **Likelihood:** Likely
- **Category:** OWASP A10:2021 SSRF · CWE-918
- **Location:** `backend/app/config.py:104` + `backend/app/services/prioritization_service.py:84-86`

**Evidence** (verbatim from source):
```python
# config.py:
104  EPSS_API_BASE_URL: str = "https://api.first.org/data/v1/epss"

# prioritization_service.py:
84   async with httpx.AsyncClient(timeout=5.0) as client:
85       resp = await client.get(settings.EPSS_API_BASE_URL, params={"cve": cve_id})
```

- **Why it's a problem:** `EPSS_API_BASE_URL` is read from the environment with no validation. An attacker with partial environment variable control (misconfigured secrets manager, CI/CD injection) can redirect this to internal metadata services or internal APIs.
- **Remediation:** Validate at startup that `EPSS_API_BASE_URL` is a known-safe HTTPS URL (allowlist to `api.first.org` or validate scheme + hostname against a config allowlist).
- **References:** OWASP A10:2021; CWE-918

---

### SEC-218 — `create_risk_acceptance` allows self-approval — separation of duties bypass

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-285
- **Location:** `backend/app/routers/compliance.py:357-408`

**Evidence** (verbatim from source):
```python
approved_by = body.get("approved_by", "").strip() or None
approval_status = "approved" if approved_by else "pending_approval"
if approved_by and finding.status in ("OPEN", "IN_REMEDIATION"):
    finding.status = "ACCEPTED_RISK"
```

- **Why it's a problem:** A single ANALYST call can set `approved_by` to their own identity in the request body, creating an immediately-approved risk acceptance that transitions a CRITICAL finding to `ACCEPTED_RISK` in one step — bypassing the separate `/approve` endpoint that exists for second-party review.
- **Remediation:** Remove `approved_by` from the create body. Set `approved_by=None` and `approval_status="pending_approval"` always at creation time; require a separate call to the `/approve` endpoint by a different authenticated principal.
- **References:** OWASP A01:2021; CWE-285

---

### SEC-219 — `acknowledge-all` uses `require_api_key` — any key silences all regression alerts

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-285
- **Location:** `backend/app/routers/regression_alerts.py:65-83`

**Evidence** (verbatim from source):
```python
69  _key: str = Depends(require_api_key),
...
# Bulk-acknowledges every unacknowledged alert:
for alert in result.scalars().all():
    alert.acknowledged_at = now
```

- **Why it's a problem:** A SCANNER-scoped key can silently dismiss all pending regression alerts after each scan run, defeating regression detection entirely.
- **Remediation:** Change to `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)`.
- **References:** OWASP A01:2021; CWE-285

---

### SEC-220 — `webhook_secret` returned in `RepositoryResponse` — exposes HMAC signing key

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-200
- **Location:** `backend/app/schemas/repository.py:85`

**Evidence** (verbatim from source):
```python
85  webhook_secret: Optional[str] = None
```

- **Why it's a problem:** `webhook_secret` is the HMAC key used to verify GitHub webhook payloads. It is returned in every `GET /repositories`, `POST /repositories`, and `PATCH /repositories/{id}` response. Any key holder (including READONLY scope) can harvest all per-repository webhook signing secrets.
- **Impact / attack scenario:** An attacker with any API key obtains all webhook secrets from `GET /repositories`, then forges GitHub push-event payloads that pass HMAC verification, triggering arbitrary scan imports.
- **Remediation:** Exclude `webhook_secret` from `RepositoryResponse` (use `exclude={"webhook_secret"}` in the ORM→schema mapping, or add `model_config = ConfigDict(exclude={"webhook_secret"})`). Provide a separate admin-scoped endpoint to rotate the secret if needed.
- **References:** OWASP A01:2021; CWE-200

---

### SEC-221 — LIKE wildcard abuse in `search` parameter — performance DoS

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-400
- **Location:** `backend/app/routers/findings.py:62-65`

**Evidence** (verbatim from source):
```python
62  if search:
63      like = f"%{search}%"
64      stmt = stmt.where(or_(
65          Finding.title.ilike(like),
```

- **Why it's a problem:** SQL LIKE metacharacters `%` and `_` in `search` are not escaped before being embedded in the pattern. A pattern like `%_%_%_%_%_` (200 chars of `%_` pairs) forces exponential backtracking across all four ORed `ilike()` columns.
- **Remediation:** Escape LIKE metacharacters before interpolation: `like = f"%{search.replace('%','\\%').replace('_','\\_')}%"` and pass the escape character to the DB engine, or use full-text search instead of LIKE for the `search` param.
- **References:** OWASP A04:2021; CWE-400

---

### SEC-222 — `reject`, `dismiss`, and `list` remediation endpoints have no rate limiting

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A07:2021 Identification and Authentication Failures · CWE-770
- **Location:** `backend/app/routers/remediation.py:208,266,296`

**Evidence** (verbatim from source):
```python
208  @router.get("/{remediation_id}", response_model=RemediationResponse)
     # no @limiter.limit
266  @router.post("/{remediation_id}/reject", ...)
     # no @limiter.limit
296  @router.delete("/{remediation_id}", ...)
     # no @limiter.limit
```

- **Remediation:** Add `@limiter.limit("20/minute")` to `list_remediations` and `@limiter.limit("10/minute")` to `reject` and `dismiss`, matching the pattern on `approve`.
- **References:** OWASP A07:2021; CWE-770

---

### SEC-223 — `SbomSubmitRequest` has no JSON depth check — JSON bomb window before parse

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-400
- **Location:** `backend/app/routers/sbom.py:66-69`

**Evidence** (verbatim from source):
```python
class SbomSubmitRequest(BaseModel):
    git_ref: Optional[str] = None
    sbom: Dict[str, Any]   # no depth/size validation before Pydantic parse
```

- **Why it's a problem:** Unlike the scan import endpoint which calls `_check_json_depth()` before processing, `SbomSubmitRequest` fully deserializes a potentially-nested `sbom` dict via Pydantic before any component-count cap is applied.
- **Remediation:** Add a JSON depth/nesting validator to `SbomSubmitRequest` mirroring the `_check_json_depth` pattern from `scans.py`.
- **References:** OWASP A04:2021; CWE-400

---

### SEC-224 — `_validate_jira_url()` allows `http://` — credentials over plaintext

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A10:2021 SSRF / A02:2021 Crypto · CWE-319
- **Location:** `backend/app/services/jira_service.py:341`

**Evidence** (verbatim from source):
```python
341  if parsed.scheme not in ("http", "https"):
342      raise ValueError(...)
```

- **Why it's a problem:** Jira API calls include Basic Auth (email + API token). An `http://` JIRA_URL transmits these credentials in cleartext. This is inconsistent with `notification_service.py` which was hardened to `https`-only in SEC-101.
- **Remediation:** Change to `if parsed.scheme != "https":`.
- **References:** OWASP A02:2021; CWE-319

---

### SEC-225 — `generate_alternatives()` `num_alternatives` uncapped — cost amplification

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP LLM10:2025 Unbounded Consumption · CWE-770
- **Location:** `backend/app/services/ai_service.py:320-328`

**Evidence** (verbatim from source):
```python
320  response = await client.messages.create(
321      model=settings.ANTHROPIC_MODEL,
322      max_tokens=settings.AI_MAX_OUTPUT_TOKENS,
```

- **Why it's a problem:** `num_alternatives` has no upper bound enforced in the function. A caller can request 20+ alternatives, causing a single call to consume the full `AI_MAX_OUTPUT_TOKENS` budget per alternative.
- **Remediation:** Add `num_alternatives: int = Field(default=3, ge=1, le=5)` in the Pydantic request schema, or add `num_alternatives = min(max(num_alternatives, 1), 5)` at the function entry.
- **References:** OWASP LLM10:2025; CWE-770

---

### SEC-226 — `map_severity()` calls `.lower()` without `isinstance` guard — affects all normalizers

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-20
- **Location:** `backend/app/services/normalization/base.py:94`

**Evidence** (verbatim from source):
```python
94  return mapping.get(raw.lower().strip(), default)
```

- **Why it's a problem:** Called by every normalizer (bandit, checkov, hadolint, trivy, grype, semgrep, zap, dependabot, code_scanning) with scanner-supplied data. A non-string severity value (integer, None, dict) raises `AttributeError`, causing the entire finding to be silently dropped via the bare `except` in each normalizer loop.
- **Remediation:** Add a guard: `if not isinstance(raw, str): return default` before calling `.lower()`.
- **References:** OWASP A03:2021; CWE-20

---

### SEC-227 — `', '.join(tags)` on scanner-supplied list without element type guard

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-20
- **Location:** `backend/app/services/normalization/gitleaks.py:44`

**Evidence** (verbatim from source):
```python
44  description_parts.append(f"Tags: {', '.join(tags)}")
```

- **Why it's a problem:** `tags` is taken directly from scanner JSON. If any element is non-string, `str.join()` raises `TypeError`, silently dropping the finding.
- **Remediation:** `', '.join(str(t) for t in tags)`.
- **References:** OWASP A03:2021; CWE-20

---

### SEC-228 — `_normalize_vuln()` in `snyk.py` joins `fixedIn` without `str()` coercion

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-20
- **Location:** `backend/app/services/normalization/snyk.py:113`

**Evidence** (verbatim from source):
```python
113  fix_info = v.get("fixedIn", [])
114  fix_text = f"Upgrade to {', '.join(fix_info)}" if fix_info else ""
```

- **Why it's a problem:** SEC-109 fixed this in `_normalize_webhook_issue()` but the identical pattern in `_normalize_vuln()` was missed. Non-string elements in `fixedIn` raise `TypeError`.
- **Remediation:** `', '.join(str(v) for v in fix_info)`.
- **References:** OWASP A03:2021; CWE-20

---

### SEC-229 — Unvalidated open redirect via `location.state.from` after login

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A05:2021 Security Misconfiguration · CWE-601
- **Location:** `frontend/src/pages/LoginPage.tsx:13`

**Evidence** (verbatim from source):
```typescript
13  const redirectTo = (location.state as { from?: string } | null)?.from || '/'
...
    navigate(redirectTo, { replace: true })
```

- **Why it's a problem:** The post-login redirect target comes from `location.state`, which is writable JavaScript state. A crafted link or script can set `from` to `//evil.com` — react-router-dom v6 passes such strings to the history API, which browsers treat as protocol-relative URLs.
- **Remediation:** Validate that `redirectTo` is a same-origin relative path before navigating: `const safe = redirectTo?.startsWith('/') && !redirectTo.startsWith('//') ? redirectTo : '/'`.
- **References:** OWASP A05:2021; CWE-601

---

### SEC-230 — Missing HSTS header in frontend nginx config

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A05:2021 Security Misconfiguration · CWE-311
- **Location:** `frontend/Dockerfile:25-29`

**Evidence** (verbatim from source):
```nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-XSS-Protection "0" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
# no Strict-Transport-Security header
```

- **Why it's a problem:** Without HSTS, browsers do not enforce HTTPS on subsequent visits after a cache expiry or first visit, leaving the door open for SSL-stripping attacks.
- **Remediation:** Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` inside the `server` block (conditionally on whether TLS is configured).
- **References:** OWASP A05:2021; CWE-311

---

### SEC-231 — Hardcoded weak HMAC key silently used in non-production

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A09:2021 Security Logging Failures · CWE-321
- **Location:** `backend/app/services/audit_service.py:42-46`

**Evidence** (verbatim from source):
```python
42  logger.warning("NYX_SECRET_KEY not set — audit HMAC chain uses a weak default key.")
43  return b"nyx-audit-chain-default"
```

- **Why it's a problem:** Non-production environments (dev, staging) silently use a well-known key, making audit chain integrity forgeable. Compliance evidence from these environments cannot be trusted.
- **Remediation:** Either refuse to start (like production) or generate and warn about a per-instance random key rather than using a hardcoded string.
- **References:** OWASP A09:2021; CWE-321

---

### SEC-232 — Executive HTML report interpolates DB values without escaping — stored XSS

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 XSS · CWE-79
- **Location:** `backend/app/routers/reports.py:182-195`

**Evidence** (verbatim from source):
```python
182  vuln_html = "".join(
183      f"<tr><td>{v.title}</td><td>{v.scanner}</td><td><code>{v.rule_id}</code></td>..."
184      for v in top_vulns
185  )
```

- **Why it's a problem:** `finding.title`, `scanner`, `rule_id`, and `repo.github_full_name` are interpolated directly into HTML without `html.escape()`. Scanner output containing HTML/JS in these fields — ingested via `/import-json` — renders as active markup in the generated report.
- **Remediation:** Wrap all DB values with `html.escape()`: `f"<tr><td>{html.escape(v.title)}</td>..."`. Import `html` from stdlib.
- **References:** OWASP A03:2021; CWE-79

---

### SEC-233 — `REQUIRE_SUBMISSION_HMAC=False` default — scan integrity opt-in not opt-out

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-345
- **Location:** `backend/app/config.py:86`

**Evidence** (verbatim from source):
```python
86  REQUIRE_SUBMISSION_HMAC: bool = False
```

- **Why it's a problem:** By default, any authenticated scanner key can submit forged scan results without an HMAC header. Scan data integrity is opt-in, meaning most deployments run without it.
- **Remediation:** Consider changing the default to `True` and documenting how to configure the CI/CD workflows to include the HMAC header (they already do in the provided workflow templates).
- **References:** OWASP A04:2021; CWE-345

---

### SEC-234 — SLA policy PATCH endpoint skips create-time validators

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-20
- **Location:** `backend/app/routers/sla_policies.py:125-145`

**Evidence** (verbatim from source):
```python
class SlaPolicyUpdate(BaseModel):
    severity: Optional[str] = None    # no @field_validator
    max_days: Optional[int] = None    # no range check
    escalation_action: Optional[str] = None
```

- **Remediation:** Add the same `@field_validator` constraints from `SlaPolicyCreate` to `SlaPolicyUpdate`, or use a shared validator mixin.
- **References:** OWASP A04:2021; CWE-20

---

### SEC-235 — `FindingSuppressRequest` lacks `max_length` and `expires_days` bounds

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-20
- **Location:** `backend/app/schemas/finding.py:109-112`

**Evidence** (verbatim from source):
```python
class FindingSuppressRequest(BaseModel):
    reason: str
    expires_days: Optional[int] = None
```

- **Remediation:** `reason: str = Field(max_length=1000)`, `expires_days: Optional[int] = Field(None, ge=1, le=3650)`.
- **References:** OWASP A04:2021; CWE-20

---

### SEC-236 — Internal exception messages returned to callers on `/health/integrations`

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A09:2021 Security Logging Failures · CWE-209
- **Location:** `backend/app/main.py:755`

**Evidence** (verbatim from source):
```python
755  results["database"] = {"status": "error", "detail": str(e)[:100]}
```

- **Remediation:** Log `str(e)` at `logger.exception()` level, yield only `{"status": "error"}` to callers.
- **References:** OWASP A09:2021; CWE-209

---

### SEC-237 — Floating base image tag `python:3.12-slim` — no digest pin

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A08:2021 Software & Data Integrity Failures · CWE-1357
- **Location:** `backend/Dockerfile:1`

**Evidence** (verbatim from source):
```dockerfile
FROM python:3.12-slim
```

- **Remediation:** Pin to a specific digest: `FROM python:3.12-slim@sha256:<current-digest>`. Use `docker pull python:3.12-slim` then `docker inspect --format='{{index .RepoDigests 0}}'` to obtain the current digest.
- **References:** OWASP A08:2021; CWE-1357

---

### SEC-238 — `CweIDs` from Trivy passed raw without string validation

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-20
- **Location:** `backend/app/services/normalization/trivy.py:88`

**Evidence** (verbatim from source):
```python
88  cwe_ids=v.get("CweIDs", []) or [],
```

- **Remediation:** `cwe_ids=[str(c) for c in (v.get("CweIDs") or [])]`
- **References:** OWASP A03:2021; CWE-20

---

### SEC-239 — Raw Claude API exception streamed to client via SSE

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A09:2021 Security Logging Failures · CWE-209
- **Location:** `backend/app/services/ai_service.py:404-405`

**Evidence** (verbatim from source):
```python
404  except Exception as e:
405      yield f"data: {_json.dumps({'type': 'error', 'message': str(e)})}\n\n"
```

- **Remediation:** Log `str(e)` at `logger.exception()` level, yield only `{"type": "error", "message": "AI generation failed — see server logs"}`.
- **References:** OWASP A09:2021; CWE-209

---

### SEC-240 — `lines` field in Semgrep normalizer sliced without type guard

- **Severity:** Low   **Confidence:** Tentative
- **Category:** OWASP A03:2021 Injection · CWE-20
- **Location:** `backend/app/services/normalization/semgrep.py:88`

**Evidence** (verbatim from source):
```python
88  code_snippet=code_snippet[:2000] if code_snippet else None,
```

- **Why it's a problem (tentative):** If the Semgrep JSON returns `"lines"` as a list rather than a string, `[:2000]` returns a truncated list, not a string — causing a downstream ORM type error. Needs human verification of Semgrep's actual output schema.
- **Remediation:** `code_snippet = code_snippet if isinstance(code_snippet, str) else (str(code_snippet) if code_snippet else None)`.
- **References:** OWASP A03:2021; CWE-20

---

### SEC-241 — Frontend deps use `^` ranges — no version pinning enforcement

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A06:2021 Vulnerable & Outdated Components · CWE-1104
- **Location:** `frontend/package.json`

**Evidence** (verbatim from source):
```json
"dompurify": "^3.1.6",
"axios": "^1.7.2",
```

- **Remediation:** Pin exact versions in `package.json` and rely on Dependabot for controlled upgrades. At minimum, lock DOMPurify since it is the XSS sanitization boundary.
- **References:** OWASP A06:2021; CWE-1104

---

### SEC-242 — `github.event.inputs.image` passed to Trivy without format validation

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A05:2021 Security Misconfiguration
- **Location:** `.github/workflows/nyx-scan-container.yml:60`

**Evidence** (verbatim from source):
```yaml
60  SCAN_IMAGE: ${{ vars.DOCKER_IMAGE || github.event.inputs.image || 'nyx-scan-target:ci' }}
```

- **Why it's a problem:** Requires `workflow_dispatch` permissions to exploit (low likelihood), but the image name is unvalidated — a malformed input could produce unexpected behavior in Trivy's argument handling.
- **Remediation:** Add a validation step: `echo "$SCAN_IMAGE" | grep -E '^[a-zA-Z0-9/._:-]+$' || { echo "::error::Invalid SCAN_IMAGE value"; exit 1; }`.
- **References:** OWASP A05:2021

---

### SEC-243 — `.env.example` `NYX_API_KEY` has guessable non-empty placeholder

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A05:2021 Security Misconfiguration · CWE-1188
- **Location:** `.env.example:56`

**Evidence** (verbatim from source):
```
NYX_API_KEY=nyx-your-secret-key-here
```

- **Remediation:** Replace with an empty value or a clearly-invalid placeholder like `NYX_API_KEY=CHANGEME_generate_with_openssl_rand_hex_32`.
- **References:** OWASP A05:2021; CWE-1188

---

### SEC-244 — `API_KEY_MAX_LIFETIME_DAYS=0` — keys never expire by default

- **Severity:** Info   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-613
- **Location:** `backend/app/config.py:69`

**Evidence** (verbatim from source):
```python
69  API_KEY_MAX_LIFETIME_DAYS: int = 0
```

- **Remediation:** Document the setting prominently; consider defaulting to `365` with a startup warning when `0` is set in non-dev environments.
- **References:** OWASP A04:2021; CWE-613

---

## Verified safe / investigated (not findings)

| Location | What was checked | Why it's OK |
|----------|-----------------|-------------|
| `crypto.py:41-94` | HKDF-SHA256 key derivation, v2: prefix | SEC-006 fix confirmed correct — HKDF with domain-separating salt/info, v2: prefix unambiguous |
| `limiter.py:1-30` | Rate limiter key function | SEC-007 fix confirmed — `get_client_ip()` called correctly |
| `scan_worker.py:51-70` | `_sanitize_path()` traversal check | SEC-103 fix confirmed — `posixpath.normpath` + `startswith("..")` rejection |
| `main.py:521-538` | Body size middleware | SEC-105 fix confirmed — ASGI receive wrapper enforces limit on actual bytes |
| `MarkdownContent.tsx:6-28` | XSS sanitization | SEC-001 fix confirmed — DOMPurify.sanitize() in use, regex sanitizer removed |
| `FindingDetailPage.tsx:16,89,343,502` | safeUrl on href attributes | SEC-004 fix confirmed — imported from shared util, applied to all API-sourced URLs |
| `RemediationPage.tsx:9,260,280` | safeUrl on href attributes | SEC-102 fix confirmed — pr_url and jira_issue_url both wrapped |
| `findings.py:76-83` | Rate limit on generate_claude_prompt | SEC-107 fix confirmed — `@limiter.limit("5/minute")` + `request: Request` present |
| `findings.py:264-271` | Scope on suppress_finding | SEC-110 fix confirmed — `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` (no string literal) |
| `remediation.py:232-234` | TOCTOU lock on approve | SEC-104 fix confirmed — `.with_for_update()` present |
| `repositories.py:33-35` | Rate limit on add_repository | SEC-106 fix confirmed — `@limiter.limit("5/minute")` + `request: Request` present |
| `notification_service.py:35` | SSRF scheme check | SEC-101 fix confirmed — `scheme != "https"` (http rejected) |
| `webhooks.py:84-85` | Signature verification | SEC-005 fix confirmed — direct `await verify_github_signature(...)`, no dead try-except |
| `nyx-scan.yml` all report steps | NYX_REPO_ID shell injection | SEC-108 fix confirmed — all 7 steps use env: + `$NYX_REPO_ID` |
| `nyx-scan-gitleaks.yml` | Gitleaks binary checksum | SEC-003 fix confirmed — sha256sum --check --status before extraction |
| `semgrep-results.json` `missing-user` at `backend/Dockerfile:20` | False positive | `USER nyx` correctly appears at line 32 after the RUN layer |
| `backend/tests/conftest.py` | Hardcoded test API keys | Intentional test values (`nyx-test-bootstrap-key`, `"a"*64`) — not real secrets |
| `ai_service.py:189-190` | `generate_fix()` prompt injection filter | Both `_CTRL_CHARS_RE` and `_PROMPT_INJECTION_RE` applied correctly — only `generate_alternatives` and `stream_fix_generation` are missing the second filter |

---

## Coverage manifest

- **Reviewed:** ~175 source files across `backend/app/` (core, routers, services, normalization, workers, models, schemas), `frontend/src/` (pages, components, api, hooks, utils), `.github/workflows/`, `Dockerfiles`, `docker-compose*.yml`, `pyproject.toml`, `requirements.txt`, `package.json`, `.env.example`, `SECURITY.md`, `.gitleaks.toml`.
- **Skipped:** `node_modules/` (deps/build artifacts), `dist/`, `build/`, `__pycache__/`, `.git/`, `wiki/` (documentation, no executable code), `semgrep-results.json` (scanner output, not source code — reviewed for false positives only), `frontend/package-lock.json` (lockfile, reviewed package.json for versions instead).
- **Not reached / needs follow-up:**
  - `backend/scripts/seed_demo_data.py` and `backend/tests/` — test/seed code; reviewed for hardcoded secrets, none found beyond known test fixtures.
  - `frontend/src/pages/SchedulesPage.tsx`, `SlaPoliciesPage.tsx`, `SettingsPage.tsx` — UI pages with no direct API URL rendering; not individually deep-audited but the safeUrl pattern is only needed where API URLs are rendered in `href` (not present in these pages).
  - No `pip-audit` or `npm audit` was run (tools not available in environment) — dependency versions were read from manifests and cross-referenced manually.
