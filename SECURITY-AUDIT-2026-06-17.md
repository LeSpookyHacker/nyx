# Security Audit — Nyx — 2026-06-17 (Pass 5)

## Executive summary

- **Scope:** Full repo at `main` (commit `13efe53`). ~218 source files reviewed: backend Python/FastAPI (`backend/`), frontend React/TypeScript (`frontend/`), Docker Compose infrastructure, GitHub Actions workflows, dependency manifests.
- **New findings this pass:** Critical **0** · High **0** · Medium **0** · Low **3** · Info **0** = **3 new**
- **Deferred open (carried from previous passes):** Medium **1** · Low **2** · Info **1** = **4 still-open** (SEC-215, SEC-237, SEC-241, SEC-244)
- **Pass-4 remediation status:** All 36 findings (SEC-301–SEC-336) confirmed fixed in commit `13efe53`.
- **Top risks (new findings):**
  1. `approve_remediation` has no rate limit while every peer mutation endpoint does — allows unbounded GitHub API calls per analyst/admin key.
  2. `bulk_create_tickets` has no rate limit and no finding-count cap — one request can trigger N synchronous Jira API calls across all open findings.
  3. SBOM single-alert `acknowledge_alert` accepts any API key scope; inconsistent with `acknowledge-all` (analyst/admin only) and the scope pattern established for regression alerts.
- **Overall posture:** The codebase has absorbed four rounds of systematic remediation. The authentication stack, crypto primitives, prompt-injection defences, SQL injection guards, and SSRF controls are sound. The three new findings are narrowly-scoped rate-limiting and privilege-boundary omissions rather than new vulnerability classes. No critical or high-severity issues exist in the current codebase.

---

## Pass-4 remediation verification (SEC-301–SEC-336)

All 36 Pass-4 findings confirmed present and fixed in commit `13efe53`:

| ID | Location confirmed | Fix confirmed |
|----|--------------------|---------------|
| SEC-301 | `main.py:324` | `_compute_key_hashes(settings.NYX_API_KEY)[0]` — HMAC-SHA256 path used |
| SEC-302 | `main.py:711` | `@limiter.limit("20/minute")` on `/auth/logout` |
| SEC-303 | `main.py:579` | `"max-age=31536000; includeSubDomains; preload"` |
| SEC-304 | `main.py:325–338` | `_bootstrap_expires` computed from `API_KEY_MAX_LIFETIME_DAYS`; passed to `ApiKey(expires_at=...)` |
| SEC-305 | `main.py:659` | `logger.debug(..., type(db_exc).__name__)` — exception message excluded |
| SEC-306 | `backend/Dockerfile:35` | `HEALTHCHECK --interval=30s --timeout=5s ...` |
| SEC-307 | `ai_service.py:426–427` | `_CTRL_CHARS_RE.sub("", content)` + `_PROMPT_INJECTION_RE.sub("", content)` |
| SEC-308 | `ai_service.py:589` | `diff = _CTRL_CHARS_RE.sub("", diff)` |
| SEC-309 | `audit_service.py:21–24` | `_FALLBACK_HMAC_KEY: bytes = _secrets.token_bytes(32)` — module-level constant |
| SEC-310 | `prioritization_service.py:89–97` | HTTPS scheme check + `ip_address.is_private/is_loopback/is_link_local` guard |
| SEC-311 | `ai_service.py:420` | `list(test_file_contents.items())[:5]` — capped at 5 |
| SEC-312 | `jira_service.py:310` | Generic message returned, not raw exception string |
| SEC-313 | `normalization/checkov.py` | `isinstance` guard added |
| SEC-314 | `normalization/*.py` | Silent `except: continue` blocks replaced with logged exceptions |
| SEC-315 | `compliance.py:25–27` | `CreateFrameworkRequest` typed Pydantic model with `max_length` on slug/name/description |
| SEC-316 | `compliance.py:31–35` | `CreateControlRequest` with `max_length=50` on `cwe_ids`, `max_length=20` on `owasp_categories` |
| SEC-317 | `compliance.py:55–59` | `UpdateControlRequest` with same constraints as SEC-316 |
| SEC-318 | `compliance.py:85` | `expires_in_days: int = Field(180, ge=0, le=730)` — 2-year cap |
| SEC-319 | `remediation.py:38` | `BulkRemediationRequest.finding_ids` has `max_length=20`; UUID validation on elements |
| SEC-320 | `remediation.py:54` | `engineer_context: Optional[str] = Field(None, max_length=2000)` |
| SEC-321 | `compliance.py:82–87` | `RiskAcceptanceCreate` typed model replaces `body: dict` |
| SEC-322 | `audit.py:25–26` | `_escape_like()` escapes `%`, `_`, `\` before LIKE interpolation |
| SEC-323 | `sla_policies.py:125,159,181` | `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` with `# SEC-323` comments |
| SEC-324 | `schedules.py:106,134,168,187` | `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` with `# SEC-324` comments |
| SEC-325 | `sbom.py:39,391` | `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` on generate + acknowledge-all |
| SEC-326 | `saved_filters.py:78,104` | `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` with `# SEC-326` comments |
| SEC-327 | `schedules.py:40–44` | `interval_hours` validator: `1 ≤ v ≤ 8760` |
| SEC-328 | `reports.py:241–244` | `_html.escape(row.scanner)`, `_html.escape(row.category or "—")`, `_html.escape(row.severity)` |
| SEC-329 | `schemas/finding.py:116` | `notes: str = Field(..., max_length=10000)` on `FindingNoteUpdate` |
| SEC-330 | `schemas/remediation.py:26,32` | `engineer_notes` has `max_length=5000` on both `RemediationApprove` and `RemediationReject` |
| SEC-331 | `regression_alerts.py:50` | `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` with `# SEC-331` |
| SEC-332 | `RemediationPage.tsx:62,260` | `href={safeUrl(rem.pr_url)}` |
| SEC-333 | `MarkdownContent.tsx:142` | `href={safeUrl(href) ?? "#"}` in markdown `<a>` renderer |
| SEC-334 | `frontend/package.json:27` | `"dompurify": "3.1.6"` — exact pin, no `^` |
| SEC-335 | `frontend/Dockerfile:6` | `RUN npm ci` |
| SEC-336 | `frontend/src/pages/AuditPage.tsx` | Audit endpoint requires `SCOPE_ADMIN`; metadata display is text-only React JSX (no HTML sink) |

---

## Findings index

| ID | Severity | Confidence | Category | Location | Title |
|----|----------|------------|----------|----------|-------|
| SEC-401 | Low | Confirmed | A07:2021 · CWE-307 | `backend/app/routers/remediation.py:248` | `approve_remediation` missing rate limit |
| SEC-402 | Low | Confirmed | A04:2021 · CWE-770 | `backend/app/routers/jira.py:229` | `bulk_create_tickets` has no rate limit or finding-count cap |
| SEC-403 | Low | Confirmed | A01:2021 · CWE-285 | `backend/app/routers/sbom.py:373` | SBOM single-alert acknowledge accepts any API key scope |

---

## Findings (detail)

### SEC-401 — `approve_remediation` missing rate limit

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A07:2021 Identification & Authentication Failures · CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **Location:** `backend/app/routers/remediation.py:248–258`

**Evidence** (verbatim from source):
```python
248  @router.post("/{remediation_id}/approve", response_model=RemediationResponse)
249  async def approve_remediation(
250      request: Request,
251      remediation_id: str,
252      body: RemediationApprove,
253      background_tasks: BackgroundTasks,
254      db: AsyncSession = Depends(get_db),
255      _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
256  ):
```

Contrast with every other mutation endpoint in the same file:
```python
292  @router.post("/{remediation_id}/reject", response_model=RemediationResponse)
293  @limiter.limit("10/minute")  # SEC-222
294  async def reject_remediation(...)

324  @router.delete("/{remediation_id}", status_code=204)
325  @limiter.limit("10/minute")  # SEC-222
326  async def dismiss_remediation(...)

347  @router.post("/{remediation_id}/regenerate", ...)
348  @limiter.limit("10/minute")
349  async def regenerate_remediation(...)
```

- **Why it's a problem:** `approve_remediation` is the only mutation endpoint in this router without a `@limiter.limit()` decorator. Approving a remediation triggers a background GitHub API chain: branch creation, commit push, PR creation, and optionally auto-merge. Without a per-endpoint rate limit only the coarse 300/minute global cap applies, allowing ~30× more concurrent approvals than any other mutation. This is inconsistent with the rate-limiting posture applied to all peer endpoints (SEC-222).
- **Impact / attack scenario:** A compromised analyst or admin key can submit approval requests as fast as the event loop handles them. Each approval schedules a `BackgroundTask` that calls the GitHub API. At 300 approvals/minute (global cap), this could exhaust the deployment's GitHub API rate limit (5,000 requests/hour for authenticated apps), potentially causing scan integrations, webhook processing, and check-run updates to fail for the entire deployment.
- **How to verify:** `grep -n "limiter.limit\|approve_remediation" backend/app/routers/remediation.py`. Confirm `approve_remediation` has no `@limiter.limit` line while `reject_remediation`, `dismiss_remediation`, and `regenerate_remediation` do.
- **Remediation:** Add `@limiter.limit("10/minute")` immediately above `async def approve_remediation(...)`, consistent with all peer endpoints. The `request: Request` parameter is already present so SlowAPI can extract the client IP.
- **References:** OWASP A07:2021; CWE-307

---

### SEC-402 — `bulk_create_tickets` has no rate limit or finding-count cap

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-770 (Allocation of Resources Without Limits)
- **Location:** `backend/app/routers/jira.py:229–285`

**Evidence** (verbatim from source):
```python
229  @router.post("/repositories/{repo_id}/bulk-tickets")
230  async def bulk_create_tickets(
231      request: Request,
232      repo_id: str,
233      body: BulkTicketRequest,
234      db: AsyncSession = Depends(get_db),
235      _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-207
236  ):
```

The request schema:
```python
193  class BulkTicketRequest(BaseModel):
194      project_key: Optional[str] = None
195      severities: list[str] = ["CRITICAL", "HIGH"]
```

The loop that makes Jira API calls:
```python
249      findings = findings_result.scalars().all()
250  
251      created, skipped, failed = [], [], []
252  
253      for finding in findings:
...
263          try:
264              ticket = await jira_service.create_jira_ticket(finding, body.project_key)
```

- **Why it's a problem:** There is no `@limiter.limit()` decorator on `bulk_create_tickets`, and the `BulkTicketRequest` schema places no cap on the number of findings processed per call. The endpoint queries all open findings for a repository matching the specified severities and calls `jira_service.create_jira_ticket()` synchronously for each one. In contrast, the analogous `BulkRemediationRequest` (AI fix generation) caps at 20 findings: `finding_ids: List[str] = Field(..., max_length=20)`.
- **Impact / attack scenario:** A repository with hundreds or thousands of open CRITICAL/HIGH findings (common in a newly on-boarded repo) causes a single POST to issue hundreds of Jira API calls in sequence. Jira Cloud's REST API enforces a rate limit; if that limit is hit mid-loop, subsequent calls fail and findings are skipped silently (they land in the `failed` list). Additionally, because there is no per-endpoint rate limit, a compromised analyst key can submit this endpoint repeatedly. This is also a denial-of-wallet risk if the deployment uses a metered Jira plan.
- **How to verify:** `grep -n "limiter\|@limiter" backend/app/routers/jira.py` — confirms no rate-limit decorator. `grep -n "max_length\|max_items\|BulkTicketRequest" backend/app/routers/jira.py` — confirms `severities` list and finding loop are uncapped.
- **Remediation:** (1) Add `@limiter.limit("5/minute")` above `async def bulk_create_tickets`. (2) Add a finding-count cap inside the function, e.g. `findings = findings_result.scalars().all()[:200]`, and document the limit in the API response. Alternatively, add `max_length=200` to the findings slice before the loop.
- **References:** OWASP A04:2021; CWE-770

---

### SEC-403 — SBOM single-alert acknowledge accepts any API key scope

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-285 (Improper Authorization)
- **Location:** `backend/app/routers/sbom.py:368–382`

**Evidence** (verbatim from source):
```python
368  @router.post("/alerts/{alert_id}/acknowledge")
369  async def acknowledge_alert(
370      request: Request,
371      alert_id: str,
372      db: AsyncSession = Depends(get_db),
373      _key: str = Depends(require_api_key),         # ← any scope accepted
374  ):
375      result = await db.execute(select(SbomAlert).where(SbomAlert.id == alert_id))
376      alert = result.scalar_one_or_none()
377      if not alert:
378          raise HTTPException(status_code=404, detail="Alert not found")
379      alert.acknowledged_at = datetime.now(timezone.utc)
```

Contrast with the `acknowledge-all` endpoint (line 387–401):
```python
387  @router.post("/alerts/acknowledge-all")
388  async def acknowledge_all_alerts(
389      request: Request,
390      db: AsyncSession = Depends(get_db),
391      _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-325
392  ):
```

- **Why it's a problem:** `acknowledge_alert` (single-item mutation, POST) allows any valid API key — including CI scanner-scoped keys — to mark an SBOM supply-chain alert as acknowledged. `acknowledge_all_alerts` on the same resource was upgraded to `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` in SEC-325, and the parallel `regression_alerts` `acknowledge/{id}` endpoint was upgraded to the same scope in SEC-331. This endpoint was missed in both those passes, leaving a lower-privileged path to the same state change.
- **Impact / attack scenario:** A CI/CD pipeline key (scope: `scanner`) that is compromised — for example, via a secrets leak in a public GitHub Actions log — can call `POST /sbom/alerts/{alert_id}/acknowledge` to silence individual SBOM component alerts. Because `acknowledged_at` is set, the alert no longer appears as unacknowledged in the dashboard and suppression-monitoring tooling, masking a supply-chain risk without analyst or admin involvement. The attacker needs a valid API key of any scope and must enumerate or guess an alert UUID.
- **How to verify:** `grep -n "require_api_key\|require_scope" backend/app/routers/sbom.py | grep -A1 "acknowledge"`. Confirm `acknowledge_alert` uses `require_api_key` while `acknowledge_all_alerts` uses `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)`.
- **Remediation:** Change line 373:
  ```python
  # Before
  _key: str = Depends(require_api_key),
  # After
  _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-403
  ```
  `SCOPE_ANALYST` and `SCOPE_ADMIN` are already imported in this file.
- **References:** OWASP A01:2021; CWE-285

---

## Deferred findings (carried from previous passes)

These four findings were identified in prior audits and intentionally deferred. They remain open.

### SEC-215 — SlowAPI in-memory rate-limit store (Medium, deferred from Pass 3)

- **Location:** `backend/app/core/limiter.py`
- **Status:** Still open. SlowAPI defaults to an in-memory counter store. Counters are lost on container restart and are not shared across multiple backend replicas, making rate limits per-instance rather than per-deployment.
- **Risk:** In a horizontally-scaled deployment, a client can make up to `N × limit` requests per window where N is the replica count. Brute-force protection on `/auth/session` (5/minute) becomes 5N/minute across N replicas.
- **Deferral reason:** Requires infrastructure change (Redis or external rate-limit store). Not a code change.
- **Remediation:** Configure SlowAPI with a Redis backend: `Limiter(key_func=get_client_ip, storage_uri="redis://...")`. Redis is already a common dependency in production FastAPI deployments.

### SEC-237 — Floating Docker base image tags (Low, deferred from Pass 3)

- **Location:** `backend/Dockerfile:1`, `frontend/Dockerfile:2,12`
- **Evidence:**
  ```dockerfile
  FROM python:3.12-slim       # backend/Dockerfile:1
  FROM node:20-alpine         # frontend/Dockerfile:2
  FROM nginx:alpine           # frontend/Dockerfile:12
  ```
- **Status:** Still open. Tags are not pinned to image digests (`sha256:...`). A new image push to the upstream registry under the same tag can silently change the base layer without a code change.
- **Deferral reason:** Policy/operational decision; requires a digest-pinning and update process.
- **Remediation:** Pin each image to a digest and adopt a tool such as Renovate or Dependabot's `docker` ecosystem to propose digest updates as PRs.

### SEC-241 — npm `^` ranges on most frontend packages (Low, deferred from Pass 3)

- **Location:** `frontend/package.json:13–28`
- **Evidence (representative lines):**
  ```json
  "axios": "^1.7.2",
  "react": "^18.3.1",
  "recharts": "^2.12.7",
  "vite": "^5.3.4"
  ```
  Note: `dompurify` was correctly pinned to `"3.1.6"` (exact) in SEC-334.
- **Status:** Still open for all packages except `dompurify` and `@types/dompurify`.
- **Deferral reason:** Policy/architectural decision; `^` ranges are the npm ecosystem norm and the lockfile (`package-lock.json`) pins transitive versions. Risk is limited to `npm install` without the lockfile (e.g., in development or a misconfigured CI step).
- **Remediation:** Either pin all direct deps to exact versions (removes semantic-version flexibility) or ensure `npm ci` is enforced everywhere (already done in the Dockerfile). As a middle ground, pin security-sensitive packages (`axios`, `react-router-dom`) to exact versions.

### SEC-244 — `API_KEY_MAX_LIFETIME_DAYS=0` default (Info, deferred from Pass 3)

- **Location:** `backend/app/config.py:74`, `backend/app/core/security.py:521–524`
- **Evidence:**
  ```python
  API_KEY_MAX_LIFETIME_DAYS: int = 0   # config.py:74
  ```
  ```python
  if settings.API_KEY_MAX_LIFETIME_DAYS == 0 and settings.ENVIRONMENT == "production":
      logger.warning(
          "API_KEY_MAX_LIFETIME_DAYS=0 in production — API keys never expire. "
          "Set a maximum lifetime (e.g., API_KEY_MAX_LIFETIME_DAYS=90) to limit credential exposure."
      )
  ```
- **Status:** Still open. The default of 0 (no expiry) is warned about in production but not enforced. A deployment that does not set this variable will issue non-expiring keys by default.
- **Deferral reason:** Informational; operator configuration concern.
- **Remediation:** Change the default to `90` (days) and require an explicit opt-out for no-expiry deployments. Alternatively, enforce a hard minimum in production via a startup check that refuses to start if `ENVIRONMENT=production` and `API_KEY_MAX_LIFETIME_DAYS=0`.

---

## Verified safe / investigated (not findings)

The following areas appeared potentially risky but checked out:

| Area | Location | Why it's safe |
|------|----------|---------------|
| `github_full_name` URL path injection | `code_scanning_service.py:142`, `schemas/repository.py:11` | `_FULL_NAME_RE = r"^[a-zA-Z0-9._-]{1,100}/[a-zA-Z0-9._-]{1,100}$"` enforces strict allowlist at schema layer; no path traversal possible |
| SQL injection via ORM | All routers and services | SQLAlchemy ORM used throughout; no raw string interpolation in queries; `text()` calls use bound parameters |
| XSS in frontend | `MarkdownContent.tsx`, `FindingDetailPage.tsx`, `RemediationPage.tsx`, all pages | DOMPurify sanitization on all HTML paths; `safeUrl()` on all `href`/`src` from external data; no `dangerouslySetInnerHTML` without sanitization |
| Prompt injection in AI service | `ai_service.py:35–90` | `_CTRL_CHARS_RE` and `_PROMPT_INJECTION_RE` applied to file content, diffs, test files, and engineer context before prompt assembly |
| SSRF via notification webhook | `notification_service.py:19–59` | `_is_ssrf_safe()` blocks RFC-1918, loopback, link-local, AWS metadata endpoint; HTTPS enforced |
| SSRF via Jira URL | `jira_service.py:326–365` | Comprehensive IP blocklist including IPv6 ULA/loopback; HTTPS enforced |
| SSRF via EPSS URL | `prioritization_service.py:88–97` | HTTPS check + `ip_address.is_private/is_loopback/is_link_local` guard |
| Webhook replay attack | `security.py:620–651`, `webhooks.py:47–60` | `delivery_id` deduplication + timestamp staleness check (>10 min rejected) |
| Bootstrap API key weakness | `main.py:324` (SEC-301) | Fixed: `_compute_key_hashes()` now used — HMAC-SHA256 when `NYX_SECRET_KEY` is set |
| HMAC fallback key regeneration | `audit_service.py:21–24` (SEC-309) | Fixed: `_FALLBACK_HMAC_KEY` is a module-level constant, not regenerated per call |
| `body: dict` unconstrained inputs in compliance | `compliance.py:25–87` (SEC-315–321) | Fixed: all `body: dict` patterns replaced with typed Pydantic models with `max_length` constraints |
| AI-generated diff applied without review | `remediation.py:268–274` | `auto_merge` requires `SCOPE_ADMIN` explicitly checked; default path requires human approval step in `REVIEW` state |
| AuditPage metadata XSS | `AuditPage.tsx:121–125` | `{JSON.stringify(...)}` is a React text node (no HTML sink); endpoint requires `SCOPE_ADMIN` |

---

## Coverage manifest

- **Reviewed (source files):**
  - `backend/app/` — all 58 Python files: `main.py`, `config.py`, `database.py`, all routers (17 files), all services (13 files), all models (16 files), all normalization modules (11 files), core utilities (5 files), workers (1 file)
  - `backend/tests/` — `conftest.py`, `test_api/test_auth.py`, `test_api/test_webhooks.py`
  - `backend/scripts/seed_demo_data.py`
  - `backend/Dockerfile`, `backend/entrypoint.sh`, `backend/requirements.txt`, `backend/pyproject.toml`, `backend/log_config.json`
  - `frontend/src/` — all 44 TypeScript/TSX files: all pages (17), all API clients (12), all components (8), hooks (2), utils (2), types, constants
  - `frontend/Dockerfile`, `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`
  - `docker-compose.yml`, `docker-compose.postgres.yml`
  - `.env.example`
  - `.github/workflows/nyx-scan.yml`, `.github/workflows/nyx-scan-container.yml`, `.github/workflows/nyx-scan-gitleaks.yml`
  - `SECURITY-AUDIT-2026-06-16.md` (prior audit reference)
  - Total: **~218 files**

- **Skipped:**
  - `node_modules/` — third-party packages; not in scope
  - `dist/`, `build/`, `target/`, `__pycache__/` — build artifacts
  - `.git/` — version control metadata
  - `wiki/` — documentation only; no executable code
  - `semgrep-results.json` — scan output artifact; not source code

- **Not reached / needs follow-up:**
  - Frontend `package-lock.json` — lockfile integrity not verified (would require `npm audit`). The deferred SEC-241 is the relevant risk.
  - `backend/requirements.txt` dependency audit — `pip-audit` not run (tool not available in this environment). All package versions confirmed present and pinned; no known advisories identified from version numbers, but a live `pip-audit` run is recommended in CI.

---

*To apply fixes: `fix SEC-401`, `fix SEC-402`, `fix SEC-403` — the detail sections above have the exact remediation for each.*
