# Nyx Security Audit — 2026-09-27

**Scope:** full repository at `c642c7d` (branch `main`), with emphasis on the two most recent feature
drops: **Auto PR Mode** (`d1c63a4`, #2) and the **AI cost tracker** (`e9b30d5`).
**Method:** manual source review of every backend router, worker and service; endpoint-by-endpoint
auth/scope matrix; executable proof-of-concept tests; `pip-audit`, `bandit -ll`, `npm audit --omit=dev`;
existing test suite.

Every finding marked **[PoC ✔]** was demonstrated by an executable proof-of-concept that
asserted the vulnerable behaviour. **All 18 findings have since been remediated** (see
[Remediation status](#remediation-status)). The PoC script was retired after it was re-run
against the fixed code, where 8 of 9 PoCs fail as intended; PoC-08 describes the documented
semantics of an optional setting (see -08). Its cases live on, inverted, as regression tests in
[`backend/tests/test_security_regressions.py`](backend/tests/test_security_regressions.py):

```bash
cd backend && python -m pytest -q     # 110 passed
```

## Summary

| ID | Severity | Title | Area | Status (2026-09-27) |
|----|----------|-------|------|--------|
| NYX-2026-09-01 | **High** | Any API key (even `readonly`) can inject findings via `POST /scans/import`, skipping scope and submission HMAC, which then drives Auto PR in any repo | scans / auto-PR | Fixed (ef49902) |
| NYX-2026-09-02 | **High** | Security audit gate fails **open** on a non-boolean `"passed"` value | auto-PR audit | Fixed (ef49902) |
| NYX-2026-09-03 | **High** | Diff applier writes lines the diff never named; the code Nyx commits can differ from the diff that was audited and approved | github_service | Fixed (ef49902) |
| NYX-2026-09-04 | **High** | PR-merged webhook isn't scoped to its repository: merging PR #N anywhere marks every repo's remediation #N MERGED and its finding FIXED | webhooks | Fixed (ef49902) |
| NYX-2026-09-05 | Medium | Any API key (even `readonly`/`scanner`) can register repositories and install GitHub webhooks with Nyx's token | repositories | Fixed (63909a9) |
| NYX-2026-09-06 | Medium | `POST /repositories/{id}/run-auto-pr` ignores the `AUTO_PR_MODE_ENABLED` master switch | auto-PR | Fixed (63909a9) |
| NYX-2026-09-07 | Medium | Untrusted content can close the prompt fences in the fix and audit prompts | ai_service / audit | Fixed (63909a9) |
| NYX-2026-09-08 | Medium | Production mode requires `NYX_WEBHOOK_SECRET`, but setting it makes every genuine GitHub webhook fail with 403 | webhooks / config | Fixed (63909a9) |
| NYX-2026-09-09 | Medium | Advisory pipeline posts raw model output (and a raw title) as GitHub Issues under Nyx's identity | auto-PR advisory | Fixed (63909a9) |
| NYX-2026-09-10 | Medium | Weekly job auto-bumps "SHA-pinned" actions to whatever `latest` resolves to, then pushes workflows straight to every repo's default branch | supply chain | Fixed (63909a9) |
| NYX-2026-09-11 | Medium | Vulnerable frontend dependencies, including DOMPurify (the XSS sanitizer for scanner and AI HTML), axios, react-router | frontend deps | Fixed (81d7fd3) |
| NYX-2026-09-12 | Low | Auto-PR branch name is deterministic per finding; any retry hits "branch exists" and burns tokens on every scan | auto-PR | Fixed (3ed5178) |
| NYX-2026-09-13 | Low | Fix is computed on an old file snapshot but committed over the current base SHA, which can revert newer commits | github_service | Fixed (3ed5178) |
| NYX-2026-09-14 | Low | Budget accounting races: concurrent pipelines, advisory ignores over-budget, untracked `create_task` handles | auto-PR | Fixed (3ed5178) |
| NYX-2026-09-15 | Low | `check_run` handler ignores `nyx/auto-fix/*` branches and isn't repo-scoped | webhooks | Fixed (3ed5178) |
| NYX-2026-09-16 | Low | `/auth/session` rejects any DB key with an expiry on SQLite (naive/aware datetime `TypeError`) | auth | Fixed (3ed5178) |
| NYX-2026-09-17 | Low | `rotate_secret_key()` double-encrypts through the ORM TypeDecorator (dead code today) | crypto | Fixed (3ed5178) |
| NYX-2026-09-18 | Info | 4 tests in `test_auto_pr_worker.py` fail on `main`; the test suite is red | tests | Fixed (3ed5178) |

Tool results: `pip-audit` found no known vulnerable Python deps. `bandit -ll` found nothing at medium or high
(22 low-severity items). `npm audit` found 11 issues (3 high, 8 moderate); see NYX-2026-09-11.

---

## High

### NYX-2026-09-01: Scan-import authorization bypass that feeds Auto PR `[PoC ✔ test_poc_04]`

**Where:** `backend/app/routers/scans.py:162-214` (`POST /api/v1/scans/import`)

`/scans/import-json` requires `scanner`/`analyst` scope and enforces `X-Nyx-Submission-HMAC`
(`REQUIRE_SUBMISSION_HMAC=True` by default). Its multipart twin, `/scans/import`, depends only on
`require_api_key`, so **any** valid key works, including `readonly`. It also never calls `verify_submission_hmac`.
The PoC shows a `readonly` key getting `403` from `import-json` and `202` from `import` against the same
repository.

API keys aren't bound to a repository, and repository IDs are listed to any key by `GET /repositories`. So:

1. Any key holder injects findings into **any** repo with arbitrary `title`, `description`, `remediation_guidance`,
   `severity=CRITICAL` and `file_path`. That includes the `scanner` key the docs tell users to store in every
   onboarded repo's Actions secrets.
2. `process_scan_results` then calls `enqueue_auto_pr_findings` when Auto PR Mode is on (`scan_worker.py:303-311`).
3. With a `file_path`, Nyx fetches the real file with its PAT and asks Claude to "fix" it, steered by the
   attacker's description and guidance, which only get a phrase-blocklist filter. It then opens a **draft PR
   in the victim repo under Nyx's bot identity**. Without a `file_path`, it opens a **GitHub Issue** with
   model-written "remediation steps" (see -09).

The docs say a scanner key "limits blast radius if a CI secret is ever compromised"
(`wiki/CICD-Integration.md:42`). This endpoint defeats that.

**Fix:** use `require_scope(SCOPE_SCANNER, SCOPE_ANALYST)` and the same `verify_submission_hmac` gate as
`import-json`, or delete the route. Consider binding scanner keys to a repository ID. Make
`enqueue_auto_pr_findings` act only on scans with `submission_verified=True` (or a trigger other than IMPORT).

### NYX-2026-09-02: Audit verdict fails open `[PoC ✔ test_poc_01]`

**Where:** `backend/app/services/auto_pr_audit_service.py:100`

```python
"passed": bool(data.get("passed")),
```

`bool("false")`, `bool("no")` and `bool(0.0001)` are all truthy. An audit response of
`{"passed": "false", "risk_level": "CRITICAL", ...}` becomes **passed=True**, and the worker commits the fix
(`auto_pr_worker.py:382`). The module docstring promises fail-closed behaviour. Also, `_JSON_OBJECT_RE`
(`\{.*\}`, greedy, DOTALL) grabs from the first `{` to the last `}` of the whole reply, so an earlier or
later JSON-looking fragment can shape the parsed verdict. Combined with -07, attacker-influenced diff text
can suggest exactly such a reply.

**Fix:** `passed = data.get("passed") is True`. Also require `risk_level in {"LOW"}` (or ≤ MEDIUM) and
`findings == []` for a pass. Better still, use structured output (a tool with a JSON schema whose `passed`
is `boolean`) instead of regex extraction.

### NYX-2026-09-03: Committed code can differ from the audited or approved diff `[PoC ✔ test_poc_02]`

**Where:** `backend/app/services/github_service.py:975-1033` (`apply_unified_diff`)

When the fuzzy search fails to find a hunk's source lines, the code keeps `actual_start = expected_start`
("trust the diff") and overwrites `len(source_lines)` lines at that position **without checking they
match the `-`/context lines**. In the PoC, a diff that claims to change `log.debug('noop')` actually deletes
`require_auth(req)`, and the function returns the result as a clean apply.

Consequences:
- The Auto PR security audit (-02) and the engineer reviewing the diff in Nyx's UI both see diff A, while
  Nyx commits change B. The GitHub PR diff shows B, but Auto PR's whole gate reasoned about A.
- LLM hunk offsets are often wrong (`_fix_hunk_headers` exists for this reason), so this also causes
  **accidental** corruption, not only adversarial.
- `for patched_file in patch: result_lines = list(lines)` resets per file, so in a multi-file diff only the
  *last* file's hunks apply, and they apply to the target file whatever its name. `_validate_diff_scope` only
  inspects `--- a/` and `+++ b/` headers, so un-prefixed headers (`--- foo`) skip the scope check entirely.

**Fix:** if no exact match is found within the fuzz window, return `None` (the callers already treat that
as "could not apply cleanly"). Reject patches with more than one file, or with headers that don't
match `a/<finding.file_path>` exactly. Feed the audit model the real before/after content
(`difflib.unified_diff(original, fixed)`) rather than the model-authored diff.

### NYX-2026-09-04: PR-merge webhook closes findings in other repositories `[PoC ✔ test_poc_03]`

**Where:** `backend/app/routers/webhooks.py:270-280`

```python
select(Remediation).where(Remediation.pr_number == pr_number)
```

PR numbers are per repository. A merged PR #7 in *any* registered repo marks every remediation with
`pr_number == 7` (in every repo) as `MERGED` and its finding as `FIXED`, and syncs JIRA to "Done".
This happens in **normal operation** without any attacker: registered repos routinely have overlapping PR
numbers. Advisory issues also store the issue number in `pr_number` (`auto_pr_worker.py:855`), which widens
the collision space further. The result is that open CRITICAL findings silently disappear from dashboards,
SLA tracking and compliance reports.

**Fix:** join through `Finding.repository_id == repo.id`, or better, store and match on `pr_url` or
`(repo_id, pr_number)`. Exclude advisory remediations (`ADVISORY_OPENED`) from PR-merge handling.

---

## Medium

### NYX-2026-09-05: Low-privilege keys can register repos and install webhooks `[PoC ✔ test_poc_05]`

`POST /api/v1/repositories` (`repositories.py:33-82`) uses `require_api_key`. A `readonly` or `scanner` key
can make Nyx call `repo.create_hook` with its `GITHUB_TOKEN` on any repository that token administers,
and list metadata of private repos. Other write routes that also lack scope checks:
`POST /sbom/repositories/{id}/submit` and `POST /sbom/alerts/{id}/acknowledge`.
**Fix:** `require_scope(SCOPE_ANALYST, SCOPE_ADMIN)` for registration and alert acknowledgement,
`require_scope(SCOPE_SCANNER, …)` for SBOM submission.

### NYX-2026-09-06: Auto PR master switch is bypassable `[PoC ✔ test_poc_06]`

`AUTO_PR_MODE_ENABLED` is only checked in `scan_worker.py:305`. `PATCH /repositories/{id}` or
`/auto-pr-mode` can set `repo.auto_pr_mode=True`, and `POST /repositories/{id}/run-auto-pr` →
`trigger_auto_pr_now` then runs the full pipeline (Claude spend plus GitHub writes) with the master
switch **off**. With the switch off, `_auto_pr_budget_reset_loop` never starts either, so
`auto_pr_tokens_used_today` never resets. **Fix:** check the setting in `trigger_auto_pr_now`,
`enqueue_auto_pr_findings`, `set_auto_pr_mode` and `update_repository` (return 409 or 403 when disabled).

### NYX-2026-09-07: Prompt-fence breakout `[PoC ✔ test_poc_07]`

The fences `<<<NYX_FILE_CONTENT_*>>>`, `<<<NYX_TEST_CONTENT_*>>>` and `<<<NYX_DIFF_*>>>` are static strings, and
nothing strips or escapes them in file content, test files, or the model-generated diff before
interpolation (`ai_service.py:526-529`, `auto_pr_audit_service.py:70`). A repo file (or a diff echoing one)
containing `<<<NYX_DIFF_END>>>` puts the text that follows *outside* the "never an instruction" region.
`_safe()`'s phrase blocklist is easy to rephrase around. The advisory prompt also interpolates `cwe_str`
without `_safe()` (`ai_service.py:814`, unlike the fix prompt's `_CWE_ID_RE` filter).
**Fix:** use per-request random nonces in fence names (`<<<NYX_DIFF_END_{secrets.token_hex(8)}>>>`) or
strip fence tokens from all untrusted input. Filter CWE IDs with `_CWE_ID_RE` in the advisory prompt.
Treat the audit as one signal among several, not a security boundary.

### NYX-2026-09-08: `NYX_WEBHOOK_SECRET` breaks webhooks and is mandatory in production `[PoC ✔ test_poc_08]`

`verify_global_webhook_hmac` and `verify_github_signature` both check the **same** `X-Hub-Signature-256`
header. GitHub signs with one secret: the random per-repo secret Nyx registered. So when the global secret
is set, every genuine delivery gets `403`. Yet `warn_insecure_config` **refuses to start** in
`ENVIRONMENT=production` without it (`security.py:500-507`). `wiki/Deployment.md:110` and `Installation.md:33`
say to set it, while `wiki/GitHub-Integration.md:117` says setting it "breaks all webhooks". So production
deployments lose push scans, PR check runs and merge detection. **Fix:** drop the production hard-fail,
or register webhooks with the global secret (and verify only once), or move the pre-check to a separate
header or query token.

### NYX-2026-09-09: Advisory issues publish unsanitized model output `[PoC ✔ test_poc_09]`

`_build_advisory_issue_body` embeds `guidance_markdown` verbatim (`auto_pr_worker.py:780`). The issue title is
`f"[Nyx Advisory] {finding.severity}: {finding.title[:150]}"` with no sanitization (`:841`). Together with
-01 and -07, attacker-steered text (@team mentions, `curl … | sh` "remediation steps", phishing links)
gets posted to the victim repo by Nyx's trusted bot account. The system prompt even asks for "exact commands".
**Fix:** neutralize `@` mentions (insert a zero-width joiner or wrap in code), restrict links to an allowlist
(nvd.nist.gov, cve.org, github.com/advisories, and so on), run the title through `_sanitize_md`, and add a
visible "AI-generated, verify before running" banner.

### NYX-2026-09-10: Pinned actions are auto-bumped and force-pushed to all repos

`refresh_pinned_actions` (`github_service.py:84-142`) replaces the SHA pin with whatever `releases/latest`
resolves to, and `_pinned_action_refresh_loop` (`main.py:406-432`) then commits the new workflow **directly
to every repo's default branch** (`push_nyx_workflow`, no PR or review). That throws away the protection SHA
pinning is meant to give: a hijacked release or tag (the tj-actions/changed-files incident pattern) would
reach every onboarded repo within a week. The generated workflow also runs `actions/checkout@v4` (tag, not SHA),
an unpinned `pip install semgrep`, and an unpinned `npm install -g snyk`, all in a job that holds `NYX_API_KEY`
and the per-repo HMAC secret. Also, `on.push.branches: [main]` is hard-coded whatever `default_branch` is.
**Fix:** make updates propose a PR (or require admin approval in Nyx), SHA-pin `actions/checkout`, pin tool
versions with hashes, and template the branch.

### NYX-2026-09-11: Vulnerable frontend dependencies

`npm audit --omit=dev`: **dompurify ≤3.4.12** (several XSS advisories). This is the sanitizer
`MarkdownContent.tsx` relies on for scanner-sourced and AI-generated HTML, which attackers can inject via -01.
Also: **axios** 1.0.0–1.17.0 (NO_PROXY SSRF, prototype-pollution auth bypass), **form-data** (CRLF), **lodash**
(template code injection and prototype pollution), **react-router(-dom)** / **@remix-run/router** (open
redirect → XSS), **follow-redirects** (auth header leak), **prismjs** via react-syntax-highlighter (DOM
clobbering). **Fix:** `npm audit fix`, and bump react-syntax-highlighter to 16.x (breaking).

---

## Low / Informational

- **-12 Deterministic branch on retry** (`auto_pr_worker.py:450`): `nyx/auto-fix/{finding.id[:8]}` is
  per-finding. If a run fails after `create_git_ref` (or a human closes the draft without deleting the
  branch and the finding reopens), each later scan regenerates and audits the fix, spending tokens, then
  fails with "Reference already exists". Include the remediation ID in the branch name, or reuse and
  force-update the existing branch.
- **-13 Stale-content overwrite** (`github_service.py:667-674`): `fixed_content` is derived from the file
  fetched at the pipeline start, but committed with `sha=` of the *current* base file. Commits landing in
  between (generation plus audit plus a CI wait can take minutes) are silently reverted in the fix branch.
  Commit only if the current blob SHA equals the SHA the fix was generated against.
- **-14 Budget races**: `AUTO_PR_MAX_CONCURRENT` pipelines each pass the budget check before any
  deduction. The pre-call estimate counts input tokens only. `process_advisory_finding` ignores the
  over-budget result. `asyncio.create_task(...)` handles are not retained (tasks can be garbage-collected
  mid-flight). Reserve budget atomically before the call (`UPDATE … WHERE used + est <= budget`) and keep
  task references in a set.
- **-15 `check_run` handler** (`webhooks.py:329`): only matches `nyx/fix/`, so Auto PR's `nyx/auto-fix/` CI
  results are never recorded via webhook. The lookup isn't scoped to the sending repo, and
  `scalar_one_or_none()` raises if two repos share a branch name.
- **-16 Session login with expiring keys** (`main.py:680`): on SQLite, `record.expires_at < now` compares
  naive and aware datetimes. The `TypeError` is swallowed and the login returns 401 (verified). It also
  counts toward the IP lockout. Normalize tz as `require_api_key` already does.
- **-17 `rotate_secret_key`** (`security.py:786-845`): the "bypass the ORM TypeDecorator" `update()` still
  runs `EncryptedString.process_bind_param`, so the value is encrypted with the new key and then again with
  the old one. It isn't called anywhere today; fix or remove it before it's wired up.
- **-18 Red test suite**: `pytest` on `main` gives 35 passed and **4 failed** (`tests/test_auto_pr_worker.py`). The
  tests expect threshold `"HIGH"` to mean "HIGH and above", but `_severities_for_threshold` now treats it as
  an exact list. Either update the tests or restore the old semantics. A repo configured with a legacy
  `"HIGH"` value silently stops auto-fixing CRITICALs. The Auto PR worker header also notes Semgrep was never run
  on it before merge.

## What held up well

Several things held up under review: HMAC and compare_digest use everywhere, the opaque session cookie
(hash-only in DB, `SameSite=Strict`, `Secure` by default), HKDF-derived Fernet at-rest encryption, per-IP
lockout that is proxy-aware and persisted, path sanitization of scanner file paths, JSON depth and body-size
limits, CSP `default-src 'none'` on API responses, HTML escaping in the digest export, draft-only Auto PRs
with no merge path from the worker, and `_validate_diff_scope` blocking CI and dependency files. The AI cost
tracker (`e9b30d5`) is read-only aggregation, and I found no issues in it.

## Recommended order of work

1. -04 (data integrity, happens without an attacker), -01 and -05 (scope and HMAC on import and
   registration), -06 (master switch).
2. -02 and -03 (make the Auto PR gate trustworthy), then -07 and -09.
3. -08 (production webhooks), -10 (workflow supply chain), -11 (`npm audit fix`).
4. The Low items, then turn the PoC file into regression tests.

---

## Remediation status

Each finding was reproduced again before it was fixed. A regression test was written first and
confirmed to fail on the pre-fix code, then passed after the fix. Commits on
`claude/admiring-meitner-gb4nh3`: `ef49902` (-01…-04), `63909a9` (-05…-10), `81d7fd3` (-11),
`3ed5178` (-12…-18), plus a follow-up wrap-up commit (budget-reservation refund on failure, docs).

| ID | Fix |
|----|-----|
| -01 | `/scans/import` requires analyst scope. Auto PR runs only for HMAC-verified imports, signed Snyk webhooks (`submission_verified` now recorded), or scheduled/manual GitHub syncs. |
| -02 | `passed` must be the JSON boolean `true`; HIGH/CRITICAL risk forces a fail; object-by-object JSON decoding replaces the greedy regex. |
| -03 | Unmatched hunks and multi-file patches are rejected (matching ignores only line terminators). Every `---`/`+++` header pair is scope-checked. Auto PR applies the diff first and audits the real before/after change. |
| -04 | The PR-merge lookup is joined to the sending repository and excludes `ADVISORY_OPENED`. |
| -05 | `POST /repositories` and SBOM alert ack need analyst/admin; SBOM submit needs scanner/analyst. |
| -06 | The master switch is checked in `enqueue_auto_pr_findings`/`trigger_auto_pr_now`. Enabling or running while it is off → 409, and the UI shows the server message. |
| -07 | Per-request nonce fences in the fix, test, alternatives, stream and audit prompts. The advisory prompt keeps only `CWE-\d+` IDs. |
| -08 | `NYX_WEBHOOK_SECRET` is no longer required in production (a warning is logged when it is *set*). Deployment/Installation/README docs aligned. When set, hooks must use that value (documented, tested). |
| -09 | Advisory bodies: @mentions neutralised (ZWJ), raw HTML stripped, links kept only for https allowlisted hosts, and code spans left verbatim. The title goes through `_sanitize_md`, and an "AI-generated" banner is added. |
| -10 | The weekly job is detection-only (log + `workflow.pin_update_available` audit event); pins are never mutated or pushed. `actions/checkout` is SHA-pinned (v4.2.2, verified via `git ls-remote`), with `semgrep==1.178.0` and `snyk@1.1307.4` (resolved from PyPI/npm), and the trigger branch is templated. The repo's own `nyx-scan.yml` is pinned the same way. |
| -11 | `npm audit --omit=dev`: 11 → **0**. dompurify 3.4.16, react-syntax-highlighter 16.1.1, and **react-router-dom 7.18.4** (an additional major bump: the react-router advisories have no v6 fix). Verified with tsc + vite build and a headless-Chromium smoke test of all routes. |
| -12 | Branch `nyx/auto-fix/<finding8>-<rem8>`. |
| -13 | `create_fix_pr(expected_base_sha=…)` refuses (and writes nothing) if the blob changed since fetch; used by both the auto and manual flows. |
| -14 | Atomic conditional reservation (`_reserve_budget`) → true-up → refund on failure. The advisory logs over-budget. Task handles are held in `_BACKGROUND_TASKS`. |
| -15 | `check_run` handles `nyx/fix/` and `nyx/auto-fix/`, scoped to the sending repository. |
| -16 | Naive `expires_at` is normalised to UTC in `/auth/session`. |
| -17 | Rotation writes through textual SQL (single encryption; verified by decrypting with the new key). |
| -18 | Tests updated to the exact-list threshold semantics used by the UI. |

**Residual notes**
- The advisory link allowlist includes `github.com` as a whole, so links to arbitrary GitHub repos
  remain possible. Narrow it to `/advisories/` and commit URLs if that is too broad for your threat model.
- Semgrep could not be run (its registry is blocked by the audit environment's network policy).
  bandit, pip-audit and npm audit were re-run and are clean.

**Pre-existing issues observed during verification (not part of the 18 findings, not changed)**
- `GET /dashboard/hot-repos` and `/dashboard/org-risk-history` return 500
  (`TypeError: Function.__init__() got an unexpected keyword argument 'else_'`, `dashboard.py:223,354`).
- `npm run lint` fails: the repo has no ESLint configuration.
- `ai_service._parse_explanation` raises `AttributeError` if the model returns valid JSON that is
  not an object (for example `[]`).
