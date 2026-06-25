# AI Remediation

How Nyx uses Claude to turn a finding into a merge-ready pull request — and the safety rails that sit between "fix generated" and "fix merged."

---

## The request lifecycle

```
Engineer clicks "Request AI Fix"
        │
        ▼
┌──────────────────────┐
│  Context gathering    │  finding + code + tests + CVE data + prior fixes
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Claude API call      │  streamed via SSE; user sees tokens as they arrive
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Response parsing     │  extract diff, explanation, confidence, tests
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Diff security scan   │  heuristics against dangerous patterns
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Confidence gate      │  below threshold → REVIEW_LOW_CONFIDENCE
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Persist remediation  │  store diff, status, token count, cost
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Open PR + Jira link  │  branch, commit, PR, ticket, comment
└──────────────────────┘
```

<!-- IMAGE: Animated GIF of a fix request streaming into the remediation panel.
     File: wiki/images/ai-fix-stream.gif -->
![AI fix streaming](images/ai-fix-stream.gif)
<!-- /IMAGE -->

---

## Context gathering

For each fix request, Nyx builds a prompt that includes:

1. **The vulnerable code** — the specific lines the scanner flagged, plus surrounding context (default ±40 lines).
2. **Test files** — any `test_*.py`, `*_test.go`, `*.test.ts`, `tests/*` files matching the target file's basename are included in full so Claude can write fixes that pass existing tests.
3. **Finding metadata** — CWE, CVE, CVSS vector, EPSS probability, severity, scanner name, rule ID.
4. **Suppression hints** — patterns previously marked as false positive for similar findings are surfaced in the prompt to reduce hallucinated "fixes" for non-issues.
5. **Prior fix attempts** — if this finding was previously attempted, the earlier diff and its outcome are included.
6. **Repository conventions** — language, framework, dependency manager, style signals pulled from the repo's files.

---

## The request

Default model is `claude-sonnet-4-6`. Change with:

```bash
ANTHROPIC_MODEL=claude-opus-4-6   # higher quality, higher cost
ANTHROPIC_MODEL=claude-haiku-4-5  # cheaper, good for bulk summarization
```

Requests are sent with:

- `max_tokens`: `AI_MAX_OUTPUT_TOKENS` (default 8192)
- `stream=True` — the SSE endpoint (`GET /remediation/{id}/stream`) relays tokens to the UI
- A system prompt that enforces the response schema (diff, explanation, confidence, test plan)

---

## Response schema

Every fix response is expected to be structured:

```json
{
  "explanation": "The vulnerability exists because...",
  "diff": "--- a/foo.py\n+++ b/foo.py\n@@ ...",
  "confidence": 0.82,
  "test_plan": "Run test_foo.py::test_sanitize_input",
  "alternative_approaches": ["Option A...", "Option B..."]
}
```

Unstructured responses are retried once with a stricter schema reminder. A second failure is marked `PARSE_ERROR` and queued for human review.

The **explanation** field renders as formatted markdown in the UI — headings, bullet lists, and inline code are all displayed cleanly. The **diff** is displayed as a colour-coded view with green addition lines, red deletion lines, and dimmed context lines.

---

## Diff security scanning

Before storage, every diff is scanned for dangerous patterns:

- `os.system`, `subprocess.call(..., shell=True)`, `eval`, `exec`, `Function()` constructor
- Hardcoded secrets (regexes for AWS keys, GitHub tokens, generic high-entropy strings)
- Disabling TLS verification (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED`, etc.)
- Shell injection primitives
- Wide-open CORS / permissive CSP
- Dropping auth middleware

Matches are stored as `diff_warnings` on the remediation record and surfaced in the UI. A fix with warnings can still be applied, but it cannot be merged silently — the engineer must acknowledge the warnings.

---

## Confidence gating

Every fix returns a self-reported confidence score in `[0.0, 1.0]`. Fixes below `AI_MIN_CONFIDENCE_THRESHOLD` (default `0.4`) are tagged:

```
status = REVIEW_LOW_CONFIDENCE
```

They are **not** automatically opened as PRs. They appear in the Remediation page with an orange banner and require manual approval before proceeding. This is the single most important safety rail — a low-confidence fix is far more likely to regress tests or introduce subtle bugs.

---

## Alternative fix suggestions

`POST /remediation/{id}/alternatives` triggers an independent Claude call that returns 2–3 distinct approaches with trade-off analysis:

- **Approach A** — minimal change, low risk, narrow scope
- **Approach B** — refactor-oriented, higher churn, fixes root cause
- **Approach C** — defense-in-depth, wraps the vulnerability plus adds tests

Engineers pick whichever fits the codebase culture. Useful for non-obvious fixes where the "right" answer depends on context Nyx cannot see.

---

## Bulk fix requests

Select up to 20 findings on the Findings page → **Request AI Fix (Bulk)**. Nyx queues each request and processes them with bounded concurrency inside the remediation worker. Each finding gets its own remediation record; failures do not block the batch.

---

## Claude Code prompt generator

Not every fix should be applied by Claude directly — sometimes engineers want the context but their own hands on the keys. **Generate Claude Code Prompt** produces a structured prompt for the **Claude Code CLI** covering the selected findings, grouped by scanner category, with:

- Finding metadata
- Vulnerable code snippets
- CVE data
- A completion-report template the engineer fills in as they fix

Copy → paste into `claude` → work through the list interactively.

---

## Cost tracking

Every Claude call records:

- Input tokens
- Output tokens
- Computed USD cost (using published Anthropic pricing)
- Model used

The **AI Cost dashboard** (`/reports#ai-costs`) aggregates these into:

- Daily spend time series
- Running total
- Top-10 most expensive remediations
- Per-model breakdown

Cap the per-fix output budget via `AI_MAX_OUTPUT_TOKENS` in `.env` and raise `AI_MIN_CONFIDENCE_THRESHOLD` if you want fewer speculative fixes. Monitor the dashboard and revoke any runaway CI scanner keys via Settings → API Keys if spend spikes.

---

## Auto PR Mode

Auto PR Mode is a per-repository toggle that runs the remediation pipeline **autonomously**:
when a scan completes, Nyx triages new CRITICAL/HIGH findings, generates a fix, security-audits
it, and opens a **draft** pull request — never auto-merged and never marked ready-for-review.
A human still owns the merge decision.

**Enabling it.** Off by default at two levels: the operator master switch `AUTO_PR_MODE_ENABLED`
(env), and a per-repository toggle in the repository's settings (Repositories → repo → *Auto PR Mode*).
Both must be on. The repo settings also control: severity threshold (CRITICAL only, or CRITICAL+HIGH),
a daily token budget, and three behavior flags (skip low-confidence fixes, require passing CI checks,
run a security audit before committing).

**Pipeline.** For each eligible finding (ordered by priority score):

1. Budget check — pre-call token estimate; skip with `BUDGET_EXCEEDED` if it would exceed the daily cap.
2. Generate the fix with `AUTO_PR_FIX_MODEL` (default Sonnet); deduct tokens atomically.
3. Confidence gate — below `AI_MIN_CONFIDENCE_THRESHOLD` → `REVIEW_LOW_CONFIDENCE` (skipped if the flag is on).
4. Diff heuristic scan — any warning routes to review rather than committing.
5. **Security audit** — a second, independent Claude pass (`AUTO_PR_AUDIT_MODEL`, default Haiku) reviews
   the diff for introduced vulnerabilities. A fail → `AUDIT_FAILED`, no commit, optional Slack/Teams alert.
6. Open a **draft PR** on `nyx/auto-fix/<finding-id>` → `COMMITTED`.
7. Optional CI gate — poll the target repo's GitHub Actions check-runs on the pushed commit; a failure → `TEST_FAILED`.
   The draft PR is annotated with the result either way.

**Budgets** reset daily (00:05 UTC). Concurrency is capped globally by `AUTO_PR_MAX_CONCURRENT`.
Every state transition is written to the [audit log](Features.md#audit-log-with-hmac-hash-chain) as an
`auto_pr.*` event. See [Configuration](Configuration.md) for the `AUTO_PR_*` variables.

**Auto-mode statuses:** `AUTO_TRIGGERED` (queued) · `AUDIT_IN_PROGRESS` · `AUDIT_FAILED` ·
`TEST_IN_PROGRESS` · `TEST_FAILED` · `COMMITTED` (draft PR open) · `BUDGET_EXCEEDED` ·
`ADVISORY_OPENED` (GitHub Issue created — see below).

### Advisory pipeline (findings without a patchable file)

Findings that have no `file_path` — SCA dependency CVEs, container image vulnerabilities, IaC policy
failures — cannot be patched in-place. Instead of being silently skipped, they are routed through the
**advisory sub-pipeline**:

1. Budget check (same daily cap as the fix pipeline).
2. Claude Haiku (`AUTO_PR_AUDIT_MODEL`) generates structured remediation guidance: root cause, recommended
   upgrade or mitigation steps, and references.
3. Nyx opens a **GitHub Issue** on the target repository titled `[Nyx Advisory] <SEVERITY>: <title>`,
   tagged with the `nyx-advisory` and `security` labels.
4. The finding's `advisory_issue_url` field is populated with the Issue URL; the Remediation record's
   status is set to `ADVISORY_OPENED`.

Advisory findings appear in the Remediation page alongside regular fixes, with a distinct **"Advisory
Issue"** label and a link to the GitHub Issue. They are counted separately in the Daily Digest report.

---

## Failure modes and what they mean

| Status | Meaning | What to do |
|---|---|---|
| `PENDING` | Queued, not yet started | Wait |
| `IN_PROGRESS` | Streaming | Wait or watch the SSE feed |
| `COMPLETED` | Fix generated and clean | Review and open PR |
| `REVIEW_LOW_CONFIDENCE` | Below confidence threshold | Human review required |
| `REVIEW_DIFF_WARNING` | Dangerous patterns detected in diff | Human review required |
| `PARSE_ERROR` | Claude response did not match schema twice | Retry or fix by hand |
| `API_ERROR` | Claude API returned 4xx/5xx | Check Anthropic status, retry |
| `TIMEOUT` | Request exceeded `AI_REQUEST_TIMEOUT` | Retry with a tighter context window |

---

## What next

- **See costs and velocity →** [Reports & Analytics](Reports.md)
- **Automate fix PR creation on merge →** [CI/CD Integration](CICD-Integration.md)
