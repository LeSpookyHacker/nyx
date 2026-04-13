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
AI_MODEL=claude-opus-4-6   # higher quality, higher cost
AI_MODEL=claude-haiku-4-5  # cheaper, good for bulk summarization
```

Requests are sent with:

- `max_tokens`: `AI_MAX_TOKENS` (default 8000)
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

<!-- IMAGE: Remediation detail with diff warnings banner.
     File: wiki/images/diff-warnings.png -->
![Diff security warnings](images/diff-warnings.png)
<!-- /IMAGE -->

---

## Confidence gating

Every fix returns a self-reported confidence score in `[0.0, 1.0]`. Fixes below `AI_MIN_CONFIDENCE_THRESHOLD` (default `0.7`) are tagged:

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

Select up to 20 findings on the Findings page → **Request AI Fix (Bulk)**. Nyx queues each request with its own concurrency token and processes up to `AI_MAX_CONCURRENT` in parallel. Each finding gets its own remediation record; failures do not block the batch.

<!-- IMAGE: Bulk remediation queue showing 20 in-flight requests.
     File: wiki/images/bulk-remediation.png -->
![Bulk AI fix queue](images/bulk-remediation.png)
<!-- /IMAGE -->

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

Set `AI_COST_ALERT_DAILY_USD` to trigger a notification if daily spend exceeds a threshold.

<!-- IMAGE: AI cost dashboard with trend line and top-10 table.
     File: wiki/images/ai-cost-dashboard.png -->
![AI cost dashboard](images/ai-cost-dashboard.png)
<!-- /IMAGE -->

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
