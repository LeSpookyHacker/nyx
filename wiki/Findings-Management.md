# Findings Management

How findings move through their lifecycle and every action an engineer can take on them.

---

## Lifecycle states

| State | Meaning |
|---|---|
| `OPEN` | Newly ingested, not yet acted on |
| `IN_REMEDIATION` | Work is in progress — AI fix running, PR open, or engineer assigned |
| `FIXED` | Resolved. PR merged, re-scan confirmed absence, or manually closed |
| `ACCEPTED_RISK` | Known risk, formally accepted with justification and expiry |
| `SUPPRESSED` | False positive or duplicate pattern — will not alert on repeat |
| `REVIEW_LOW_CONFIDENCE` | AI fix below confidence threshold; needs human review |
| `REVIEW_DIFF_WARNING` | AI fix flagged by diff scanner; needs human review |

State transitions are audited — `audit/verify` chain records actor, old state, new state, reason.

---

## Triage workflow

Typical path:

1. **Sort** — Findings page → sort by priority score descending
2. **Filter** — severity CRITICAL + status OPEN + scanner = all
3. **Select** — up to 20 at once
4. **Act** — one of:
   - **Request AI Fix** (single or bulk)
   - **Generate Claude Code Prompt** (let engineers fix by hand with context)
   - **Create JIRA Tickets** (bulk)
   - **Assign** to an engineer
   - **Suppress** (with reason and expiry)
   - **Accept Risk** (with justification and expiry)

<!-- IMAGE: Findings page with filters open and bulk selection active.
     File: wiki/images/triage-workflow.png -->
![Triage workflow](images/triage-workflow.png)
<!-- /IMAGE -->

---

## Assignment

Assign a finding to any engineer by email. The assignment reflects to the linked Jira ticket. Useful filters: **My Findings**, **Unassigned**, **Assigned: person@org.com**.

---

## Suppression

For confirmed false positives, click **Suppress** and supply:

- **Reason** (required, free text)
- **Pattern scope** — this finding only, same rule in same file, same rule repo-wide, same rule globally
- **Expiry** — default 180 days, configurable via `SUPPRESSION_MAX_AGE_DAYS`

Matching future findings inherit the suppression automatically but are still stored. Nothing is silently dropped — you can always list suppressed findings to audit them.

---

## Risk acceptance

For real risks you consciously choose to carry, file a **Risk Acceptance** with:

- **Business justification** — why this is acceptable
- **Compensating controls** — what mitigates it
- **Evidence URL** — link to RFC, incident, architecture doc
- **Approver** — who signed off
- **Expiry** — when it must be revisited

Accepted risks still appear on the dashboard with an **ACCEPTED_RISK** badge. Expired acceptances flip back to OPEN and fire a notification. Approvals and revocations are recorded in the audit log.

<!-- IMAGE: Risk acceptance modal filled with example data.
     File: wiki/images/risk-acceptance.png -->
![Risk acceptance modal](images/risk-acceptance.png)
<!-- /IMAGE -->

---

## Regression handling

When a previously `FIXED` finding reappears:

1. It is flagged `is_regression=True`
2. A dashboard banner surfaces the count
3. If the original had `auto_close_status` set (typically ACCEPTED_RISK or SUPPRESSED), the finding is **auto-restored** to that state and the event goes into a regression-auto-sort alert batch — no manual work
4. Otherwise it shows up as a fresh OPEN finding with the regression badge

---

## Bulk actions

The bulk action bar appears when you select 2+ findings:

- **Bulk status** — mark fixed, suppress, accept risk
- **Bulk AI fix** — queue up to 20 Claude fix requests
- **Bulk prompt** — generate a single Claude Code prompt covering all selected findings
- **Bulk JIRA** — create one ticket per finding
- **Bulk assign** — hand off a whole slice to one engineer

---

## Finding detail page

Everything you need to know about one finding:

- Vulnerable code block with syntax highlighting
- CVE / CWE / EPSS / CVSS
- Priority score breakdown (show why this is ranked where it is)
- Compliance control mappings
- Related findings (same rule, same file, cross-scanner duplicates)
- AI remediation history
- Linked Jira tickets and PRs
- Full audit trail
- Action buttons: Request AI Fix, Generate Prompt, Assign, Suppress, Accept Risk, Mark Fixed

---

## What next

- **See the remediation side of the story →** [AI Remediation](AI-Remediation.md)
- **Wire SLA policies to drive triage urgency →** [SLA Policies](SLA-Policies.md)
