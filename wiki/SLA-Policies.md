# SLA Policies

Service Level Agreements translate "we should fix criticals fast" into hard deadlines, escalations, and reports leadership can act on.

---

## What an SLA policy is

A policy binds:

- **A scope** — all repos, a specific repo, a tag, or a pattern
- **Per-severity deadlines** — how many days until a finding of each severity is considered overdue
- **Escalation channels** — Slack, Teams, JIRA priority bumps, email
- **A default Jira project** — override `JIRA_DEFAULT_PROJECT_KEY` for matching findings

---

## Creating a policy

Dashboard → **SLA Policies** → **Add Policy**.

| Field | Example |
|---|---|
| Name | `backend-critical-infra` |
| Scope | Repository tag: `tier:critical` |
| Critical deadline | 3 days |
| High deadline | 7 days |
| Medium deadline | 30 days |
| Low deadline | 90 days |
| Escalation webhook | `https://hooks.slack.com/services/...` |
| Jira project override | `PROD` |

<!-- IMAGE: SLA policy creation form filled with the example above.
     File: wiki/images/sla-create.png -->
![SLA policy creation](images/sla-create.png)
<!-- /IMAGE -->

---

## How deadlines are computed

On every finding ingest:

1. Nyx resolves the **most specific** policy that matches the repo (more specific scopes win).
2. Takes the per-severity deadline from that policy.
3. Computes `sla_deadline = ingestion_time + deadline`.
4. Stores on the finding. The dashboard uses this for "overdue", "due soon", and "on track" buckets.

The deadline is **immutable** — fixing a bug in the policy doesn't retroactively shift existing deadlines. Re-issue affected findings if needed.

---

## The hourly checker

The SLA checker worker runs every `SLA_CHECK_INTERVAL` seconds (default hourly). For each open finding:

- **Overdue** — fires an escalation once per breach event, then once per 24h until fixed
- **Due soon (< 25 % of window remaining)** — a single warning notification
- **On track** — no action

Escalations go to the channels listed on the policy.

---

## Escalation channels

### Slack / Teams / generic webhook
Outgoing POST to the webhook URL with a JSON payload describing the finding. See **[Notifications](Notifications.md)** for the payload shape.

### JIRA priority bump
When enabled, a breach raises the linked Jira ticket's priority to `Highest` and adds a comment with the breach delta.

### Email
If `SMTP_*` variables are set in `.env`, escalations can email the finding's assignee or a fixed distribution list.

---

## Reading SLA status from the dashboard

The dashboard **SLA Status** card breaks findings into three buckets:

- **Overdue** — past deadline, work is late
- **Due soon** — within 25 % of the window
- **On track** — rest

Click any bucket to open the Findings page pre-filtered to that slice.

<!-- IMAGE: SLA status card with counts in all three buckets.
     File: wiki/images/sla-status-card.png -->
![SLA status card](images/sla-status-card.png)
<!-- /IMAGE -->

---

## Reporting

The **Executive PDF** report includes an SLA section broken down by repo and severity. Velocity analytics also shows breach rate over time — see [Reports & Analytics](Reports.md).

---

## What next

- **Define custom notification channels →** [Notifications](Notifications.md)
- **See breach history in the executive report →** [Reports & Analytics](Reports.md)
