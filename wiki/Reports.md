# Reports & Analytics

Everything on the Reports page, plus what each metric actually means and how it's computed.

---

## Executive PDF

A one-click, print-ready report for leadership. Contents:

1. **Cover and summary** — org name, report window, headline KPIs
2. **Finding counts by severity** — current open, 30-day delta
3. **Priority score distribution** — histogram, 10–20 bins
4. **SLA status** — overdue, due soon, on track, broken down by repo
5. **Per-repo breakdown** — open findings, top scanners, hot spots
6. **Scanner coverage** — which scanners are configured on how many repos
7. **Compliance summary** — coverage per framework
8. **Velocity** — net-new vs fixed in the report window
9. **AI cost** — Claude spend over the window, top 5 remediations

Generate from **Reports → Executive PDF** or `GET /api/v1/reports/executive?from=2026-01-01&to=2026-04-01`.

<!-- IMAGE: First and second pages of the executive PDF side by side.
     File: wiki/images/exec-pdf-pages.png -->
![Executive PDF pages](images/exec-pdf-pages.png)
<!-- /IMAGE -->

---

## Velocity analytics

**Net-new vs fixed per day** — bar chart. Positive bars mean your backlog is growing; negative means you're winning.

**Burndown projection** — at the 7-day rolling net rate, here's when the current backlog hits zero. Not a commitment, a useful reality check.

**MTTR by severity / scanner / category** — where time actually goes. Common insight: SCA findings close fastest, SAST takes longest, IaC misconfigurations sit in limbo forever.

**Weekly trend** — 12 weeks of finding rate to catch drifts before they become problems.

<!-- IMAGE: Velocity page with the net-new chart and MTTR breakdown.
     File: wiki/images/velocity-page.png -->
![Velocity analytics](images/velocity-page.png)
<!-- /IMAGE -->

---

## AI cost dashboard

Tracks Claude API spend:

- **Total tokens** (input + output)
- **Estimated USD spend** using published Anthropic pricing
- **Daily time series** for the last 30 days
- **Top-10 most expensive remediations**
- **Per-model breakdown** if you use multiple models

Set `AI_COST_ALERT_DAILY_USD` to trigger a notification if daily spend exceeds a threshold.

<!-- IMAGE: AI cost dashboard with daily series and top 10 table.
     File: wiki/images/ai-cost.png -->
![AI cost](images/ai-cost.png)
<!-- /IMAGE -->

---

## Risk score over time

A daily snapshot worker records:

- **Per-repository risk score** — weighted average of open finding priorities
- **Organization-wide risk score** — aggregate

Rendered as line charts so you can watch risk trend over months. Drops after a big remediation push, spikes after a zero-day.

<!-- IMAGE: Risk over time chart with a visible drop after a remediation event.
     File: wiki/images/risk-over-time.png -->
![Risk over time](images/risk-over-time.png)
<!-- /IMAGE -->

---

## Hot repos

"Which repos got worse this week?" — sorted by new-finding count over the last 7 days. Good for weekly standups and resource allocation.

---

## Scanner coverage gaps

Highlights repositories with partial or missing scanner coverage. The table you want when asking "how well are we actually scanning?"

- **Stale** — no scan in > 7 days
- **Partial** — only 1–2 scanners configured
- **Unconfigured** — registered but no scans ever
- **Full** — ≥ 4 scanners and recent scans

---

## Custom reports via API

Every dashboard card is backed by a JSON endpoint under `/api/v1/dashboard/*`, `/api/v1/velocity/*`, `/api/v1/ai-costs/*`, or `/api/v1/reports/*`. You can wire them into Grafana, Looker, or a custom dashboard.

Swagger UI at `/docs` documents every endpoint with parameters and example responses.

---

## What next

- **Compliance-focused reporting →** [Compliance](Compliance.md)
- **Audit trail for investigations →** [API Reference → audit](API-Reference.md#verify-audit-chain)
