# Notifications

Nyx can send outbound notifications for the events that matter. This page covers what you can subscribe to, how the payloads look, and how to wire Slack, Teams, or a generic webhook.

---

## Events you can subscribe to

| Event | Fires when |
|---|---|
| `finding.critical.new` | A new CRITICAL finding is ingested |
| `finding.regression` | A previously FIXED finding reappears |
| `finding.sla_breach` | An SLA deadline is missed |
| `finding.sla_due_soon` | Finding within 25% of its SLA window |
| `remediation.low_confidence` | AI fix comes back with confidence < threshold |
| `remediation.diff_warning` | AI fix flagged by the diff scanner |
| `sbom.drift` | SBOM shows new or upgraded components |
| `ai_cost.daily_threshold` | Daily Claude spend exceeds `AI_COST_ALERT_DAILY_USD` |
| `audit.chain_invalid` | `audit/verify` detects a break |
| `integration.health.degraded` | Any integration health probe returns `error` |

Subscribe via `NOTIFICATION_CHANNELS` (comma-separated event names) in `.env`. Default is `critical,sla_breach,regression`.

---

## Slack

Create an **Incoming Webhook** in Slack and paste its URL:

```bash
NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/services/T00.../B00.../xxxxxxxx
NOTIFICATION_FORMAT=slack
```

Nyx auto-formats payloads into Slack Block Kit. Findings come through as color-coded cards with severity, title, repo, and a link back to Nyx.

<!-- IMAGE: A rich Slack card for a new critical finding.
     File: wiki/images/slack-card.png -->
![Slack notification card](images/slack-card.png)
<!-- /IMAGE -->

---

## Microsoft Teams

Create an **Incoming Webhook** on a Teams channel:

```bash
NOTIFICATION_WEBHOOK_URL=https://your-tenant.webhook.office.com/webhookb2/...
NOTIFICATION_FORMAT=teams
```

Nyx emits MessageCards compatible with the Teams connector.

---

## Generic webhook

For PagerDuty, Opsgenie, your own bot, or a custom Slack formatter:

```bash
NOTIFICATION_WEBHOOK_URL=https://your-endpoint.example.com/nyx-hook
NOTIFICATION_FORMAT=generic
```

Payload:

```json
{
  "event": "finding.critical.new",
  "timestamp": "2026-04-12T15:03:21Z",
  "data": {
    "finding_id": "f_01HXYZ...",
    "repository": "acme-corp/backend-api",
    "severity": "CRITICAL",
    "title": "SQL injection in get_user()",
    "priority_score": 94,
    "url": "https://nyx.example.com/findings/f_01HXYZ..."
  },
  "signature": "sha256=..."
}
```

The payload is signed with `NYX_WEBHOOK_SECRET`. Verify on your side:

```python
expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(f"sha256={expected}", signature)
```

---

## Daily digest

An optional once-a-day summary email/webhook covering:

- New findings in the last 24h by severity
- SLA breaches introduced
- Fixed findings
- AI spend for the day

Enable:

```bash
NOTIFICATION_DAILY_DIGEST_ENABLED=true
NOTIFICATION_DIGEST_TIME=09:00
```

---

## Email

If you set `SMTP_*` variables, Nyx can also email specific events. Useful for low-frequency critical alerts when Slack is saturated:

```bash
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USERNAME=postmaster@your-org.com
SMTP_PASSWORD=...
SMTP_FROM=nyx@your-org.com
NOTIFICATION_EMAIL_RECIPIENTS=security@your-org.com,on-call@your-org.com
```

---

## Per-event routing

Different events can go to different channels. Override `NOTIFICATION_WEBHOOK_URL` with a mapping:

```bash
NOTIFICATION_ROUTES='{"finding.critical.new": "https://hooks.slack.com/...", "audit.chain_invalid": "https://pagerduty.example.com/..."}'
```

---

## Testing

Trigger a test notification from Settings → Notifications → **Send Test**. It posts a fake `finding.critical.new` to your configured channel.

---

## What next

- **Define SLA policies that trigger notifications →** [SLA Policies](SLA-Policies.md)
