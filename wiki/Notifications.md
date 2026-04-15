# Notifications

Nyx sends outbound webhook notifications for a fixed set of high-signal events. This page covers what fires, what the payloads look like, and how to wire a Slack, Teams, or generic webhook endpoint.

> **Current scope:** notifications are best-effort and delivered via a single outbound webhook. There is no built-in email/SMTP sender, no digest scheduler, and no per-event subscription model — if you need any of those, proxy through your own router (Slack workflow, Opsgenie, n8n, etc.).

---

## Events that fire

| Event | Fires when |
|---|---|
| **Regression** | A previously `FIXED` or `SUPPRESSED` finding reappears in a new scan |
| **SLA breach** | A finding's per-severity SLA window elapses without a state transition |
| **PR merged** | A remediation PR created by Nyx is merged on GitHub |
| **Critical suppression** | A CRITICAL or HIGH finding is suppressed (surfaces an audit-worthy event for security review) |

Each event is dispatched by `backend/app/services/notification_service.py` as a best-effort POST — failures are logged at `debug` level and never raise to the caller.

---

## Configuration

Only two variables govern notifications:

| Variable | Default | Purpose |
|---|---|---|
| `NOTIFICATION_WEBHOOK_URL` | _(blank)_ | The outbound webhook destination. Leave blank to disable all notifications. |
| `NOTIFY_ON_CRITICAL` | `true` | When `true`, also fire a notification for every new CRITICAL finding (on top of the events above). |

SSRF protection is on by default: the URL is resolved and any IP belonging to a private, loopback, link-local, or reserved range is rejected before the POST is issued.

---

## Wiring Slack

Create an **Incoming Webhook** in your Slack workspace (Apps → Incoming Webhooks → Add to Slack → pick a channel). Copy the generated URL and drop it in `.env`:

```bash
NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/services/T00.../B00.../xxxxxxxx
```

Nyx POSTs a simple JSON body that Slack's Incoming Webhook endpoint renders as a plain message. For richer formatting (Block Kit cards, colour-coded attachments), route through a Slack Workflow or a small adapter Lambda.

---

## Wiring Microsoft Teams

Create an **Incoming Webhook** connector on a Teams channel and paste its URL:

```bash
NOTIFICATION_WEBHOOK_URL=https://your-tenant.webhook.office.com/webhookb2/...
```

Teams accepts simple JSON bodies — the text field is rendered as the message. As with Slack, route through a flow if you want MessageCards.

---

## Wiring a generic webhook

Point the URL at any HTTPS endpoint you control — PagerDuty events API, Opsgenie, n8n, your own bot:

```bash
NOTIFICATION_WEBHOOK_URL=https://your-endpoint.example.com/nyx-hook
```

Payload shape (exact fields depend on the event, but always JSON):

```json
{
  "event": "regression",
  "finding_id": "f_01HXYZ...",
  "title": "SQL injection in get_user()",
  "severity": "CRITICAL",
  "repository": "acme-corp/backend-api"
}
```

Verify you're receiving from Nyx by pinning the source IP to your deployment, or put the endpoint behind a shared secret in the path (e.g. `…/nyx-hook/<random>`).

---

## What next

- **Full breach-response playbook →** [Security Hardening](Security.md#what-a-breach-looks-like-and-how-to-respond)
- **Configure SLA windows that drive the breach event →** [SLA Policies](SLA-Policies.md)
