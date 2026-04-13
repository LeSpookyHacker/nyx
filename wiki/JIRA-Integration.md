# JIRA Integration

Nyx can keep a JIRA ticket in lockstep with every finding — created when work starts, updated as status changes, closed when the fix PR merges. This page covers Jira Cloud; on-prem Jira Server/Data Center works but is not covered here.

---

## What the integration does

| Trigger | Jira action |
|---|---|
| New finding marked **IN_REMEDIATION** | Create ticket with severity, CVSS, description, code snippet |
| AI fix PR opened | Update ticket with PR link, set status to `In Review` |
| Fix PR merged | Transition ticket to `Done`, add closing comment |
| Finding assigned in Nyx | Update Jira assignee to matching email |
| Jira status changes to `Done` | Close finding in Nyx (bidirectional sync) |
| Risk acceptance filed | Comment on Jira with justification + expiry |
| SLA breach imminent | Raise Jira priority + comment with deadline |

---

## Prerequisites

- A Jira Cloud instance (`your-org.atlassian.net`)
- An admin user who can create an API token
- A Jira **project** where tickets will land (e.g. key `SEC`)
- The Nyx backend running and reachable

---

## 1. Create an API token

1. Go to **https://id.atlassian.com/manage-profile/security/api-tokens**
2. Click **Create API token**, name it `nyx-security-platform`
3. Copy the token — this is the only time it is shown

<!-- IMAGE: Atlassian API token page after creating the token.
     File: wiki/images/jira-api-token.png -->
![JIRA API token page](images/jira-api-token.png)
<!-- /IMAGE -->

---

## 2. Configure `.env`

```bash
JIRA_URL=https://your-org.atlassian.net
JIRA_USER_EMAIL=security-bot@your-org.com
JIRA_API_TOKEN=paste-the-token-here
JIRA_DEFAULT_PROJECT_KEY=SEC
JIRA_MOCK_MODE=false
JIRA_SYNC_INTERVAL=600
```

Restart:

```bash
./nyx.sh restart
./nyx.sh check
```

`./nyx.sh check` will hit `GET /rest/api/3/myself` with the credentials and report `jira: ok` on success.

---

## 3. Verify manually

```bash
curl -u "security-bot@your-org.com:your-api-token" \
  "https://your-org.atlassian.net/rest/api/3/myself"
```

Expected: JSON payload with the user's profile. If this fails, the integration will also fail — fix the credentials before proceeding.

---

## 4. Map projects per repository (optional)

By default every ticket lands in `JIRA_DEFAULT_PROJECT_KEY`. To route different repos to different projects, edit the repository in Nyx:

**Repositories → pick repo → Settings → JIRA Project Key**

Or via API:

```bash
curl -X PATCH "https://your-nyx-url/api/v1/repositories/$REPO_ID" \
  -H "X-API-Key: $NYX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jira_project_key": "BACKEND"}'
```

You can also route by **severity** via SLA policies — see **[SLA Policies](SLA-Policies.md)**.

<!-- IMAGE: Repository settings page with the JIRA project key field highlighted.
     File: wiki/images/jira-project-mapping.png -->
![JIRA project mapping](images/jira-project-mapping.png)
<!-- /IMAGE -->

---

## 5. Bulk ticket creation

From any repository detail page click **Create JIRA Tickets** to open one ticket per open CRITICAL and HIGH finding in that repo. Useful for onboarding a new repo into Nyx when you want an immediate ticket footprint for leadership visibility.

---

## 6. Bidirectional status sync

Every `JIRA_SYNC_INTERVAL` seconds, Nyx polls linked tickets and:

- Mirrors **status** (in progress, done, blocked) back to the finding
- Mirrors **assignee** — the email is matched to Nyx users
- Mirrors **priority** overrides if an engineer bumps Jira priority

When a Jira ticket transitions to `Done`, Nyx closes the associated finding and records the Jira transition id in the audit log.

> **Safety:** bidirectional sync is **read-only on the Jira side unless a PR is merged or a finding is fixed**. Nyx never force-closes a Jira ticket from the Nyx side without a merge event.

---

## 7. Mock mode

For testing without creating real tickets:

```bash
JIRA_MOCK_MODE=true
```

All ticket calls are logged but no HTTP request is made. Audit entries still record "would have created SEC-1234".

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `401 Unauthorized` | Wrong email/token combo | Regenerate the token |
| `403 Forbidden` on create | User cannot create issues in project | Grant **Create Issues** permission |
| Custom fields not populated | Jira field IDs differ per instance | Adjust `services/jira_service.py` field mapping |
| Tickets created twice on restart | Delivery deduplication disabled | Ensure `JIRA_DEDUP_ENABLED=true` (default) |
| Transitions fail with `400` | Target status not valid from current status | Check your Jira workflow — some projects require intermediate states |

---

## What next

- **Slack / Teams notifications →** [Notifications](Notifications.md)
- **Define SLA policies that trigger Jira priority bumps →** [SLA Policies](SLA-Policies.md)
