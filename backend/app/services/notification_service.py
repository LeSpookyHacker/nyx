"""
Notification service — outbound webhook/Slack notifications.
All notifications are best-effort; failures are silently swallowed.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

from app.config import get_settings

logger = logging.getLogger("nyx.notifications")


async def notify(event_type: str, payload: Dict[str, Any]) -> None:
    """POST a JSON notification to NOTIFICATION_WEBHOOK_URL if configured."""
    settings = get_settings()
    url = settings.NOTIFICATION_WEBHOOK_URL
    if not url:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(url, json={"event": event_type, "data": payload})
    except Exception as exc:
        logger.debug("Notification delivery failed: %s", exc)


async def notify_regression(finding_id: str, title: str, severity: str, repo: str) -> None:
    await notify("finding.regression", {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "repository": repo,
        "message": f"🔁 Regression detected: [{severity}] {title} re-appeared in {repo}",
    })


async def notify_sla_breach(finding_id: str, title: str, severity: str, repo: str, days_overdue: int) -> None:
    await notify("finding.sla_breach", {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "repository": repo,
        "days_overdue": days_overdue,
        "message": f"⏰ SLA breach: [{severity}] {title} in {repo} is {days_overdue}d overdue",
    })


async def notify_pr_merged(repo: str, pr_number: int, finding_title: str) -> None:
    await notify("remediation.pr_merged", {
        "repository": repo,
        "pr_number": pr_number,
        "finding_title": finding_title,
        "message": f"✅ Fix merged: PR #{pr_number} in {repo} closed finding '{finding_title}'",
    })
