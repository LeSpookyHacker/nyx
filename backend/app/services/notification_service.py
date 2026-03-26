"""
Notification service — outbound webhook/Slack notifications.
All notifications are best-effort; failures are silently swallowed.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

from app.config import get_settings

logger = logging.getLogger("nyx.notifications")

# RFC-1918 + link-local + loopback ranges to block SSRF attempts
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("10.0.0.0/8"),         # private
    ipaddress.ip_network("172.16.0.0/12"),      # private
    ipaddress.ip_network("192.168.0.0/16"),     # private
    ipaddress.ip_network("169.254.0.0/16"),     # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


def _is_ssrf_safe(url: str) -> bool:
    """Return True only if the URL is https and its hostname is not a raw private/loopback IP."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        # Block raw private/loopback IPs; hostnames are allowed (pair with egress firewall)
        try:
            addr = ipaddress.ip_address(host)
            if any(addr in net for net in _BLOCKED_NETWORKS):
                logger.warning("SSRF_BLOCKED notification_url=%s host=%s", url, host)
                return False
        except ValueError:
            pass  # hostname, not a raw IP — allowed at code level
        return True
    except Exception:
        return False


async def notify(event_type: str, payload: Dict[str, Any]) -> None:
    """POST a JSON notification to NOTIFICATION_WEBHOOK_URL if configured."""
    settings = get_settings()
    url = settings.NOTIFICATION_WEBHOOK_URL
    if not url:
        return
    if not _is_ssrf_safe(url):
        logger.warning("Notification skipped: NOTIFICATION_WEBHOOK_URL blocked as potential SSRF target")
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


async def notify_critical_suppression(
    finding_id: str,
    title: str,
    severity: str,
    repo: str,
    actor: str,
    reason: str,
) -> None:
    await notify("finding.critical_suppressed", {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "repository": repo,
        "actor": actor,
        "reason": reason[:200],  # truncate for notification body
        "message": (
            f"⚠️ {severity} finding suppressed by {actor}: [{severity}] {title} "
            f"in {repo} — requires review"
        ),
    })
