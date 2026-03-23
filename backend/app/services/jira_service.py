"""
JIRA integration service.

Supports two modes:
  - Real mode:  connects to Atlassian Cloud via REST API v3 (email + API token)
  - Mock mode:  JIRA_MOCK_MODE=true — returns realistic fake data, no credentials needed

Real setup:
  1. Create an API token at https://id.atlassian.com/manage-profile/security/api-tokens
  2. Set JIRA_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN in .env
  3. Set JIRA_DEFAULT_PROJECT_KEY to your project key (e.g. "SEC")
"""
from __future__ import annotations

import random
import string
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_settings

# Map Nyx severity → JIRA priority name
_SEVERITY_TO_PRIORITY = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
}

_MOCK_STATUSES = ["To Do", "In Progress", "In Review", "Done"]
_MOCK_ASSIGNEES = ["alice@example.com", "bob@example.com", "carol@example.com", None]


def _mock_issue_key(project_key: str) -> str:
    num = random.randint(10, 999)
    return f"{project_key}-{num}"


def _adf_doc(*paragraphs: str) -> Dict[str, Any]:
    """Build a minimal Atlassian Document Format body."""
    content = []
    for text in paragraphs:
        if not text:
            continue
        content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": text}],
        })
    return {"version": 1, "type": "doc", "content": content}


def _build_description(finding: Any) -> Dict[str, Any]:
    parts = []
    if finding.description:
        parts.append(finding.description)

    if finding.file_path:
        loc = f"Location: {finding.file_path}"
        if finding.line_start:
            loc += f" (line {finding.line_start})"
        parts.append(loc)

    if finding.rule_id:
        parts.append(f"Rule: {finding.rule_id}  |  Scanner: {finding.scanner}")

    if finding.cve_id:
        parts.append(f"CVE: {finding.cve_id}")

    if finding.remediation_guidance:
        parts.append(f"Remediation: {finding.remediation_guidance}")

    parts.append(f"Nyx finding ID: {finding.id}")
    return _adf_doc(*parts)


def _build_summary(finding: Any) -> str:
    loc = finding.file_path or finding.url or finding.scanner
    return f"[{finding.severity}] {finding.title} — {loc}"[:255]


async def create_jira_ticket(
    finding: Any,
    project_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a JIRA issue for the given Finding.
    Returns dict with: key, url, status, priority, assignee
    """
    settings = get_settings()
    pk = (project_key or settings.JIRA_DEFAULT_PROJECT_KEY or "SEC").upper()

    if settings.JIRA_MOCK_MODE:
        key = _mock_issue_key(pk)
        base = settings.JIRA_URL or "https://mock-jira.example.com"
        return {
            "key": key,
            "url": f"{base.rstrip('/')}/browse/{key}",
            "status": "To Do",
            "priority": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium"),
            "assignee": None,
        }

    _require_config(settings)

    payload = {
        "fields": {
            "project": {"key": pk},
            "summary": _build_summary(finding),
            "description": _build_description(finding),
            "issuetype": {"name": settings.JIRA_ISSUE_TYPE or "Bug"},
            "priority": {"name": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium")},
            "labels": ["nyx-security", finding.scanner.lower(), finding.severity.lower()],
        }
    }

    async with _client(settings) as c:
        resp = await c.post("/rest/api/3/issue", json=payload)
        resp.raise_for_status()
        data = resp.json()

    key = data["key"]
    return {
        "key": key,
        "url": f"{settings.JIRA_URL.rstrip('/')}/browse/{key}",
        "status": "To Do",
        "priority": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium"),
        "assignee": None,
    }


async def create_remediation_ticket(
    finding: Any,
    remediation: Any,
    project_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a JIRA issue that records an AI-generated fix and its PR.
    Returns dict with: key, url, status, priority, assignee
    """
    settings = get_settings()
    pk = (project_key or settings.JIRA_DEFAULT_PROJECT_KEY or "SEC").upper()

    if settings.JIRA_MOCK_MODE:
        key = _mock_issue_key(pk)
        base = settings.JIRA_URL or "https://mock-jira.example.com"
        return {
            "key": key,
            "url": f"{base.rstrip('/')}/browse/{key}",
            "status": "To Do",
            "priority": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium"),
            "assignee": None,
        }

    _require_config(settings)

    summary = f"[AI Fix Applied] [{finding.severity}] {finding.title}"[:255]
    description = _build_remediation_description(finding, remediation)

    payload = {
        "fields": {
            "project": {"key": pk},
            "summary": summary,
            "description": description,
            "issuetype": {"name": settings.JIRA_ISSUE_TYPE or "Bug"},
            "priority": {"name": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium")},
            "labels": ["nyx-security", "nyx-ai-fix", finding.scanner.lower(), finding.severity.lower()],
        }
    }

    async with _client(settings) as c:
        resp = await c.post("/rest/api/3/issue", json=payload)
        resp.raise_for_status()
        data = resp.json()

    key = data["key"]
    return {
        "key": key,
        "url": f"{settings.JIRA_URL.rstrip('/')}/browse/{key}",
        "status": "To Do",
        "priority": _SEVERITY_TO_PRIORITY.get(finding.severity, "Medium"),
        "assignee": None,
    }


def _build_remediation_description(finding: Any, remediation: Any) -> Dict[str, Any]:
    """Build an ADF description that includes finding details + AI fix info."""
    parts: List[str] = []

    parts.append("An AI-generated fix has been applied to the following security finding.")

    # Finding summary
    loc = finding.file_path or finding.url or ""
    if loc and finding.line_start:
        loc = f"{loc} (line {finding.line_start})"
    if loc:
        parts.append(f"Location: {loc}")
    if finding.rule_id:
        parts.append(f"Rule: {finding.rule_id}  |  Scanner: {finding.scanner}  |  Severity: {finding.severity}")
    if finding.cve_id:
        parts.append(f"CVE: {finding.cve_id}")
    parts.append(f"Priority Score: {finding.priority_score:.1f}/100")
    if finding.description:
        parts.append(f"Description: {finding.description}")

    # AI fix details
    if remediation.ai_explanation:
        parts.append(f"AI Explanation: {remediation.ai_explanation[:1000]}")
    if remediation.ai_confidence is not None:
        parts.append(f"AI Confidence: {remediation.ai_confidence * 100:.0f}%")
    if remediation.ai_model:
        parts.append(f"AI Model: {remediation.ai_model}")
    if remediation.engineer_notes:
        parts.append(f"Engineer Notes: {remediation.engineer_notes}")

    # PR link
    if remediation.pr_url:
        parts.append(f"Pull Request: {remediation.pr_url}")

    parts.append(f"Nyx finding ID: {finding.id}")
    return _adf_doc(*parts)


async def get_jira_ticket(issue_key: str) -> Dict[str, Any]:
    """Fetch current state of a JIRA issue."""
    settings = get_settings()

    if settings.JIRA_MOCK_MODE:
        return {
            "key": issue_key,
            "url": f"{settings.JIRA_URL or 'https://mock-jira.example.com'}/browse/{issue_key}",
            "status": random.choice(_MOCK_STATUSES),
            "priority": random.choice(list(_SEVERITY_TO_PRIORITY.values())),
            "assignee": random.choice(_MOCK_ASSIGNEES),
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

    _require_config(settings)
    async with _client(settings) as c:
        resp = await c.get(
            f"/rest/api/3/issue/{issue_key}",
            params={"fields": "status,priority,assignee"},
        )
        resp.raise_for_status()
        data = resp.json()

    fields = data.get("fields", {})
    assignee = fields.get("assignee")
    return {
        "key": issue_key,
        "url": f"{settings.JIRA_URL.rstrip('/')}/browse/{issue_key}",
        "status": fields.get("status", {}).get("name"),
        "priority": fields.get("priority", {}).get("name"),
        "assignee": assignee.get("emailAddress") if assignee else None,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }


async def list_projects() -> List[Dict[str, Any]]:
    """Return list of accessible JIRA projects."""
    settings = get_settings()

    if settings.JIRA_MOCK_MODE:
        return [
            {"key": "SEC", "name": "Security", "type": "software"},
            {"key": "OPS", "name": "Operations", "type": "software"},
            {"key": "PLAT", "name": "Platform", "type": "software"},
        ]

    _require_config(settings)
    async with _client(settings) as c:
        resp = await c.get("/rest/api/3/project/search", params={"maxResults": 50})
        resp.raise_for_status()
        data = resp.json()

    return [
        {"key": p["key"], "name": p["name"], "type": p.get("projectTypeKey", "")}
        for p in data.get("values", [])
    ]


async def test_connection() -> Dict[str, Any]:
    """Verify JIRA credentials and connectivity."""
    settings = get_settings()

    if settings.JIRA_MOCK_MODE:
        return {"ok": True, "mode": "mock", "user": "mock@example.com", "url": settings.JIRA_URL or "mock"}

    if not settings.JIRA_URL:
        return {"ok": False, "mode": "real", "error": "JIRA_URL not configured"}

    try:
        _require_config(settings)
        async with _client(settings) as c:
            resp = await c.get("/rest/api/3/myself")
            resp.raise_for_status()
            data = resp.json()
        return {"ok": True, "mode": "real", "user": data.get("emailAddress"), "url": settings.JIRA_URL}
    except Exception as e:
        return {"ok": False, "mode": "real", "error": str(e)}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _require_config(settings: Any) -> None:
    missing = [k for k in ("JIRA_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN") if not getattr(settings, k)]
    if missing:
        raise ValueError(f"JIRA not configured. Missing: {', '.join(missing)}")


def _client(settings: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=settings.JIRA_URL,
        auth=(settings.JIRA_USER_EMAIL, settings.JIRA_API_TOKEN),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=15.0,
    )
