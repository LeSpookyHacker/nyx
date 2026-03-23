"""JIRA integration API."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key
from app.database import get_db
from app.models.finding import Finding
from app.models.jira_link import JiraLink
from app.services import jira_service

router = APIRouter(prefix="/jira", tags=["jira"])

# JIRA project keys: 2-10 uppercase alphanumerics, starting with a letter (H-6)
_JIRA_KEY_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}$")


def _validate_project_key(v: Optional[str]) -> Optional[str]:
    if v is not None and not _JIRA_KEY_RE.match(v):
        raise ValueError("project_key must be 2–10 uppercase alphanumeric characters starting with a letter")
    return v


class CreateTicketRequest(BaseModel):
    project_key: Optional[str] = None

    @field_validator("project_key")
    @classmethod
    def validate_key(cls, v: Optional[str]) -> Optional[str]:
        return _validate_project_key(v)


# ── Connection / meta ─────────────────────────────────────────────────────────

@router.get("/health")
async def jira_health(_key: str = Depends(require_api_key)):
    """Test JIRA connectivity and return current mode (real / mock)."""
    return await jira_service.test_connection()


@router.get("/projects")
async def list_projects(_key: str = Depends(require_api_key)):
    """List accessible JIRA projects."""
    try:
        return await jira_service.list_projects()
    except ValueError:
        raise HTTPException(status_code=400, detail="Failed to retrieve JIRA projects")


# ── Per-finding ticket management ─────────────────────────────────────────────

@router.get("/findings/{finding_id}/ticket")
async def get_ticket(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Return the linked JIRA ticket for a finding, or 404 if none."""
    link_result = await db.execute(
        select(JiraLink).where(JiraLink.finding_id == finding_id)
    )
    link = link_result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=404, detail="No JIRA ticket linked to this finding")
    return _link_response(link)


@router.post("/findings/{finding_id}/ticket", status_code=201)
async def create_ticket(
    finding_id: str,
    body: CreateTicketRequest,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Create a JIRA ticket for the finding and link it."""
    # Get finding
    finding_result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = finding_result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Check not already linked
    existing_result = await db.execute(
        select(JiraLink).where(JiraLink.finding_id == finding_id)
    )
    if existing_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Finding already has a linked JIRA ticket")

    try:
        ticket = await jira_service.create_jira_ticket(finding, body.project_key)
    except (ValueError, Exception):
        raise HTTPException(status_code=400, detail="Failed to create JIRA ticket")

    link = JiraLink(
        finding_id=finding_id,
        jira_issue_key=ticket["key"],
        jira_issue_url=ticket["url"],
        jira_project_key=(body.project_key or ticket["key"].split("-")[0]).upper(),
        jira_status=ticket.get("status"),
        jira_priority=ticket.get("priority"),
        jira_assignee=ticket.get("assignee"),
        synced_at=datetime.now(timezone.utc),
    )
    db.add(link)
    await db.commit()
    await db.refresh(link)
    return _link_response(link)


@router.post("/findings/{finding_id}/sync")
async def sync_ticket(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Pull latest status from JIRA and update the link.
    If the JIRA ticket is Done/Closed/Resolved, mark the finding FIXED.
    """
    link_result = await db.execute(
        select(JiraLink).where(JiraLink.finding_id == finding_id)
    )
    link = link_result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=404, detail="No JIRA ticket linked to this finding")

    try:
        ticket = await jira_service.get_jira_ticket(link.jira_issue_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to sync JIRA ticket")

    link.jira_status = ticket.get("status")
    link.jira_assignee = ticket.get("assignee")
    link.jira_priority = ticket.get("priority")
    link.synced_at = datetime.now(timezone.utc)

    # Auto-resolve finding when JIRA ticket is closed
    done_statuses = {"done", "closed", "resolved", "complete", "won't fix"}
    if (ticket.get("status") or "").lower() in done_statuses:
        finding_result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = finding_result.scalar_one_or_none()
        if finding and finding.status == "OPEN":
            from app.core.constants import FindingStatus
            finding.status = FindingStatus.FIXED.value
            finding.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    return _link_response(link)


@router.delete("/findings/{finding_id}/ticket", status_code=204)
async def unlink_ticket(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Remove the JIRA link from a finding (does not delete the JIRA ticket)."""
    link_result = await db.execute(
        select(JiraLink).where(JiraLink.finding_id == finding_id)
    )
    link = link_result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=404, detail="No JIRA ticket linked to this finding")
    await db.delete(link)
    await db.commit()


# ── Repository-scoped bulk operations ─────────────────────────────────────────

class BulkTicketRequest(BaseModel):
    project_key: Optional[str] = None
    severities: list[str] = ["CRITICAL", "HIGH"]

    @field_validator("project_key")
    @classmethod
    def validate_key(cls, v: Optional[str]) -> Optional[str]:
        return _validate_project_key(v)


@router.get("/repositories/{repo_id}/tickets")
async def list_repo_tickets(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List all JIRA-linked findings for a repository."""
    result = await db.execute(
        select(Finding, JiraLink)
        .join(JiraLink, JiraLink.finding_id == Finding.id)
        .where(Finding.repository_id == repo_id)
        .order_by(Finding.priority_score.desc())
    )
    rows = result.all()
    return [
        {
            **_link_response(link),
            "finding_title": finding.title,
            "finding_severity": finding.severity,
            "finding_status": finding.status,
            "finding_priority_score": finding.priority_score,
        }
        for finding, link in rows
    ]


@router.post("/repositories/{repo_id}/bulk-tickets")
async def bulk_create_tickets(
    repo_id: str,
    body: BulkTicketRequest,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Create JIRA tickets for all open findings in a repository that
    match the requested severities and don't already have a ticket.
    """
    severities_upper = [s.upper() for s in body.severities]
    findings_result = await db.execute(
        select(Finding).where(
            Finding.repository_id == repo_id,
            Finding.status == "OPEN",
            Finding.severity.in_(severities_upper),
        ).order_by(Finding.priority_score.desc())
    )
    findings = findings_result.scalars().all()

    created, skipped, failed = [], [], []

    for finding in findings:
        # Skip if already linked
        existing = await db.execute(
            select(JiraLink).where(JiraLink.finding_id == finding.id)
        )
        if existing.scalar_one_or_none():
            skipped.append(finding.id)
            continue

        try:
            ticket = await jira_service.create_jira_ticket(finding, body.project_key)
            link = JiraLink(
                finding_id=finding.id,
                jira_issue_key=ticket["key"],
                jira_issue_url=ticket["url"],
                jira_project_key=(body.project_key or ticket["key"].split("-")[0]).upper(),
                jira_status=ticket.get("status"),
                jira_priority=ticket.get("priority"),
                jira_assignee=ticket.get("assignee"),
                synced_at=datetime.now(timezone.utc),
            )
            db.add(link)
            await db.commit()
            created.append({"finding_id": finding.id, "ticket": ticket["key"]})
        except Exception:
            await db.rollback()
            failed.append({"finding_id": finding.id, "error": "Failed to create JIRA ticket"})

    return {
        "created": len(created),
        "skipped": len(skipped),
        "failed": len(failed),
        "tickets": created,
    }


def _link_response(link: JiraLink) -> dict:
    return {
        "finding_id": link.finding_id,
        "jira_issue_key": link.jira_issue_key,
        "jira_issue_url": link.jira_issue_url,
        "jira_project_key": link.jira_project_key,
        "jira_status": link.jira_status,
        "jira_priority": link.jira_priority,
        "jira_assignee": link.jira_assignee,
        "synced_at": link.synced_at.isoformat() if link.synced_at else None,
        "created_at": link.created_at.isoformat() if link.created_at else None,
    }
