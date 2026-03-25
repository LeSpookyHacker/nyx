"""Remediation API router — AI fix generation and PR management."""
from __future__ import annotations

import asyncio
import json
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus, RemediationStatus
from app.core.limiter import limiter
from app.core.security import require_api_key
from app.database import get_db
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.schemas.remediation import (
    RemediationApprove,
    RemediationRegenerate,
    RemediationReject,
    RemediationRequest,
    RemediationResponse,
)
from app.services import ai_service, github_service, jira_service
from app.services.audit_service import log_event

router = APIRouter(prefix="/remediation", tags=["remediation"])


async def _run_ai_fix(remediation_id: str, finding_id: str, engineer_context: str, db_session_factory) -> None:
    """Background task: generate AI fix for a finding."""
    from app.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        # Fetch remediation and finding
        rem_result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
        remediation = rem_result.scalar_one_or_none()
        if not remediation:
            return

        finding_result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = finding_result.scalar_one_or_none()
        if not finding:
            remediation.status = RemediationStatus.FAILED.value
            remediation.error_message = "Finding not found"
            await db.commit()
            return

        repo_result = await db.execute(
            select(Repository).where(Repository.id == finding.repository_id)
        )
        repo = repo_result.scalar_one_or_none()

        remediation.status = RemediationStatus.GENERATING.value
        await db.commit()

        try:
            # Fetch file content from GitHub
            file_content = ""
            if finding.file_path and repo:
                try:
                    file_content = await github_service.get_file_content(
                        repo.github_full_name,
                        finding.file_path,
                        repo.default_branch,
                    )
                except Exception:
                    # Use stored code snippet as fallback — do not expose exception detail (H-1)
                    file_content = finding.code_snippet or "# File content unavailable"

            # Generate fix with Claude
            fix_result = await ai_service.generate_fix(finding, file_content, engineer_context)

            remediation.ai_explanation = fix_result.explanation
            remediation.ai_fix_diff = fix_result.fix_diff
            remediation.ai_fix_summary = fix_result.fix_summary
            remediation.ai_confidence = fix_result.confidence
            remediation.ai_model = fix_result.model
            remediation.prompt_tokens = fix_result.prompt_tokens
            remediation.completion_tokens = fix_result.completion_tokens
            remediation.status = RemediationStatus.REVIEW.value

        except Exception as e:
            remediation.status = RemediationStatus.FAILED.value
            remediation.error_message = str(e)

        await db.commit()


@router.get("", response_model=List[RemediationResponse])
async def list_remediations(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(
        select(Remediation).order_by(Remediation.created_at.desc())
    )
    return result.scalars().all()


@router.post("", response_model=RemediationResponse, status_code=202)
@limiter.limit("10/minute")
async def request_remediation(
    request: Request,
    body: RemediationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Request AI-powered fix for a finding. AI generation runs in background."""
    # Verify finding exists
    finding_result = await db.execute(select(Finding).where(Finding.id == body.finding_id))
    finding = finding_result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    remediation = Remediation(
        finding_id=body.finding_id,
        requested_by=body.requested_by,
        status=RemediationStatus.PENDING.value,
        engineer_context=body.engineer_context,
    )
    db.add(remediation)

    # Update finding status
    finding.status = FindingStatus.IN_REMEDIATION.value

    await db.flush()
    await log_event(db, actor=_key, action="remediation.requested", resource_type="remediation",
        resource_id=remediation.id,
        metadata={"finding_id": body.finding_id, "requested_by": body.requested_by})
    await db.commit()
    await db.refresh(remediation)

    # Kick off AI generation in background
    background_tasks.add_task(
        _run_ai_fix,
        remediation.id,
        body.finding_id,
        body.engineer_context or "",
        None,
    )

    return remediation


@router.get("/{remediation_id}", response_model=RemediationResponse)
async def get_remediation(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return rem


@router.post("/{remediation_id}/approve", response_model=RemediationResponse)
async def approve_remediation(
    remediation_id: str,
    body: RemediationApprove,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Approve the AI-generated fix and trigger PR creation."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if rem.status != RemediationStatus.REVIEW.value:
        raise HTTPException(status_code=400, detail=f"Cannot approve remediation in status '{rem.status}'")

    rem.engineer_approved = True
    rem.engineer_notes = body.engineer_notes
    rem.status = RemediationStatus.PR_CREATING.value
    await log_event(db, actor=_key, action="remediation.approved", resource_type="remediation",
        resource_id=remediation_id,
        metadata={"auto_merge": body.auto_merge, "jira_assignee": body.jira_assignee})
    await db.commit()

    # Create PR in background (optionally auto-merge)
    background_tasks.add_task(_create_pr, remediation_id, body.auto_merge, body.jira_assignee)

    await db.refresh(rem)
    return rem


@router.post("/{remediation_id}/reject", response_model=RemediationResponse)
async def reject_remediation(
    remediation_id: str,
    body: RemediationReject,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    rem.engineer_approved = False
    rem.engineer_notes = body.engineer_notes
    rem.status = RemediationStatus.REJECTED.value

    # Revert finding status to OPEN
    finding_result = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_result.scalar_one_or_none()
    if finding and finding.status == FindingStatus.IN_REMEDIATION.value:
        finding.status = FindingStatus.OPEN.value

    await log_event(db, actor=_key, action="remediation.rejected", resource_type="remediation",
        resource_id=remediation_id,
        metadata={"notes": body.engineer_notes})
    await db.commit()
    await db.refresh(rem)
    return rem


@router.delete("/{remediation_id}", status_code=204)
async def dismiss_remediation(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Dismiss (delete) a FAILED or REJECTED remediation record."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    if rem.status not in (RemediationStatus.FAILED.value, RemediationStatus.REJECTED.value):
        raise HTTPException(status_code=400, detail="Only FAILED or REJECTED remediations can be dismissed")
    await log_event(db, actor=_key, action="remediation.dismissed", resource_type="remediation",
        resource_id=remediation_id,
        metadata={"status": rem.status})
    await db.delete(rem)
    await db.commit()


@router.post("/{remediation_id}/regenerate", response_model=RemediationResponse, status_code=202)
@limiter.limit("10/minute")
async def regenerate_remediation(
    request: Request,
    remediation_id: str,
    body: RemediationRegenerate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Re-run AI fix generation with additional engineer context."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    rem.status = RemediationStatus.PENDING.value
    rem.engineer_context = body.engineer_context
    rem.ai_explanation = None
    rem.ai_fix_diff = None
    rem.error_message = None
    await log_event(db, actor=_key, action="remediation.regenerated", resource_type="remediation",
        resource_id=remediation_id,
        metadata={"context": body.engineer_context})
    await db.commit()

    background_tasks.add_task(
        _run_ai_fix, rem.id, rem.finding_id, body.engineer_context, None
    )

    await db.refresh(rem)
    return rem


@router.post("/bulk", status_code=202)
@limiter.limit("5/minute")
async def bulk_request_remediation(
    request: Request,
    body: dict,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Request AI fixes for multiple findings at once (max 20)."""
    finding_ids = body.get("finding_ids", [])
    requested_by = body.get("requested_by", "engineer")

    if not finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids is required")
    if len(finding_ids) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 findings per bulk request")

    result = await db.execute(
        select(Finding).where(
            Finding.id.in_(finding_ids),
            Finding.status == FindingStatus.OPEN.value,
        )
    )
    valid_findings = result.scalars().all()
    skipped = len(finding_ids) - len(valid_findings)
    remediation_ids = []

    for finding in valid_findings:
        rem = Remediation(
            finding_id=finding.id,
            requested_by=requested_by,
            status=RemediationStatus.PENDING.value,
        )
        db.add(rem)
        finding.status = FindingStatus.IN_REMEDIATION.value
        await db.flush()
        remediation_ids.append(rem.id)
        background_tasks.add_task(_run_ai_fix, rem.id, finding.id, "", None)

    await db.commit()
    return {"requested": len(valid_findings), "skipped": skipped, "remediation_ids": remediation_ids}


@router.get("/{remediation_id}/pr-status")
async def get_pr_status(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Poll the current PR and deployment status from GitHub."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if not rem.pr_number:
        return {"status": rem.status, "pr": None}

    # Fetch finding -> repo
    finding_result = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_result.scalar_one_or_none()
    repo_result = await db.execute(
        select(Repository).where(Repository.id == finding.repository_id)
    )
    repo = repo_result.scalar_one_or_none()

    try:
        pr_info = await github_service.get_pr_status(repo.github_full_name, rem.pr_number)
        return {"status": rem.status, "pr": pr_info}
    except Exception:
        return {"status": rem.status, "pr": None, "error": "Failed to fetch PR status from GitHub"}


async def _create_pr(remediation_id: str, auto_merge: bool = False, jira_assignee: str | None = None) -> None:
    """Background task: apply unified diff and create GitHub PR."""
    from app.database import AsyncSessionLocal
    from app.models.jira_link import JiraLink
    from datetime import datetime, timezone
    import re

    async with AsyncSessionLocal() as db:
        rem_result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
        rem = rem_result.scalar_one_or_none()
        if not rem:
            return

        finding_result = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
        finding = finding_result.scalar_one_or_none()
        repo_result = await db.execute(
            select(Repository).where(Repository.id == finding.repository_id)
        )
        repo = repo_result.scalar_one_or_none()

        try:
            # Fetch current file content
            file_content = await github_service.get_file_content(
                repo.github_full_name,
                finding.file_path,
                repo.default_branch,
            )

            # Apply the diff
            fixed_content = github_service.apply_unified_diff(file_content, rem.ai_fix_diff)
            if fixed_content is None:
                raise ValueError("Could not apply diff cleanly — the file may have changed since the fix was generated.")

            branch_name = f"nyx/fix/{rem.id[:8]}"
            pr_title = rem.ai_fix_summary or f"fix: Nyx AI remediation for {finding.title[:60]}"

            pr_body = _build_pr_body(finding, rem)

            pr_number, pr_url = await github_service.create_fix_pr(
                repo_full_name=repo.github_full_name,
                file_path=finding.file_path,
                original_content=file_content,
                fixed_content=fixed_content,
                branch_name=branch_name,
                pr_title=pr_title,
                pr_body=pr_body,
                base_branch=repo.default_branch,
            )

            rem.pr_number = pr_number
            rem.pr_url = pr_url
            rem.pr_branch = branch_name
            rem.status = RemediationStatus.PR_OPEN.value
            finding.fix_pr_url = pr_url

            # Auto-merge if requested
            if auto_merge:
                try:
                    from datetime import datetime, timezone as tz
                    merged = await github_service.merge_pr(
                        repo.github_full_name, pr_number, branch_name
                    )
                    if merged:
                        rem.status = RemediationStatus.MERGED.value
                        rem.pr_merged_at = datetime.now(tz.utc)
                        finding.status = FindingStatus.FIXED.value
                except Exception as merge_err:
                    # Merge failed (e.g. branch protection) — leave PR open, log warning
                    rem.error_message = f"PR created but auto-merge failed: {merge_err}"

            # Auto-create JIRA ticket for this AI fix
            try:
                existing_link = await db.execute(
                    select(JiraLink).where(JiraLink.finding_id == finding.id)
                )
                jira_link = existing_link.scalar_one_or_none()

                if jira_link:
                    # Ticket already exists — record its key on the remediation for reference
                    rem.jira_issue_key = jira_link.jira_issue_key
                    rem.jira_issue_url = jira_link.jira_issue_url
                else:
                    ticket = await jira_service.create_remediation_ticket(finding, rem, assignee=jira_assignee)
                    rem.jira_issue_key = ticket["key"]
                    rem.jira_issue_url = ticket["url"]
                    new_link = JiraLink(
                        finding_id=finding.id,
                        jira_issue_key=ticket["key"],
                        jira_issue_url=ticket["url"],
                        jira_project_key=(ticket["key"].rsplit("-", 1)[0] if "-" in ticket["key"] else "SEC"),
                        jira_status=ticket.get("status"),
                        jira_priority=ticket.get("priority"),
                    )
                    db.add(new_link)
            except Exception:
                # JIRA is optional — never fail PR creation because of it
                pass

        except Exception as e:
            rem.status = RemediationStatus.FAILED.value
            rem.error_message = str(e)
            finding.status = FindingStatus.OPEN.value

        await db.commit()


def _build_pr_body(finding: Finding, rem: Remediation) -> str:
    try:
        cwe_list = json.loads(finding.cwe_ids or "[]")
        cwe_str = " ".join(cwe_list)
    except Exception:
        cwe_str = finding.cwe_ids or ""

    return f"""## 🌑 Nyx AI Security Remediation

> This pull request was automatically generated by [Nyx](https://github.com/your-org/nyx), your security findings dashboard.

### Vulnerability Summary
| Field | Value |
|-------|-------|
| **Title** | {finding.title} |
| **Severity** | {finding.severity} |
| **Scanner** | {finding.scanner} |
| **Rule** | `{finding.rule_id}` |
| **File** | `{finding.file_path}:{finding.line_start}` |
| **CWE** | {cwe_str} |
| **Priority Score** | {finding.priority_score:.1f}/100 |

### Explanation
{rem.ai_explanation or '_No explanation available._'}

### AI Confidence
{f"{rem.ai_confidence * 100:.0f}%" if rem.ai_confidence else "N/A"}

### Review Checklist
- [ ] The fix addresses the identified vulnerability
- [ ] No unrelated logic has been changed
- [ ] Tests pass in the staging environment
- [ ] The fix does not introduce new vulnerabilities

---
🤖 Generated by Nyx AI (model: `{rem.ai_model}`) | [View in Dashboard]({finding.fix_pr_url or '#'})
"""
