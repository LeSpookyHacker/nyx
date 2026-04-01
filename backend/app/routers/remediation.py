"""Remediation API router — AI fix generation and PR management."""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus, RemediationStatus
from app.core.limiter import limiter
from app.core.security import require_scope, SCOPE_ANALYST, SCOPE_ADMIN, SCOPE_READONLY
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

            # Attempt to fetch associated test files for richer AI context (Track C)
            test_file_contents: dict[str, str] = {}
            if finding.file_path and repo:
                test_file_contents = await _fetch_test_files(
                    repo.github_full_name,
                    finding.file_path,
                    repo.default_branch,
                )

            # Generate fix with Claude
            fix_result = await ai_service.generate_fix(
                finding, file_content, engineer_context, test_file_contents
            )

            remediation.ai_explanation = fix_result.explanation
            remediation.ai_fix_diff = fix_result.fix_diff
            remediation.ai_fix_summary = fix_result.fix_summary
            remediation.ai_confidence = fix_result.confidence
            remediation.ai_model = fix_result.model
            remediation.prompt_tokens = fix_result.prompt_tokens
            remediation.completion_tokens = fix_result.completion_tokens
            remediation.ai_prompt = fix_result.fix_prompt
            remediation.ai_diff_sha256 = hashlib.sha256(fix_result.fix_diff.encode()).hexdigest()
            remediation.confidence_flagged = fix_result.confidence_flagged
            remediation.diff_warnings = json.dumps(fix_result.diff_warnings) if fix_result.diff_warnings else None
            # Place low-confidence fixes in a distinct status so engineers know to review more carefully
            if fix_result.confidence_flagged:
                remediation.status = RemediationStatus.REVIEW_LOW_CONFIDENCE.value
            else:
                remediation.status = RemediationStatus.REVIEW.value

        except Exception as e:
            remediation.status = RemediationStatus.FAILED.value
            remediation.error_message = str(e)

        await db.commit()


@router.get("", response_model=List[RemediationResponse])
async def list_remediations(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_READONLY, SCOPE_ANALYST, SCOPE_ADMIN)),
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
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """Request AI-powered fix for a finding. AI generation runs in background."""
    # Per-key daily AI cost rate limit — cap AI spend to 50 remediations per actor per day (M3)
    _AI_DAILY_LIMIT = 50
    from datetime import datetime, timedelta, timezone as _tz
    from app.models.audit_log import AuditLog as _AuditLog
    _day_start = datetime.now(_tz.utc) - timedelta(hours=24)
    _count_result = await db.execute(
        select(func.count()).select_from(_AuditLog).where(
            _AuditLog.actor == _key,
            _AuditLog.action == "remediation.requested",
            _AuditLog.created_at >= _day_start,
        )
    )
    if (_count_result.scalar_one() or 0) >= _AI_DAILY_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Daily AI remediation limit of {_AI_DAILY_LIMIT} reached for this key. Try again tomorrow.",
        )

    # Verify finding exists — load with repository for ownership audit (H6)
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
    # Include repository_id in audit trail for ownership traceability (H6)
    await log_event(db, actor=_key, action="remediation.requested", resource_type="remediation",
        resource_id=remediation.id,
        metadata={"finding_id": body.finding_id, "requested_by": body.requested_by,
                  "repository_id": finding.repository_id})
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
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return rem


@router.post("/{remediation_id}/approve", response_model=RemediationResponse)
async def approve_remediation(
    request: Request,
    remediation_id: str,
    body: RemediationApprove,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """Approve the AI-generated fix and trigger PR creation."""
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if rem.status != RemediationStatus.REVIEW.value:
        raise HTTPException(status_code=400, detail=f"Cannot approve remediation in status '{rem.status}'")

    # Auto-merge bypasses human review — restrict to admin scope only (H2)
    if body.auto_merge:
        key_scopes = set(getattr(request.state, "key_scopes", "").split(","))
        if SCOPE_ADMIN not in key_scopes:
            raise HTTPException(
                status_code=403,
                detail="auto_merge requires admin scope. Use branch protection rules for mandatory review.",
            )

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
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
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
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
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
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
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
    rem.ai_prompt = None
    rem.ai_diff_sha256 = None
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
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):  # noqa: E501
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

    from app.services.audit_service import log_event
    from app.core.security import get_client_ip
    await log_event(db, actor=_key, action="remediation.bulk_requested",
        resource_type="remediation",
        metadata={"requested_count": len(valid_findings), "skipped": skipped,
                  "requested_by": requested_by, "remediation_ids": remediation_ids},
        ip_address=get_client_ip(request))
    await db.commit()
    return {"requested": len(valid_findings), "skipped": skipped, "remediation_ids": remediation_ids}


@router.get("/{remediation_id}/pr-status")
async def get_pr_status(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_READONLY, SCOPE_ANALYST, SCOPE_ADMIN)),
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


_BLOCKED_DIFF_PATHS = (
    ".github/",
    ".gitlab-ci",
    "Makefile",
    "Dockerfile",
    "docker-compose",
    ".env",
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
)


def _validate_diff_scope(diff: str, expected_file_path: str) -> None:
    """
    Verify the AI-generated diff only modifies the expected file (H5).
    Blocks diffs that touch CI configuration, dependency files, or secrets files.
    Raises ValueError if the diff scope is outside allowed bounds.
    """
    import re as _re
    if not diff:
        return
    # Extract filenames from diff headers (--- a/path and +++ b/path)
    touched = set(_re.findall(r"^(?:---|\+\+\+) [ab]/(.+)$", diff, _re.MULTILINE))
    for path in touched:
        path_lower = path.lower()
        # Block path traversal sequences (M4)
        parts = path.replace("\\", "/").split("/")
        if ".." in parts:
            raise ValueError(
                f"AI-generated diff contains path traversal sequence in: {path!r}. Aborting PR creation."
            )
        for blocked in _BLOCKED_DIFF_PATHS:
            if path_lower.startswith(blocked.lower()) or path_lower == blocked.lower():
                raise ValueError(
                    f"AI-generated diff touches a blocked sensitive file: {path!r}. "
                    "Manual review required for changes to CI/CD, dependency, or configuration files."
                )
    if expected_file_path:
        # Normalize: strip leading slashes for comparison
        expected = expected_file_path.lstrip("/")
        for path in touched:
            normalized = path.lstrip("/")
            if normalized != expected:
                raise ValueError(
                    f"AI-generated diff touches unexpected file {path!r} "
                    f"(expected only {expected_file_path!r}). Aborting PR creation."
                )


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

            # Re-verify diff integrity before applying — detect DB tampering (H9)
            if rem.ai_diff_sha256:
                import hashlib as _hashlib
                computed_sha = _hashlib.sha256((rem.ai_fix_diff or "").encode()).hexdigest()
                if computed_sha != rem.ai_diff_sha256:
                    raise ValueError(
                        "AI diff integrity check failed — hash mismatch. "
                        "The stored diff may have been tampered with. Aborting PR creation."
                    )

            # Validate diff only touches the expected file (H5 — excessive AI agency)
            _validate_diff_scope(rem.ai_fix_diff, finding.file_path)

            # Apply the diff
            fixed_content = github_service.apply_unified_diff(file_content, rem.ai_fix_diff)
            if fixed_content is None:
                raise ValueError("Could not apply diff cleanly — the file may have changed since the fix was generated.")

            branch_name = f"nyx/fix/{rem.id[:8]}"
            # Sanitize PR title — finding.title comes from scanner output (H8)
            safe_pr_title = _sanitize_md(rem.ai_fix_summary or finding.title, 120)
            pr_title = safe_pr_title or f"fix: Nyx AI remediation {rem.id[:8]}"

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


def _sanitize_md(value: str | None, max_len: int = 500) -> str:
    """Strip markdown control sequences and limit length for PR body fields (M3)."""
    if not value:
        return ""
    # Remove backticks and pipe characters that could break table formatting
    # and newlines that could inject new table rows or headings
    safe = value.replace("`", "'").replace("|", "∣").replace("\r", "").replace("\n", " ")
    return safe[:max_len]


def _build_pr_body(finding: Finding, rem: Remediation) -> str:
    try:
        import re as _re
        _CWE_RE = _re.compile(r"^CWE-\d+$")
        cwe_list = json.loads(finding.cwe_ids or "[]")
        cwe_str = " ".join(c for c in cwe_list if isinstance(c, str) and _CWE_RE.match(c))
    except Exception:
        cwe_str = ""

    # Sanitize all scanner-sourced fields before inclusion in GitHub PR body (M3)
    safe_title = _sanitize_md(finding.title, 200)
    safe_severity = _sanitize_md(finding.severity, 20)
    safe_scanner = _sanitize_md(finding.scanner, 50)
    safe_rule_id = _sanitize_md(finding.rule_id, 100)
    safe_file = _sanitize_md(finding.file_path, 300)
    safe_line = str(finding.line_start or "")
    safe_cwe = _sanitize_md(cwe_str, 200)
    safe_explanation = _sanitize_md(rem.ai_explanation, 2000) if rem.ai_explanation else "_No explanation available._"
    safe_model = _sanitize_md(rem.ai_model, 50)

    return f"""## Nyx AI Security Remediation

> This pull request was automatically generated by Nyx, your security findings dashboard.
> **This PR requires human review before merging.** Do not enable auto-merge without reviewing the diff.

### Vulnerability Summary
| Field | Value |
|-------|-------|
| **Title** | {safe_title} |
| **Severity** | {safe_severity} |
| **Scanner** | {safe_scanner} |
| **Rule** | {safe_rule_id} |
| **File** | {safe_file}:{safe_line} |
| **CWE** | {safe_cwe} |
| **Priority Score** | {finding.priority_score:.1f}/100 |

### Explanation
{safe_explanation}

### AI Confidence
{f"{rem.ai_confidence * 100:.0f}%" if rem.ai_confidence else "N/A"}

### Review Checklist
- [ ] The fix addresses the identified vulnerability
- [ ] No unrelated logic has been changed
- [ ] Tests pass in the staging environment
- [ ] The fix does not introduce new vulnerabilities

---
Generated by Nyx AI (model: {safe_model})
"""


# ── Test file discovery helper ────────────────────────────────────────────────

async def _fetch_test_files(
    repo_full_name: str,
    source_file_path: str,
    ref: str,
    max_files: int = 2,
) -> dict[str, str]:
    """
    Try to locate and fetch test files associated with source_file_path.
    Looks for common test file naming conventions:
      - test_<filename>.py  (pytest convention)
      - <name>_test.py      (Go-style)
      - tests/<filename>.py
      - spec/<filename>.spec.ts  (JS/TS)

    Returns a dict of {filename: content}, silently ignoring fetch failures.
    """
    import os
    from app.services.github_service import get_file_content

    name = os.path.basename(source_file_path)
    stem, ext = os.path.splitext(name)
    dir_path = os.path.dirname(source_file_path)

    candidates = [
        os.path.join(dir_path, f"test_{stem}{ext}"),
        os.path.join(dir_path, f"{stem}_test{ext}"),
        os.path.join("tests", f"test_{stem}{ext}"),
        os.path.join("tests", f"{stem}_test{ext}"),
        os.path.join(dir_path, "tests", f"test_{stem}{ext}"),
        os.path.join(dir_path, "__tests__", f"{stem}.test{ext}"),
        os.path.join(dir_path, f"{stem}.spec{ext}"),
    ]

    results: dict[str, str] = {}
    for candidate in candidates:
        if len(results) >= max_files:
            break
        try:
            content = await get_file_content(repo_full_name, candidate, ref)
            results[candidate] = content
        except Exception:
            pass

    return results


# ── SSE streaming endpoint ────────────────────────────────────────────────────

@router.get("/{remediation_id}/stream")
async def stream_remediation(
    remediation_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """
    Stream AI fix generation progress as Server-Sent Events (SSE).
    Clients receive real-time chunks of the generated diff and final result.

    Returns:  text/event-stream  with JSON data payloads.
    Types: 'status' | 'diff_chunk' | 'complete' | 'error'
    """
    from fastapi.responses import StreamingResponse

    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if rem.status not in (
        RemediationStatus.PENDING.value,
        RemediationStatus.GENERATING.value,
    ):
        # Already generated — return the stored result as a single SSE event
        import json as _json

        async def _already_done():
            payload = {
                "type": "complete",
                "diff": rem.ai_fix_diff or "",
                "explanation": rem.ai_explanation or "",
                "fix_summary": rem.ai_fix_summary or "",
                "confidence": rem.ai_confidence or 0.0,
                "diff_warnings": _json.loads(rem.diff_warnings) if rem.diff_warnings else [],
                "status": rem.status,
            }
            yield f"data: {_json.dumps(payload)}\n\n"

        return StreamingResponse(_already_done(), media_type="text/event-stream")

    # Fetch finding and file content for live streaming
    finding_result = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_result.scalar_one_or_none()
    repo_result = await db.execute(
        select(Repository).where(Repository.id == finding.repository_id)
    ) if finding else None
    repo = (await repo_result).scalar_one_or_none() if repo_result else None

    file_content = ""
    if finding and finding.file_path and repo:
        try:
            from app.services import github_service as _gh
            file_content = await _gh.get_file_content(
                repo.github_full_name, finding.file_path, repo.default_branch
            )
        except Exception:
            file_content = finding.code_snippet or ""

    engineer_context = rem.engineer_context or ""

    return StreamingResponse(
        ai_service.stream_fix_generation(finding, file_content, engineer_context),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Alternative fixes endpoint ────────────────────────────────────────────────

@router.post("/{remediation_id}/alternatives")
@limiter.limit("5/minute")
async def get_alternative_fixes(
    request: Request,
    remediation_id: str,
    body: dict = None,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """
    Generate 2–3 alternative fix approaches for the same finding.
    Useful when the primary fix is rejected or has low confidence.

    Returns a list of alternative diffs with trade-off notes.
    """
    result = await db.execute(select(Remediation).where(Remediation.id == remediation_id))
    rem = result.scalar_one_or_none()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")

    finding_result = await db.execute(select(Finding).where(Finding.id == rem.finding_id))
    finding = finding_result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    repo_result = await db.execute(
        select(Repository).where(Repository.id == finding.repository_id)
    )
    repo = repo_result.scalar_one_or_none()

    file_content = ""
    if finding.file_path and repo:
        try:
            file_content = await github_service.get_file_content(
                repo.github_full_name, finding.file_path, repo.default_branch
            )
        except Exception:
            file_content = finding.code_snippet or ""

    num_alternatives = min(int((body or {}).get("num_alternatives", 3)), 5)
    engineer_context = (body or {}).get("engineer_context", rem.engineer_context or "")

    try:
        alternatives = await ai_service.generate_alternatives(
            finding, file_content, engineer_context, num_alternatives
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI alternative generation failed: {e}")

    await log_event(
        db, actor=_key, action="remediation.alternatives_requested",
        resource_type="remediation", resource_id=remediation_id,
        metadata={"num_alternatives": len(alternatives)},
    )
    await db.commit()

    return [
        {
            "approach": alt.approach,
            "explanation": alt.explanation,
            "fix_diff": alt.fix_diff,
            "confidence": alt.confidence,
            "trade_offs": alt.trade_offs,
        }
        for alt in alternatives
    ]
