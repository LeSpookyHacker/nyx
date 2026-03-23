"""Findings API router."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus
from app.core.exceptions import FindingNotFound
from app.core.security import require_api_key
from app.database import get_db
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.suppression_pattern import SuppressionPattern
from app.schemas.finding import (
    BulkStatusUpdate,
    FindingNoteUpdate,
    FindingResponse,
    FindingStatusUpdate,
    FindingSuppressRequest,
)

router = APIRouter(prefix="/findings", tags=["findings"])

# Whitelist of sortable columns — prevents attribute enumeration via getattr
_SORT_WHITELIST = frozenset({
    "priority_score", "severity", "status", "scanner", "category",
    "first_seen_at", "last_seen_at", "cvss_score", "epss_score", "title",
})


def _build_filter_query(
    stmt,
    severity: Optional[List[str]] = None,
    scanner: Optional[List[str]] = None,
    status: Optional[List[str]] = None,
    category: Optional[List[str]] = None,
    repository_id: Optional[str] = None,
    search: Optional[str] = None,
):
    if severity:
        stmt = stmt.where(Finding.severity.in_([s.upper() for s in severity]))
    if scanner:
        stmt = stmt.where(Finding.scanner.in_([s.upper() for s in scanner]))
    if status:
        stmt = stmt.where(Finding.status.in_([s.upper() for s in status]))
    if category:
        stmt = stmt.where(Finding.category.in_([c.upper() for c in category]))
    if repository_id:
        stmt = stmt.where(Finding.repository_id == repository_id)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(like),
                Finding.description.ilike(like),
                Finding.file_path.ilike(like),
                Finding.rule_id.ilike(like),
            )
        )
    return stmt


@router.get("", response_model=dict)
async def list_findings(
    severity: Optional[List[str]] = Query(None),
    scanner: Optional[List[str]] = Query(None),
    finding_status: Optional[List[str]] = Query(None, alias="status"),
    category: Optional[List[str]] = Query(None),
    repository_id: Optional[str] = Query(None, max_length=36, pattern=r"^[0-9a-f-]{36}$"),
    search: Optional[str] = Query(None, max_length=200),
    assigned_to: Optional[str] = Query(None, max_length=255),
    is_regression: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: str = Query("priority_score"),
    sort_desc: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List findings with filtering, sorting, and pagination."""
    stmt = select(Finding)
    stmt = _build_filter_query(stmt, severity, scanner, finding_status, category, repository_id, search)
    if assigned_to:
        stmt = stmt.where(Finding.assigned_to == assigned_to)
    if is_regression is not None:
        stmt = stmt.where(Finding.is_regression == is_regression)

    # Sorting — only allow whitelisted columns to prevent attribute enumeration
    if sort_by not in _SORT_WHITELIST:
        sort_by = "priority_score"
    sort_col = getattr(Finding, sort_by)
    stmt = stmt.order_by(desc(sort_col) if sort_desc else sort_col)

    # Count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    # Paginate
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    findings = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [FindingResponse.model_validate(f).model_dump() for f in findings],
    }


@router.get("/export")
async def export_findings(
    severity: Optional[List[str]] = Query(None),
    scanner: Optional[List[str]] = Query(None),
    finding_status: Optional[List[str]] = Query(None, alias="status"),
    repository_id: Optional[str] = Query(None, max_length=36, pattern=r"^[0-9a-f-]{36}$"),
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Export findings as CSV or JSON."""
    stmt = select(Finding)
    stmt = _build_filter_query(stmt, severity, scanner, finding_status, repository_id=repository_id)
    stmt = stmt.order_by(desc(Finding.priority_score)).limit(5000)  # Cap to prevent memory exhaustion
    result = await db.execute(stmt)
    findings = result.scalars().all()

    if format == "json":
        data = [FindingResponse.model_validate(f).model_dump(mode="json") for f in findings]
        return Response(
            content=json.dumps(data, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=nyx-findings.json"},
        )

    # CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Title", "Severity", "Scanner", "Category", "File", "Line", "Status", "Priority Score", "CVE", "First Seen", "Last Seen"])
    for f in findings:
        writer.writerow([
            f.id, f.title, f.severity, f.scanner, f.category,
            f.file_path or "", f.line_start or "", f.status,
            f.priority_score, f.cve_id or "",
            f.first_seen_at.isoformat(), f.last_seen_at.isoformat(),
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=nyx-findings.csv"},
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = finding.status
    finding.status = body.status.value
    if body.notes:
        finding.notes = body.notes
    if body.status in (FindingStatus.FIXED, FindingStatus.ACCEPTED_RISK):
        finding.resolved_at = datetime.now(timezone.utc)

    # Audit log — use the hashed key identity as actor (M-6)
    db.add(AuditLog(
        actor=_key,
        action="finding.status_updated",
        resource_type="finding",
        resource_id=finding_id,
        metadata_json=json.dumps({"old_status": old_status, "new_status": body.status.value}),
    ))

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/suppress", response_model=FindingResponse)
async def suppress_finding(
    finding_id: str,
    body: FindingSuppressRequest,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus.SUPPRESSED.value
    finding.suppression_reason = body.reason
    finding.suppressed_by = "api"
    finding.suppressed_at = datetime.now(timezone.utc)
    if body.expires_days:
        finding.resolved_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    db.add(AuditLog(
        actor=_key,
        action="finding.suppressed",
        resource_type="finding",
        resource_id=finding_id,
        metadata_json=json.dumps({"reason": body.reason, "expires_days": body.expires_days}),
    ))

    # Learn suppression pattern — upsert by rule_id + scanner + repository_id
    existing_pattern = await db.execute(
        select(SuppressionPattern).where(
            SuppressionPattern.rule_id == finding.rule_id,
            SuppressionPattern.scanner == finding.scanner,
            SuppressionPattern.repository_id == finding.repository_id,
        )
    )
    pat = existing_pattern.scalar_one_or_none()
    if pat:
        pat.times_applied += 1
        pat.suppression_reason = body.reason
    else:
        db.add(SuppressionPattern(
            rule_id=finding.rule_id,
            scanner=finding.scanner,
            repository_id=finding.repository_id,
            file_path_pattern=finding.file_path,
            suppression_reason=body.reason,
            times_applied=1,
        ))

    await db.commit()
    await db.refresh(finding)
    return finding


@router.delete("/{finding_id}/suppress", response_model=FindingResponse)
async def unsuppress_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = FindingStatus.OPEN.value
    finding.suppression_reason = None
    finding.suppressed_by = None
    finding.suppressed_at = None
    finding.resolved_at = None

    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/{finding_id}/notes", response_model=FindingResponse)
async def update_notes(
    finding_id: str,
    body: FindingNoteUpdate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.notes = body.notes
    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/{finding_id}/assign", response_model=FindingResponse)
async def assign_finding(
    finding_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Assign a finding to an engineer (empty string to unassign)."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    assignee = (body.get("assignee") or "").strip()
    finding.assigned_to = assignee or None
    finding.assigned_at = datetime.now(timezone.utc) if assignee else None

    db.add(AuditLog(
        actor=_key,
        action="finding.assigned",
        resource_type="finding",
        resource_id=finding_id,
        metadata_json=json.dumps({"assignee": assignee or None}),
    ))
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/{finding_id}/suppression-suggestion")
async def get_suppression_suggestion(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Check if a suppression pattern exists for this finding's rule."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Check repo-specific first, then org-wide
    pattern = None
    for repo_filter in [finding.repository_id, None]:
        pat_result = await db.execute(
            select(SuppressionPattern).where(
                SuppressionPattern.rule_id == finding.rule_id,
                SuppressionPattern.scanner == finding.scanner,
                SuppressionPattern.repository_id == repo_filter,
            ).order_by(SuppressionPattern.times_applied.desc())
        )
        pattern = pat_result.scalar_one_or_none()
        if pattern:
            break

    # Count similar open findings
    similar_count_result = await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.rule_id == finding.rule_id,
            Finding.scanner == finding.scanner,
            Finding.repository_id == finding.repository_id,
            Finding.status == FindingStatus.OPEN.value,
            Finding.id != finding_id,
        )
    )
    similar_count = similar_count_result.scalar_one()

    return {
        "has_suggestion": pattern is not None,
        "pattern": {
            "rule_id": pattern.rule_id,
            "scanner": pattern.scanner,
            "times_applied": pattern.times_applied,
            "suppression_reason": pattern.suppression_reason,
        } if pattern else None,
        "similar_findings_count": similar_count,
    }


@router.get("/suppression-patterns")
async def list_suppression_patterns(
    scanner: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None, max_length=255),
    repository_id: Optional[str] = Query(None, max_length=36),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List learned suppression patterns ordered by times applied."""
    stmt = select(SuppressionPattern).order_by(SuppressionPattern.times_applied.desc())
    if scanner:
        stmt = stmt.where(SuppressionPattern.scanner == scanner.upper())
    if rule_id:
        stmt = stmt.where(SuppressionPattern.rule_id == rule_id)
    if repository_id:
        stmt = stmt.where(SuppressionPattern.repository_id == repository_id)
    result = await db.execute(stmt.limit(200))
    patterns = result.scalars().all()
    return [
        {
            "id": p.id,
            "rule_id": p.rule_id,
            "scanner": p.scanner,
            "file_path_pattern": p.file_path_pattern,
            "repository_id": p.repository_id,
            "suppression_reason": p.suppression_reason,
            "times_applied": p.times_applied,
            "created_by": p.created_by,
            "created_at": p.created_at,
        }
        for p in patterns
    ]


@router.post("/bulk/status")
async def bulk_update_status(
    body: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Finding).where(Finding.id.in_(body.finding_ids)))
    findings = result.scalars().all()
    now = datetime.now(timezone.utc)
    for f in findings:
        f.status = body.status.value
        if body.notes:
            f.notes = body.notes
        if body.status in (FindingStatus.FIXED, FindingStatus.ACCEPTED_RISK):
            f.resolved_at = now
    await db.commit()
    return {"updated": len(findings)}
