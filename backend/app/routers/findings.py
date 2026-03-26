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
    GeneratePromptRequest,
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


@router.post("/generate-claude-prompt/repository/{repo_id}")
async def generate_claude_prompt_for_repo(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Generate a Claude Code remediation prompt for all open findings in a repository."""
    from app.models.repository import Repository

    repo_result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = repo_result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    result = await db.execute(
        select(Finding).where(
            Finding.repository_id == repo_id,
            Finding.status == FindingStatus.OPEN.value,
        ).order_by(Finding.severity, Finding.priority_score.desc()).limit(100)
    )
    findings = result.scalars().all()
    if not findings:
        raise HTTPException(status_code=404, detail="No open findings for this repository")

    for f in findings:
        f.status = FindingStatus.IN_REMEDIATION.value
    await db.commit()

    repos = {repo.id: repo}
    prompt = _build_claude_prompt(findings, repos)
    return {"prompt": prompt, "updated": len(findings)}


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
    writer.writerow(["ID", "Title", "Severity", "Scanner", "Category", "File", "Line", "Status", "Priority Score", "CVE", "First Seen", "Last Seen", "Suppressed By", "Suppressed At"])
    for f in findings:
        writer.writerow([
            f.id, f.title, f.severity, f.scanner, f.category,
            f.file_path or "", f.line_start or "", f.status,
            f.priority_score, f.cve_id or "",
            f.first_seen_at.isoformat(), f.last_seen_at.isoformat(),
            f.suppressed_by or "", f.suppressed_at.isoformat() if f.suppressed_at else "",
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
    if body.status in (FindingStatus.ACCEPTED_RISK, FindingStatus.SUPPRESSED):
        finding.auto_close_status = body.status.value

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
    finding.suppressed_by = _key
    finding.suppressed_at = datetime.now(timezone.utc)
    finding.auto_close_status = FindingStatus.SUPPRESSED.value
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

    old_suppressed_by = finding.suppressed_by
    finding.status = FindingStatus.OPEN.value
    finding.suppression_reason = None
    finding.suppressed_by = None
    finding.suppressed_at = None
    finding.resolved_at = None

    db.add(AuditLog(
        actor=_key,
        action="finding.unsuppressed",
        resource_type="finding",
        resource_id=finding_id,
        metadata_json=json.dumps({"previously_suppressed_by": old_suppressed_by}),
    ))

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


@router.post("/generate-claude-prompt")
async def generate_claude_prompt(
    body: GeneratePromptRequest,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Generate a Claude Code remediation prompt for selected findings.
    Marks each finding as IN_REMEDIATION and returns a ready-to-paste prompt.
    """
    from app.models.repository import Repository

    result = await db.execute(
        select(Finding).where(Finding.id.in_(body.finding_ids))
    )
    findings = result.scalars().all()
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found for the given IDs")

    # Fetch repo names
    repo_ids = list({f.repository_id for f in findings})
    repos_result = await db.execute(select(Repository).where(Repository.id.in_(repo_ids)))
    repos = {r.id: r for r in repos_result.scalars().all()}

    # Mark as IN_REMEDIATION
    now = datetime.now(timezone.utc)
    for f in findings:
        if f.status == FindingStatus.OPEN.value:
            f.status = FindingStatus.IN_REMEDIATION.value
    await db.commit()

    # Build the prompt
    prompt = _build_claude_prompt(findings, repos)
    return {"prompt": prompt, "updated": len([f for f in findings if f.status == FindingStatus.IN_REMEDIATION.value])}


def _build_claude_prompt(findings, repos: dict) -> str:
    """Generate a structured Claude Code remediation prompt."""
    # Group findings by scanner category
    SCA_SCANNERS = {"TRIVY", "SNYK", "DEPENDABOT", "GRYPE"}
    SAST_SCANNERS = {"SEMGREP", "CODEQL", "BANDIT", "CODE_SCANNING"}
    SECRET_SCANNERS = {"GITLEAKS"}
    IAC_SCANNERS = {"HADOLINT", "CHECKOV"}
    DAST_SCANNERS = {"ZAP"}

    sca, sast, secrets, iac, dast, other = [], [], [], [], [], []
    for f in findings:
        s = f.scanner.upper()
        if s in SCA_SCANNERS:       sca.append(f)
        elif s in SAST_SCANNERS:    sast.append(f)
        elif s in SECRET_SCANNERS:  secrets.append(f)
        elif s in IAC_SCANNERS:     iac.append(f)
        elif s in DAST_SCANNERS:    dast.append(f)
        else:                        other.append(f)

    repo_names = sorted({repos[f.repository_id].github_full_name for f in findings if f.repository_id in repos})
    repo_str = ", ".join(repo_names) if repo_names else "this repository"
    total = len(findings)

    lines = []
    lines.append(f"# Security Remediation Task — {total} Finding{'s' if total != 1 else ''}")
    lines.append(f"\nYou are helping remediate **{total} security finding{'s' if total != 1 else ''}** identified by Nyx in **{repo_str}**.")
    lines.append("\nWork through each finding below in order. For every fix:")
    lines.append("1. Read the affected file(s) first to understand context")
    lines.append("2. Implement the minimal change needed to address the finding")
    lines.append("3. Show a diff of exactly what you changed")
    lines.append("4. Do not refactor or change unrelated code")
    lines.append("\nAfter completing all findings, output the **Completion Report** described at the bottom.\n")
    lines.append("---\n")

    finding_num = 0

    def _fmt_finding(f, category_hint: str) -> list:
        nonlocal finding_num
        finding_num += 1
        repo = repos.get(f.repository_id)
        repo_name = repo.github_full_name if repo else f.repository_id

        out = [f"## Finding {finding_num} — [{f.severity}] {f.title}"]
        out.append(f"\n| Field | Value |")
        out.append(f"|-------|-------|")
        out.append(f"| Repository | `{repo_name}` |")
        out.append(f"| Scanner | {f.scanner} |")
        out.append(f"| Rule | `{f.rule_id}` |")
        out.append(f"| Severity | **{f.severity}** |")
        out.append(f"| Category | {f.category or category_hint} |")
        if f.cve_id:
            out.append(f"| CVE | [{f.cve_id}](https://nvd.nist.gov/vuln/detail/{f.cve_id}) |")
        if f.cvss_score:
            out.append(f"| CVSS | {f.cvss_score} |")
        if f.file_path:
            loc = f.file_path
            if f.line_start:
                loc += f":{f.line_start}"
                if f.line_end and f.line_end != f.line_start:
                    loc += f"–{f.line_end}"
            out.append(f"| Location | `{loc}` |")
        out.append("")
        if f.description:
            out.append(f"**Description:** {f.description}\n")
        if f.code_snippet:
            out.append(f"**Affected code:**\n```\n{f.code_snippet}\n```\n")
        if f.remediation_guidance:
            out.append(f"**Remediation:** {f.remediation_guidance}\n")
        return out

    if sca:
        lines.append("## Dependency Vulnerabilities (SCA)\n")
        lines.append("These require package version updates. For each finding:")
        lines.append("- Update the package to the fixed version in the manifest (`package.json`, `requirements.txt`, `go.mod`, `Gemfile`, `pom.xml`, etc.)")
        lines.append("- Run the appropriate package manager to regenerate the lock file")
        lines.append("- If no fix version exists, document it in the completion report\n")
        for f in sorted(sca, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity) if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
            lines.extend(_fmt_finding(f, "SCA"))
            lines.append("")

    if sast:
        lines.append("## Code Vulnerabilities (SAST)\n")
        lines.append("These require code changes at the specific file and line numbers indicated.")
        lines.append("Read the file first, fix only the flagged issue, then show the diff.\n")
        for f in sorted(sast, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity) if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
            lines.extend(_fmt_finding(f, "SAST"))
            lines.append("")

    if iac:
        lines.append("## Infrastructure-as-Code Issues (IaC)\n")
        lines.append("These are Dockerfile or configuration linting issues. Fix the flagged instruction.\n")
        for f in sorted(iac, key=lambda x: x.severity):
            lines.extend(_fmt_finding(f, "IAC"))
            lines.append("")

    if dast:
        lines.append("## Web Application Issues (DAST)\n")
        lines.append("These are runtime security issues found by scanning the live app.")
        lines.append("Fix the missing headers, cookie flags, or other server-side configuration in the web server or application code.\n")
        for f in sorted(dast, key=lambda x: x.severity):
            lines.extend(_fmt_finding(f, "DAST"))
            lines.append("")

    if secrets:
        lines.append("## Exposed Secrets\n")
        lines.append("> **IMPORTANT:** Do NOT commit the secret value in any fix. The correct remediation is:")
        lines.append("> 1. Revoke/rotate the secret immediately in the relevant service")
        lines.append("> 2. Remove the secret from the file and replace with an environment variable reference")
        lines.append("> 3. If the secret is in git history, document it — history scrubbing requires `git filter-repo` and a force-push\n")
        for f in secrets:
            lines.extend(_fmt_finding(f, "SECRETS"))
            lines.append("")

    if other:
        lines.append("## Other Findings\n")
        for f in other:
            lines.extend(_fmt_finding(f, "OTHER"))
            lines.append("")

    lines.append("---\n")
    lines.append("## Completion Report\n")
    lines.append("After finishing all fixes above, output a report in this exact format:\n")
    lines.append("```")
    lines.append("REMEDIATION COMPLETION REPORT")
    lines.append("=" * 40)
    lines.append(f"Repository: {repo_str}")
    lines.append(f"Total findings addressed: {total}")
    lines.append("")
    lines.append("FINDINGS STATUS:")
    for i, f in enumerate(findings, 1):
        lines.append(f"  [{i}] {f.severity} — {f.title[:60]}")
        lines.append(f"      Status: [FIXED | PARTIALLY FIXED | SKIPPED — reason]")
    lines.append("")
    lines.append("FILES CHANGED:")
    lines.append("  - [list each file you modified]")
    lines.append("")
    lines.append("COMMANDS RUN:")
    lines.append("  - [list any package manager or shell commands executed]")
    lines.append("")
    lines.append("FINDINGS THAT COULD NOT BE AUTO-FIXED:")
    lines.append("  - [list any findings requiring manual action and why]")
    lines.append("")
    lines.append("NEXT STEPS:")
    lines.append("  - [any follow-up actions the engineer should take]")
    lines.append("```")

    return "\n".join(lines)


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
        old_status = f.status
        f.status = body.status.value
        if body.notes:
            f.notes = body.notes
        if body.status in (FindingStatus.FIXED, FindingStatus.ACCEPTED_RISK):
            f.resolved_at = now
        if body.status in (FindingStatus.ACCEPTED_RISK, FindingStatus.SUPPRESSED):
            f.auto_close_status = body.status.value
        db.add(AuditLog(
            actor=_key,
            action="finding.bulk_status_update",
            resource_type="finding",
            resource_id=f.id,
            metadata_json=json.dumps({"old_status": old_status, "new_status": body.status.value}),
        ))
    await db.commit()
    return {"updated": len(findings)}
