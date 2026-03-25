"""Dashboard API router — aggregated stats and trend data."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus, Severity
from app.core.security import require_api_key
from app.database import get_db
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
async def get_summary(
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Counts by severity, scanner, status, and category."""
    base = select(Finding)
    if repository_id:
        base = base.where(Finding.repository_id == repository_id)

    # Open findings by severity
    severity_counts = {}
    for sev in Severity:
        result = await db.execute(
            base.where(
                Finding.severity == sev.value,
                Finding.status == FindingStatus.OPEN.value,
            ).with_only_columns(func.count())
        )
        severity_counts[sev.value.lower()] = result.scalar_one()

    # Total findings by status
    status_counts = {}
    for stat in FindingStatus:
        result = await db.execute(
            base.where(Finding.status == stat.value).with_only_columns(func.count())
        )
        status_counts[stat.value.lower()] = result.scalar_one()

    # By scanner (open only)
    scanner_result = await db.execute(
        select(Finding.scanner, func.count().label("count"))
        .where(Finding.status == FindingStatus.OPEN.value)
        .group_by(Finding.scanner)
        .order_by(desc("count"))
    )
    by_scanner = [{"scanner": row.scanner, "count": row.count} for row in scanner_result]

    # By category (open only)
    category_result = await db.execute(
        select(Finding.category, func.count().label("count"))
        .where(Finding.status == FindingStatus.OPEN.value)
        .group_by(Finding.category)
    )
    by_category = [{"category": row.category, "count": row.count} for row in category_result]

    # SLA breached
    now = datetime.now(timezone.utc)
    sla_result = await db.execute(
        base.where(
            Finding.status == FindingStatus.OPEN.value,
            Finding.sla_breach_at <= now,
            Finding.sla_breach_at.is_not(None),
        ).with_only_columns(func.count())
    )
    sla_breached = sla_result.scalar_one()

    # Total repositories
    repo_count = (await db.execute(select(func.count()).select_from(Repository))).scalar_one()

    return {
        "open_by_severity": severity_counts,
        "by_status": status_counts,
        "by_scanner": by_scanner,
        "by_category": by_category,
        "sla_breached": sla_breached,
        "total_repositories": repo_count,
    }


@router.get("/trends")
async def get_trends(
    days: int = Query(30, ge=7, le=365),
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Finding counts per day over the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    stmt = (
        select(
            func.date(Finding.first_seen_at).label("date"),
            func.count().label("new_findings"),
        )
        .where(Finding.first_seen_at >= since)
        .group_by(func.date(Finding.first_seen_at))
        .order_by("date")
    )
    if repository_id:
        stmt = stmt.where(Finding.repository_id == repository_id)

    result = await db.execute(stmt)
    trend_data = [{"date": str(row.date), "new_findings": row.new_findings} for row in result]

    # Fixed trend
    fixed_stmt = (
        select(
            func.date(Finding.resolved_at).label("date"),
            func.count().label("fixed_findings"),
        )
        .where(
            Finding.resolved_at >= since,
            Finding.status == FindingStatus.FIXED.value,
        )
        .group_by(func.date(Finding.resolved_at))
        .order_by("date")
    )
    fixed_result = await db.execute(fixed_stmt)
    fixed_by_date = {str(row.date): row.fixed_findings for row in fixed_result}

    for entry in trend_data:
        entry["fixed_findings"] = fixed_by_date.get(entry["date"], 0)

    return {"days": days, "data": trend_data}


@router.get("/top-vulnerabilities")
async def get_top_vulnerabilities(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Most common rule IDs among open findings."""
    result = await db.execute(
        select(Finding.rule_id, Finding.title, Finding.scanner, func.count().label("count"))
        .where(Finding.status == FindingStatus.OPEN.value)
        .group_by(Finding.rule_id, Finding.title, Finding.scanner)
        .order_by(desc("count"))
        .limit(limit)
    )
    return [
        {"rule_id": row.rule_id, "title": row.title, "scanner": row.scanner, "count": row.count}
        for row in result
    ]


@router.get("/repo-risk")
async def get_repo_risk(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Per-repository risk scores, ranked highest first."""
    result = await db.execute(
        select(Repository).order_by(desc(Repository.risk_score)).limit(20)
    )
    repos = result.scalars().all()
    return [
        {
            "id": r.id,
            "name": r.github_full_name,
            "risk_score": r.risk_score,
            "open_critical": r.open_critical,
            "open_high": r.open_high,
            "open_medium": r.open_medium,
            "open_low": r.open_low,
            "last_scan_at": r.last_scan_at,
        }
        for r in repos
    ]


@router.get("/mttr")
async def get_mttr(
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Mean Time to Remediate by severity (in days)."""
    mttr = {}
    for sev in Severity:
        stmt = select(
            func.avg(
                func.julianday(Finding.resolved_at) - func.julianday(Finding.first_seen_at)
            ).label("avg_days")
        ).where(
            Finding.severity == sev.value,
            Finding.status == FindingStatus.FIXED.value,
            Finding.resolved_at.is_not(None),
        )
        if repository_id:
            stmt = stmt.where(Finding.repository_id == repository_id)
        result = await db.execute(stmt)
        avg = result.scalar_one()
        mttr[sev.value.lower()] = round(float(avg), 1) if avg else None
    return {"mttr_days": mttr}


@router.get("/hot-repos")
async def get_hot_repos(
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Repositories with the most new findings in the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(
            Finding.repository_id,
            func.count().label("new_findings"),
            func.sum(func.case((Finding.severity == "CRITICAL", 1), else_=0)).label("critical_new"),
            func.sum(func.case((Finding.severity == "HIGH", 1), else_=0)).label("high_new"),
        )
        .where(Finding.first_seen_at >= since)
        .group_by(Finding.repository_id)
        .order_by(desc("new_findings"))
        .limit(limit)
    )
    rows = result.all()

    hot = []
    for row in rows:
        repo_res = await db.execute(select(Repository).where(Repository.id == row.repository_id))
        repo = repo_res.scalar_one_or_none()
        if repo:
            hot.append({
                "repository_id": row.repository_id,
                "github_full_name": repo.github_full_name,
                "new_findings": row.new_findings,
                "critical_new": row.critical_new or 0,
                "high_new": row.high_new or 0,
                "risk_score": repo.risk_score,
            })
    return hot


@router.get("/coverage-gaps")
async def get_coverage_gaps(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Repositories with stale, missing, or incomplete scanner coverage."""
    from datetime import date
    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(days=7)

    repos_res = await db.execute(select(Repository))
    all_repos = repos_res.scalars().all()

    stale, unconfigured, partial = [], [], []

    _sast = {"SEMGREP", "BANDIT"}
    _sca = {"TRIVY", "GRYPE", "SNYK"}
    _iac = {"CHECKOV"}
    _dast = {"ZAP"}
    _categories = {"SAST": _sast, "SCA": _sca, "IaC": _iac, "DAST": _dast}

    for repo in all_repos:
        scanners = set(s.strip().upper() for s in repo.enabled_scanners.split(",") if s.strip())

        if not scanners:
            unconfigured.append({"id": repo.id, "github_full_name": repo.github_full_name})
            continue

        last_scan = repo.last_scan_at.replace(tzinfo=timezone.utc) if repo.last_scan_at and repo.last_scan_at.tzinfo is None else repo.last_scan_at
        if last_scan is None or last_scan < stale_threshold:
            days_since = int((now - last_scan).days) if last_scan else 9999
            stale.append({
                "id": repo.id,
                "github_full_name": repo.github_full_name,
                "last_scan_at": repo.last_scan_at,
                "days_since_scan": days_since,
            })

        missing = [cat for cat, members in _categories.items() if not scanners & members]
        if missing:
            partial.append({
                "id": repo.id,
                "github_full_name": repo.github_full_name,
                "has_scanners": list(scanners),
                "missing_categories": missing,
            })

    return {"stale_repos": stale, "unconfigured_repos": unconfigured, "partial_coverage": partial}


@router.get("/regressions")
async def get_regressions(
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Recent regression findings — previously fixed issues that reappeared."""
    from app.models.finding import Finding
    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(Finding)
        .where(Finding.is_regression == True, Finding.regression_detected_at >= since)  # noqa: E712
        .order_by(desc(Finding.regression_detected_at))
        .limit(limit)
    )
    findings = result.scalars().all()
    out = []
    for f in findings:
        repo_res = await db.execute(select(Repository).where(Repository.id == f.repository_id))
        repo = repo_res.scalar_one_or_none()
        out.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "scanner": f.scanner,
            "file_path": f.file_path,
            "repository_id": f.repository_id,
            "github_full_name": repo.github_full_name if repo else None,
            "regression_detected_at": f.regression_detected_at,
        })
    return out


@router.get("/org-risk-history")
async def get_org_risk_history(
    days: int = Query(30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Aggregated organization risk score history."""
    from app.models.repo_risk_history import RepoRiskHistory
    since = datetime.now(timezone.utc).date() - timedelta(days=days)

    result = await db.execute(
        select(
            RepoRiskHistory.snapshot_date,
            func.avg(RepoRiskHistory.risk_score).label("avg_risk_score"),
            func.sum(RepoRiskHistory.open_critical + RepoRiskHistory.open_high +
                     RepoRiskHistory.open_medium + RepoRiskHistory.open_low).label("total_open"),
            func.sum(RepoRiskHistory.open_critical).label("total_critical"),
            func.sum(func.case((RepoRiskHistory.risk_score >= 50, 1), else_=0)).label("repos_at_risk"),
        )
        .where(RepoRiskHistory.snapshot_date >= since)
        .group_by(RepoRiskHistory.snapshot_date)
        .order_by(RepoRiskHistory.snapshot_date)
    )
    rows = result.all()
    return [
        {
            "date": str(row.snapshot_date),
            "avg_risk_score": round(float(row.avg_risk_score or 0), 1),
            "total_open": int(row.total_open or 0),
            "total_critical": int(row.total_critical or 0),
            "repos_at_risk": int(row.repos_at_risk or 0),
        }
        for row in rows
    ]


@router.get("/compliance-trends")
async def get_compliance_trends(
    framework_id: str = Query(..., max_length=50),
    days: int = Query(30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Estimated compliance coverage trend over time based on finding open/close dates."""
    from app.services.compliance_service import FRAMEWORKS
    if framework_id not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")

    controls = FRAMEWORKS[framework_id]
    all_cwe_ids = {cwe for ctrl in controls for cwe in (ctrl.cwe_ids or [])}

    trend_data = []
    now = datetime.now(timezone.utc)
    for day_offset in range(days, -1, -7):  # weekly buckets
        point_date = now - timedelta(days=day_offset)
        date_str = point_date.strftime("%Y-%m-%d")

        # Findings open at this point in time mapped to the framework's CWEs
        total_res = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.first_seen_at <= point_date,
            )
        )
        total_ever = total_res.scalar_one() or 1

        open_at_point_res = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.first_seen_at <= point_date,
                or_(Finding.resolved_at.is_(None), Finding.resolved_at > point_date),
                Finding.status != FindingStatus.SUPPRESSED.value,
            )
        )
        open_at_point = open_at_point_res.scalar_one()

        fixed_at_point_res = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.resolved_at.isnot(None),
                Finding.resolved_at <= point_date,
                Finding.status == FindingStatus.FIXED.value,
            )
        )
        fixed_at_point = fixed_at_point_res.scalar_one()

        coverage_pct = round(max(0, 1 - (open_at_point / total_ever)) * 100, 1) if total_ever else 100.0
        trend_data.append({
            "date": date_str,
            "coverage_pct": coverage_pct,
            "open_findings": open_at_point,
            "fixed_findings": fixed_at_point,
        })

    return {"framework_id": framework_id, "data": trend_data}


@router.get("/severity-trend")
async def get_severity_trend(
    days: int = Query(90, ge=14, le=365),
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    New findings per week, broken down by severity.
    Returns the last N days bucketed into ISO weeks.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)

    stmt = select(
        func.strftime("%Y-%W", Finding.first_seen_at).label("week"),
        Finding.severity,
        func.count().label("count"),
    ).where(Finding.first_seen_at >= since).group_by("week", Finding.severity).order_by("week")

    if repository_id:
        stmt = stmt.where(Finding.repository_id == repository_id)

    result = await db.execute(stmt)
    rows = result.all()

    # Build ordered week buckets
    week_map: dict = {}
    for row in rows:
        w = row.week
        if w not in week_map:
            week_map[w] = {"week": w, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        if row.severity in week_map[w]:
            week_map[w][row.severity] = row.count

    return {"days": days, "data": list(week_map.values())}
