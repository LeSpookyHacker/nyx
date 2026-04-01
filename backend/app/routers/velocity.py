"""
Velocity analytics — finding discovery and resolution rates over time.

Answers: How fast are new vulnerabilities being introduced vs. fixed?
Which scanners/severities have the worst throughput?
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus, Severity
from app.core.security import require_api_key
from app.database import get_db
from app.models.finding import Finding
from app.models.remediation import Remediation

router = APIRouter(prefix="/dashboard/velocity", tags=["analytics"])


@router.get("")
async def get_velocity(
    days: int = Query(30, ge=7, le=365),
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Finding velocity metrics for the specified period.

    Returns:
      - new_per_day:   average new findings per day
      - fixed_per_day: average resolved findings per day
      - net_rate:      net daily change (new - fixed) — negative = improving
      - by_severity:   breakdown of new/fixed per severity level
      - by_scanner:    breakdown of new findings per scanner
      - burndown_days: estimated days to clear all open findings at current fix rate
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    now = datetime.now(timezone.utc)

    base_filters = [Finding.first_seen_at >= since]
    if repository_id:
        base_filters.append(Finding.repository_id == repository_id)

    # Total new findings in period
    new_total_res = await db.execute(
        select(func.count()).select_from(Finding).where(*base_filters)
    )
    new_total = new_total_res.scalar_one() or 0

    # Total fixed in period
    fixed_filters = [
        Finding.resolved_at >= since,
        Finding.resolved_at.isnot(None),
        Finding.status == FindingStatus.FIXED.value,
    ]
    if repository_id:
        fixed_filters.append(Finding.repository_id == repository_id)

    fixed_total_res = await db.execute(
        select(func.count()).select_from(Finding).where(*fixed_filters)
    )
    fixed_total = fixed_total_res.scalar_one() or 0

    new_per_day = round(new_total / days, 2)
    fixed_per_day = round(fixed_total / days, 2)
    net_rate = round(new_per_day - fixed_per_day, 2)

    # Breakdown by severity
    by_severity = {}
    for sev in Severity:
        sev_new_res = await db.execute(
            select(func.count()).select_from(Finding).where(
                *base_filters, Finding.severity == sev.value
            )
        )
        sev_new = sev_new_res.scalar_one() or 0

        sev_fixed_filters = [
            *fixed_filters,
            Finding.severity == sev.value,
        ]
        sev_fixed_res = await db.execute(
            select(func.count()).select_from(Finding).where(*sev_fixed_filters)
        )
        sev_fixed = sev_fixed_res.scalar_one() or 0

        by_severity[sev.value] = {
            "new": sev_new,
            "fixed": sev_fixed,
            "net": sev_new - sev_fixed,
        }

    # Breakdown by scanner (new only)
    scanner_res = await db.execute(
        select(Finding.scanner, func.count().label("count"))
        .where(*base_filters)
        .group_by(Finding.scanner)
        .order_by(desc("count"))
    )
    by_scanner = [
        {"scanner": row.scanner, "new_findings": row.count}
        for row in scanner_res
    ]

    # Open count for burndown estimate
    open_filters = [Finding.status == FindingStatus.OPEN.value]
    if repository_id:
        open_filters.append(Finding.repository_id == repository_id)

    open_total_res = await db.execute(
        select(func.count()).select_from(Finding).where(*open_filters)
    )
    open_total = open_total_res.scalar_one() or 0

    burndown_days = None
    if fixed_per_day > new_per_day and fixed_per_day > 0:
        burndown_days = round(open_total / (fixed_per_day - new_per_day), 0)

    # Weekly trend (new findings per ISO week)
    week_res = await db.execute(
        select(
            func.strftime("%Y-%W", Finding.first_seen_at).label("week"),
            func.count().label("new_findings"),
        )
        .where(*base_filters)
        .group_by("week")
        .order_by("week")
    )
    weekly_new = [{"week": row.week, "new_findings": row.new_findings} for row in week_res]

    week_fixed_res = await db.execute(
        select(
            func.strftime("%Y-%W", Finding.resolved_at).label("week"),
            func.count().label("fixed_findings"),
        )
        .where(*fixed_filters)
        .group_by("week")
        .order_by("week")
    )
    weekly_fixed_map = {row.week: row.fixed_findings for row in week_fixed_res}

    for entry in weekly_new:
        entry["fixed_findings"] = weekly_fixed_map.get(entry["week"], 0)
        entry["net"] = entry["new_findings"] - entry["fixed_findings"]

    return {
        "period_days": days,
        "new_total": new_total,
        "fixed_total": fixed_total,
        "open_total": open_total,
        "new_per_day": new_per_day,
        "fixed_per_day": fixed_per_day,
        "net_rate": net_rate,
        "burndown_days": burndown_days,
        "by_severity": by_severity,
        "by_scanner": by_scanner,
        "weekly_trend": weekly_new,
    }


@router.get("/mttr-breakdown")
async def get_mttr_breakdown(
    days: int = Query(90, ge=14, le=365),
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    MTTR (Mean Time to Remediate) broken down by severity, scanner, and category.
    Only includes findings that were actually fixed (status=FIXED) in the period.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)

    results: dict = {"by_severity": {}, "by_scanner": {}, "by_category": {}}

    base = [
        Finding.status == FindingStatus.FIXED.value,
        Finding.resolved_at >= since,
        Finding.resolved_at.isnot(None),
        Finding.first_seen_at.isnot(None),
    ]
    if repository_id:
        base.append(Finding.repository_id == repository_id)

    # By severity
    for sev in Severity:
        stmt = select(
            func.avg(
                func.julianday(Finding.resolved_at) - func.julianday(Finding.first_seen_at)
            ).label("avg_days"),
            func.count().label("sample_size"),
        ).where(*base, Finding.severity == sev.value)
        row = (await db.execute(stmt)).one()
        results["by_severity"][sev.value] = {
            "mttr_days": round(float(row.avg_days), 1) if row.avg_days else None,
            "sample_size": row.sample_size,
        }

    # By scanner
    scanner_stmt = select(
        Finding.scanner,
        func.avg(
            func.julianday(Finding.resolved_at) - func.julianday(Finding.first_seen_at)
        ).label("avg_days"),
        func.count().label("sample_size"),
    ).where(*base).group_by(Finding.scanner)
    for row in (await db.execute(scanner_stmt)).all():
        results["by_scanner"][row.scanner] = {
            "mttr_days": round(float(row.avg_days), 1) if row.avg_days else None,
            "sample_size": row.sample_size,
        }

    # By category
    category_stmt = select(
        Finding.category,
        func.avg(
            func.julianday(Finding.resolved_at) - func.julianday(Finding.first_seen_at)
        ).label("avg_days"),
        func.count().label("sample_size"),
    ).where(*base).group_by(Finding.category)
    for row in (await db.execute(category_stmt)).all():
        results["by_category"][row.category] = {
            "mttr_days": round(float(row.avg_days), 1) if row.avg_days else None,
            "sample_size": row.sample_size,
        }

    return {"period_days": days, **results}
