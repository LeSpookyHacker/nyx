"""Regression auto-sort alerts — notifies engineers when findings were auto-restored."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_client_ip, require_api_key, require_scope, SCOPE_ANALYST, SCOPE_ADMIN
from app.database import get_db
from app.models.regression_auto_alert import RegressionAutoAlert
from app.models.repository import Repository
from app.services.audit_service import log_event

router = APIRouter(prefix="/regression-alerts", tags=["regression-alerts"])


@router.get("")
async def list_regression_alerts(
    unacknowledged_only: bool = Query(False),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List regression auto-sort alerts."""
    q = select(RegressionAutoAlert).order_by(RegressionAutoAlert.created_at.desc()).limit(limit)
    if unacknowledged_only:
        q = q.where(RegressionAutoAlert.acknowledged_at.is_(None))
    result = await db.execute(q)
    alerts = result.scalars().all()

    repo_ids = list({a.repository_id for a in alerts})
    repos: dict[str, str] = {}
    if repo_ids:
        repo_result = await db.execute(
            select(Repository).where(Repository.id.in_(repo_ids))
        )
        repos = {r.id: r.github_full_name for r in repo_result.scalars().all()}

    return [_alert_response(a, repos.get(a.repository_id)) for a in alerts]


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    request: Request,
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(RegressionAutoAlert).where(RegressionAutoAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged_at = datetime.now(timezone.utc)
    await log_event(db, actor=_key, action="regression_alert.acknowledged",
        resource_type="regression_alert", resource_id=alert_id,
        metadata={"repository_id": alert.repository_id},
        ip_address=get_client_ip(request))
    await db.commit()
    return {"acknowledged": True}


@router.post("/acknowledge-all")
async def acknowledge_all(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-219: scanner keys must not silence all alerts
):
    result = await db.execute(
        select(RegressionAutoAlert).where(RegressionAutoAlert.acknowledged_at.is_(None))
    )
    now = datetime.now(timezone.utc)
    count = 0
    for alert in result.scalars().all():
        alert.acknowledged_at = now
        count += 1
    await log_event(db, actor=_key, action="regression_alert.all_acknowledged",
        resource_type="regression_alert", metadata={"count": count},
        ip_address=get_client_ip(request))
    await db.commit()
    return {"acknowledged": count}


def _alert_response(alert: RegressionAutoAlert, repo_name: str | None) -> dict:
    return {
        "id": alert.id,
        "repository_id": alert.repository_id,
        "repository_name": repo_name,
        "scan_id": alert.scan_id,
        "auto_sorted_count": alert.auto_sorted_count,
        "findings": json.loads(alert.findings_json or "[]"),
        "acknowledged": alert.acknowledged_at is not None,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }
