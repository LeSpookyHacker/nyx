"""Scan Schedule router — manage periodic scan configurations."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import limiter
from app.core.security import get_client_ip, require_api_key, require_scope, SCOPE_ANALYST, SCOPE_ADMIN
from app.database import get_db
from app.models.scan_schedule import ScanSchedule
from app.services.audit_service import log_event

router = APIRouter(prefix="/schedules", tags=["schedules"])

_VALID_SCANNERS = frozenset({
    "SEMGREP", "BANDIT", "TRIVY", "GRYPE", "CHECKOV", "SNYK",
    "CODE_SCANNING", "GITLEAKS", "TRUFFLEHOG", "ZAP",
})


class ScheduleCreate(BaseModel):
    repository_id: str
    enabled_scanners: List[str] = ["SEMGREP", "BANDIT", "TRIVY"]
    interval_hours: int = 24

    @field_validator("enabled_scanners")
    @classmethod
    def validate_scanners(cls, v: List[str]) -> List[str]:
        upper = [s.upper().strip() for s in v]
        invalid = [s for s in upper if s not in _VALID_SCANNERS]
        if invalid:
            raise ValueError(f"Unknown scanner(s): {', '.join(invalid)}")
        return upper

    @field_validator("interval_hours")
    @classmethod
    def validate_interval(cls, v: int) -> int:
        if v < 1 or v > 8760:
            raise ValueError("interval_hours must be between 1 and 8760 (1 year)")
        return v


class ScheduleUpdate(BaseModel):
    enabled_scanners: Optional[List[str]] = None
    interval_hours: Optional[int] = None
    enabled: Optional[bool] = None

    @field_validator("interval_hours")
    @classmethod
    def validate_interval(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and (v < 1 or v > 8760):  # SEC-327: same bounds as ScheduleCreate
            raise ValueError("interval_hours must be between 1 and 8760")
        return v


def _to_dict(s: ScanSchedule) -> dict:
    return {
        "id": s.id,
        "repository_id": s.repository_id,
        "enabled_scanners": s.enabled_scanners,
        "interval_hours": s.interval_hours,
        "enabled": s.enabled,
        "last_run_at": s.last_run_at,
        "next_run_at": s.next_run_at,
        "created_at": s.created_at,
        "updated_at": s.updated_at,
    }


@router.get("")
async def list_schedules(
    repository_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    stmt = select(ScanSchedule).order_by(ScanSchedule.created_at.desc())
    if repository_id:
        stmt = stmt.where(ScanSchedule.repository_id == repository_id)
    result = await db.execute(stmt)
    return [_to_dict(s) for s in result.scalars().all()]


@router.get("/{schedule_id}")
async def get_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _to_dict(s)


@router.post("", status_code=201)
async def create_schedule(
    request: Request,
    body: ScheduleCreate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-324
):
    now = datetime.now(timezone.utc)
    s = ScanSchedule(
        repository_id=body.repository_id,
        enabled_scanners=",".join(body.enabled_scanners),
        interval_hours=body.interval_hours,
        enabled=True,
        next_run_at=now + timedelta(hours=body.interval_hours),
    )
    db.add(s)
    await db.flush()
    await log_event(db, actor=_key, action="schedule.created", resource_type="schedule",
        resource_id=s.id,
        metadata={"repository_id": body.repository_id, "enabled_scanners": body.enabled_scanners,
                  "interval_hours": body.interval_hours},
        ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(s)
    return _to_dict(s)


@router.patch("/{schedule_id}")
async def update_schedule(
    request: Request,
    schedule_id: str,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-324
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    changes: dict = {}
    if body.enabled_scanners is not None:
        upper = [sc.upper().strip() for sc in body.enabled_scanners]
        invalid = [sc for sc in upper if sc not in _VALID_SCANNERS]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Unknown scanner(s): {', '.join(invalid)}")
        s.enabled_scanners = ",".join(upper)
        changes["enabled_scanners"] = upper
    if body.interval_hours is not None:
        s.interval_hours = body.interval_hours
        s.next_run_at = datetime.now(timezone.utc) + timedelta(hours=body.interval_hours)
        changes["interval_hours"] = body.interval_hours
    if body.enabled is not None:
        s.enabled = body.enabled
        changes["enabled"] = body.enabled
    await log_event(db, actor=_key, action="schedule.updated", resource_type="schedule",
        resource_id=schedule_id, metadata={"changes": changes},
        ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(s)
    return _to_dict(s)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    request: Request,
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-324
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await log_event(db, actor=_key, action="schedule.deleted", resource_type="schedule",
        resource_id=schedule_id,
        metadata={"repository_id": s.repository_id, "enabled_scanners": s.enabled_scanners},
        ip_address=get_client_ip(request))
    await db.delete(s)
    await db.commit()


@router.post("/{schedule_id}/trigger")
async def trigger_schedule(
    request: Request,
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-324
):
    """Manually trigger a scheduled scan immediately."""
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")

    from app.core.constants import ScanStatus, ScanTrigger
    from app.models.scan import Scan
    from app.workers.scan_worker import process_scan_results
    import asyncio

    scanners = [sc.strip() for sc in s.enabled_scanners.split(",") if sc.strip()]
    scan_ids = []
    now = datetime.now(timezone.utc)

    for scanner in scanners:
        scan = Scan(
            repository_id=s.repository_id,
            scanner=scanner,
            trigger=ScanTrigger.MANUAL.value,
            status=ScanStatus.PENDING.value,
            started_at=now,
        )
        db.add(scan)
        await db.flush()
        scan_ids.append(scan.id)
        asyncio.create_task(process_scan_results(scan.id, {}))

    s.last_run_at = now
    s.next_run_at = now + timedelta(hours=s.interval_hours)
    await log_event(db, actor=_key, action="schedule.manually_triggered", resource_type="schedule",
        resource_id=schedule_id,
        metadata={"repository_id": s.repository_id, "scanners": scanners, "scan_ids": scan_ids},
        ip_address=get_client_ip(request))
    await db.commit()

    return {"message": f"Triggered {len(scanners)} scan(s)", "scan_ids": scan_ids}
