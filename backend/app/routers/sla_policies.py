"""SLA Policy router — manage custom SLA rules."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_client_ip, require_api_key
from app.database import get_db
from app.models.sla_policy import SlaPolicy
from app.services.audit_service import log_event

router = APIRouter(prefix="/sla-policies", tags=["sla-policies"])

_VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "ALL"})
_VALID_ACTIONS = frozenset({"NOTIFY", "JIRA", "BOTH", "NONE"})


class SlaPolicyCreate(BaseModel):
    name: str
    repository_id: Optional[str] = None
    severity: str = "ALL"
    max_days: int = 30
    escalation_action: str = "NOTIFY"
    jira_project_key: Optional[str] = None
    enabled: bool = True

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v = v.upper()
        if v not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}")
        return v

    @field_validator("escalation_action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        v = v.upper()
        if v not in _VALID_ACTIONS:
            raise ValueError(f"escalation_action must be one of {sorted(_VALID_ACTIONS)}")
        return v

    @field_validator("max_days")
    @classmethod
    def validate_days(cls, v: int) -> int:
        if v < 1 or v > 365:
            raise ValueError("max_days must be between 1 and 365")
        return v


class SlaPolicyUpdate(BaseModel):
    name: Optional[str] = None
    severity: Optional[str] = None
    max_days: Optional[int] = None
    escalation_action: Optional[str] = None
    jira_project_key: Optional[str] = None
    enabled: Optional[bool] = None


def _to_dict(p: SlaPolicy) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "repository_id": p.repository_id,
        "severity": p.severity,
        "max_days": p.max_days,
        "escalation_action": p.escalation_action,
        "jira_project_key": p.jira_project_key,
        "enabled": p.enabled,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    }


@router.get("")
async def list_policies(
    repository_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    stmt = select(SlaPolicy).order_by(SlaPolicy.created_at.desc())
    if repository_id:
        stmt = stmt.where(SlaPolicy.repository_id == repository_id)
    result = await db.execute(stmt)
    return [_to_dict(p) for p in result.scalars().all()]


@router.post("", status_code=201)
async def create_policy(
    request: Request,
    body: SlaPolicyCreate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    p = SlaPolicy(**body.model_dump())
    db.add(p)
    await db.flush()
    await log_event(db, actor=_key, action="sla_policy.created", resource_type="sla_policy",
        resource_id=p.id,
        metadata={"name": p.name, "severity": p.severity, "max_days": p.max_days,
                  "escalation_action": p.escalation_action},
        ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(p)
    return _to_dict(p)


@router.get("/{policy_id}")
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(SlaPolicy).where(SlaPolicy.id == policy_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    return _to_dict(p)


@router.patch("/{policy_id}")
async def update_policy(
    request: Request,
    policy_id: str,
    body: SlaPolicyUpdate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(SlaPolicy).where(SlaPolicy.id == policy_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    changes = body.model_dump(exclude_none=True)
    for field, val in changes.items():
        setattr(p, field, val.upper() if field in ("severity", "escalation_action") and val else val)
    await log_event(db, actor=_key, action="sla_policy.updated", resource_type="sla_policy",
        resource_id=policy_id, metadata={"changes": changes},
        ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(p)
    return _to_dict(p)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    request: Request,
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(SlaPolicy).where(SlaPolicy.id == policy_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    await log_event(db, actor=_key, action="sla_policy.deleted", resource_type="sla_policy",
        resource_id=policy_id,
        metadata={"name": p.name, "severity": p.severity, "max_days": p.max_days},
        ip_address=get_client_ip(request))
    await db.delete(p)
    await db.commit()
