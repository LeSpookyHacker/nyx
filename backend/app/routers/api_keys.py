"""API key management — create, list, and deactivate API keys."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_client_ip, require_api_key
from app.database import get_db
from app.models.api_key import ApiKey
from app.services.audit_service import log_event

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class ApiKeyCreate(BaseModel):
    name: str
    expires_in_days: Optional[int] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        if len(v) > 255:
            raise ValueError("name cannot exceed 255 characters")
        return v

    @field_validator("expires_in_days")
    @classmethod
    def validate_expiry(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and (v < 1 or v > 730):
            raise ValueError("expires_in_days must be between 1 and 730")
        return v


def _key_response(k: ApiKey) -> dict:
    return {
        "id": k.id,
        "name": k.name,
        "is_active": k.is_active,
        "expires_at": k.expires_at.isoformat() if k.expires_at else None,
        "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        "created_by": k.created_by,
        "created_at": k.created_at.isoformat() if k.created_at else None,
    }


@router.get("", response_model=List[dict])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List all API keys (never returns the plaintext key or hash)."""
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))
    return [_key_response(k) for k in result.scalars().all()]


@router.post("", status_code=201)
async def create_api_key(
    request: Request,
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Create a new API key. Returns the plaintext key ONCE — store it immediately.

    The plaintext key is never stored and cannot be recovered after this response.
    """
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    record = ApiKey(
        name=body.name,
        key_hash=key_hash,
        is_active=True,
        expires_at=expires_at,
        created_by=_key,
    )
    db.add(record)
    await db.flush()
    await log_event(db, actor=_key, action="api_key.created", resource_type="api_key",
        resource_id=record.id,
        metadata={"name": body.name, "expires_in_days": body.expires_in_days},
        ip_address=get_client_ip(request))
    await db.commit()

    return {
        "id": record.id,
        "name": record.name,
        "key": raw_key,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "warning": "Store this key securely — it will not be shown again.",
    }


@router.delete("/{key_id}", status_code=200)
async def deactivate_api_key(
    request: Request,
    key_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Deactivate an API key (soft delete — preserves audit trail).
    The deactivated key is rejected immediately on next use.
    """
    result = await db.execute(select(ApiKey).where(ApiKey.id == key_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="API key not found")
    if not record.is_active:
        raise HTTPException(status_code=409, detail="API key is already deactivated")

    record.is_active = False
    await log_event(db, actor=_key, action="api_key.deactivated", resource_type="api_key",
        resource_id=key_id,
        metadata={"name": record.name},
        ip_address=get_client_ip(request))
    await db.commit()
    return {"deactivated": True, "id": key_id, "name": record.name}
