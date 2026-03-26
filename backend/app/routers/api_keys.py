"""API key management — create, list, and deactivate API keys."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    SCOPE_ADMIN, SCOPE_ANALYST, SCOPE_READONLY, SCOPE_SCANNER,
    get_client_ip, require_api_key, require_scope,
)
from app.database import get_db
from app.models.api_key import ApiKey
from app.services.audit_service import log_event

router = APIRouter(prefix="/api-keys", tags=["api-keys"])

_VALID_SCOPES = {SCOPE_SCANNER, SCOPE_READONLY, SCOPE_ANALYST, SCOPE_ADMIN}


class ApiKeyCreate(BaseModel):
    name: str
    expires_in_days: Optional[int] = None
    scopes: str = SCOPE_ADMIN  # default admin for backward compat

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

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: str) -> str:
        parts = {s.strip() for s in v.split(",") if s.strip()}
        invalid = parts - _VALID_SCOPES
        if invalid:
            raise ValueError(f"Invalid scopes: {invalid}. Valid: {_VALID_SCOPES}")
        return ",".join(sorted(parts))


def _key_response(k: ApiKey) -> dict:
    return {
        "id": k.id,
        "name": k.name,
        "is_active": k.is_active,
        "scopes": k.scopes,
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
    _key: str = Depends(require_scope(SCOPE_ADMIN)),
):
    """
    Create a new API key. Returns the plaintext key ONCE — store it immediately.

    The plaintext key is never stored and cannot be recovered after this response.
    Requires admin scope.
    """
    from app.config import get_settings
    settings = get_settings()

    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    # Resolve expiry: use provided value, or enforce max lifetime if configured
    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)
    elif settings.API_KEY_MAX_LIFETIME_DAYS > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.API_KEY_MAX_LIFETIME_DAYS)

    record = ApiKey(
        name=body.name,
        key_hash=key_hash,
        is_active=True,
        expires_at=expires_at,
        created_by=_key,
        scopes=body.scopes,
    )
    db.add(record)
    await db.flush()
    await log_event(db, actor=_key, action="api_key.created", resource_type="api_key",
        resource_id=record.id,
        metadata={"name": body.name, "scopes": body.scopes, "expires_in_days": body.expires_in_days},
        ip_address=get_client_ip(request))
    await db.commit()

    return {
        "id": record.id,
        "name": record.name,
        "key": raw_key,
        "scopes": record.scopes,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "warning": "Store this key securely — it will not be shown again.",
    }


@router.delete("/{key_id}", status_code=200)
async def deactivate_api_key(
    request: Request,
    key_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ADMIN)),
):
    """
    Deactivate an API key (soft delete — preserves audit trail).
    The deactivated key is rejected immediately on next use.
    Requires admin scope.
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
        metadata={"name": record.name, "scopes": record.scopes},
        ip_address=get_client_ip(request))
    await db.commit()
    return {"deactivated": True, "id": key_id, "name": record.name}
