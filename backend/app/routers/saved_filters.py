"""Saved filters — named filter presets for the FindingsPage and friends."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key, require_scope, SCOPE_ANALYST, SCOPE_ADMIN
from app.database import get_db
from app.models.saved_filter import SavedFilter

router = APIRouter(prefix="/saved-filters", tags=["saved-filters"])

_MAX_FILTERS_JSON_BYTES = 8 * 1024  # 8 KB — filter state is tiny, cap to defeat abuse


class SavedFilterCreate(BaseModel):
    name: str
    filters: Dict[str, Any]
    is_default: bool = False
    scope: str = "findings"

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        if len(v) > 100:
            raise ValueError("name cannot exceed 100 characters")
        return v

    @field_validator("filters")
    @classmethod
    def validate_filters(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(v)
        if len(serialized.encode()) > _MAX_FILTERS_JSON_BYTES:
            raise ValueError(f"filters payload exceeds {_MAX_FILTERS_JSON_BYTES} bytes")
        return v


def _response(f: SavedFilter) -> dict:
    try:
        filters = json.loads(f.filters_json) if f.filters_json else {}
    except Exception:
        filters = {}
    return {
        "id": f.id,
        "name": f.name,
        "filters": filters,
        "is_default": f.is_default,
        "scope": f.scope,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


@router.get("", response_model=List[dict])
async def list_saved_filters(
    scope: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    stmt = select(SavedFilter).order_by(SavedFilter.is_default.desc(), SavedFilter.created_at.desc())
    if scope:
        stmt = stmt.where(SavedFilter.scope == scope)
    result = await db.execute(stmt)
    return [_response(f) for f in result.scalars().all()]


@router.post("", status_code=201)
async def create_saved_filter(
    body: SavedFilterCreate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-326
):
    # If this is marked default, clear any existing default for the same scope.
    if body.is_default:
        await db.execute(
            sa_update(SavedFilter)
            .where(SavedFilter.scope == body.scope, SavedFilter.is_default.is_(True))
            .values(is_default=False)
        )

    record = SavedFilter(
        name=body.name,
        filters_json=json.dumps(body.filters),
        is_default=body.is_default,
        scope=body.scope,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return _response(record)


@router.delete("/{filter_id}", status_code=200)
async def delete_saved_filter(
    filter_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),  # SEC-326
):
    result = await db.execute(select(SavedFilter).where(SavedFilter.id == filter_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Saved filter not found")
    await db.delete(record)
    await db.commit()
    return {"deleted": True, "id": filter_id}
