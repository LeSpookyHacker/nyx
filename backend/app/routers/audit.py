"""Audit log router — read, search, and download audit events."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key
from app.database import get_db
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


def _serialize(log: AuditLog) -> dict:
    return {
        "id": log.id,
        "actor": log.actor,
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "metadata": json.loads(log.metadata_json) if log.metadata_json else None,
        "ip_address": log.ip_address,
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }


def _build_query(
    actor: Optional[str],
    action: Optional[str],
    resource_type: Optional[str],
    search: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
):
    stmt = select(AuditLog).order_by(desc(AuditLog.created_at))
    if actor:
        stmt = stmt.where(AuditLog.actor.ilike(f"%{actor}%"))
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if search:
        stmt = stmt.where(AuditLog.metadata_json.ilike(f"%{search}%") | AuditLog.action.ilike(f"%{search}%"))
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            stmt = stmt.where(AuditLog.created_at >= dt)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc)
            stmt = stmt.where(AuditLog.created_at <= dt)
        except ValueError:
            pass
    return stmt


@router.get("")
async def get_audit_log(
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=200),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    base = _build_query(actor, action, resource_type, search, date_from, date_to)

    # Total count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    # Page
    stmt = base.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_serialize(log) for log in logs],
    }


@router.get("/download")
async def download_audit_log(
    fmt: str = Query("json", pattern="^(json|csv)$"),
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=200),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Download audit log as JSON or CSV (max 10,000 rows)."""
    stmt = _build_query(actor, action, resource_type, search, date_from, date_to).limit(10_000)
    result = await db.execute(stmt)
    logs = [_serialize(log) for log in result.scalars().all()]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "created_at", "actor", "action", "resource_type", "resource_id", "metadata", "ip_address"])
        writer.writeheader()
        for row in logs:
            row["metadata"] = json.dumps(row["metadata"]) if row["metadata"] else ""
            writer.writerow(row)
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=nyx_audit_{timestamp}.csv"},
        )
    else:
        content = json.dumps(logs, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=nyx_audit_{timestamp}.json"},
        )
