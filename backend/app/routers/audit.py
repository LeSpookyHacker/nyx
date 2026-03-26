"""Audit log router — read, search, download, and verify audit events."""
from __future__ import annotations

import csv
import hashlib
import hmac as hmac_mod
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key
from app.database import get_db
from app.models.audit_log import AuditLog
from app.services.audit_service import _CHAIN_GENESIS, _compute_entry_hash, _get_hmac_key

router = APIRouter(prefix="/audit", tags=["audit"])


def _serialize(log: AuditLog, include_hashes: bool = False) -> dict:
    d = {
        "id": log.id,
        "actor": log.actor,
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "metadata": json.loads(log.metadata_json) if log.metadata_json else None,
        "ip_address": log.ip_address,
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }
    if include_hashes:
        d["entry_hash"] = log.entry_hash
        d["prev_hash"] = log.prev_hash
    return d


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


@router.get("/verify")
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Walk the audit log hash chain in chronological order and detect tampering.

    Returns a summary of chain validity. Any modified, deleted, or inserted
    entries will cause a chain break that is reported with the entry ID and timestamp.

    Entries created before hash chaining was enabled (entry_hash is NULL) are
    counted separately as 'pre_chain' entries — they are expected during migration.
    """
    stmt = select(AuditLog).order_by(asc(AuditLog.created_at), asc(AuditLog.id))
    result = await db.execute(stmt)
    logs = result.scalars().all()

    errors = []
    prev_hash = _CHAIN_GENESIS
    chain_started = False
    pre_chain_count = 0
    checked = 0

    for log in logs:
        if log.entry_hash is None:
            # Entry pre-dates hash chain feature
            pre_chain_count += 1
            continue

        chain_started = True
        checked += 1

        # Recompute expected hash for this entry
        if log.created_at is None:
            errors.append({
                "id": log.id,
                "error": "missing created_at — cannot verify hash",
            })
            prev_hash = log.entry_hash or prev_hash
            continue

        expected_hash = _compute_entry_hash(
            actor=log.actor,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            metadata_json=log.metadata_json,
            ip_address=log.ip_address,
            created_at=log.created_at,
            prev_hash=log.prev_hash or _CHAIN_GENESIS,
        )

        if log.entry_hash != expected_hash:
            errors.append({
                "id": log.id,
                "created_at": log.created_at.isoformat(),
                "action": log.action,
                "error": "entry_hash mismatch — content may have been tampered",
            })
        elif log.prev_hash != prev_hash:
            errors.append({
                "id": log.id,
                "created_at": log.created_at.isoformat(),
                "action": log.action,
                "error": "prev_hash mismatch — entry may have been inserted or a prior entry deleted",
            })

        prev_hash = log.entry_hash

    return {
        "valid": not errors,
        "total_entries": len(logs),
        "pre_chain_entries": pre_chain_count,
        "chain_entries_checked": checked,
        "chain_started": chain_started,
        "errors": errors,
        "chain_tip": prev_hash if chain_started else None,
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
    include_hashes: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Download audit log as JSON or CSV (max 10,000 rows)."""
    stmt = _build_query(actor, action, resource_type, search, date_from, date_to).limit(10_000)
    result = await db.execute(stmt)
    logs = [_serialize(log, include_hashes=include_hashes) for log in result.scalars().all()]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        fieldnames = ["id", "created_at", "actor", "action", "resource_type", "resource_id", "metadata", "ip_address"]
        if include_hashes:
            fieldnames += ["entry_hash", "prev_hash"]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
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
        # Include chain tip hash in JSON export for out-of-band verification
        chain_tip = logs[-1].get("entry_hash") if logs and include_hashes else None
        export = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(logs),
            "chain_tip": chain_tip,
            "entries": logs,
        }
        content = json.dumps(export, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=nyx_audit_{timestamp}.json"},
        )
