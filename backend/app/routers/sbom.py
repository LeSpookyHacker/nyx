"""SBOM submission, history, and alert management."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key
from app.database import get_db
from app.models.repository import Repository
from app.models.sbom import Sbom, SbomAlert
from app.services import sbom_service

router = APIRouter(prefix="/sbom", tags=["sbom"])


# ── Submission ────────────────────────────────────────────────────────────────

class SbomSubmitRequest(BaseModel):
    git_ref: Optional[str] = None
    # The full SBOM JSON body is passed as a dict
    sbom: Dict[str, Any]


@router.post("/repositories/{repo_id}/submit", status_code=201)
async def submit_sbom(
    repo_id: str,
    body: SbomSubmitRequest,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Submit a new SBOM for a repository.  Diffs against the previous snapshot
    and creates an SbomAlert if the component set changed.

    Accepts CycloneDX JSON or SPDX JSON.

    Example (CI/CD):
        syft . -o cyclonedx-json | curl -X POST .../sbom/repositories/<id>/submit \\
            -H "Content-Type: application/json" \\
            -d "{\\"git_ref\\": \\"main\\", \\"sbom\\": $(cat -)}"
    """
    repo_result = await db.execute(select(Repository).where(Repository.id == repo_id))
    if not repo_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Repository not found")

    try:
        fmt, tool, components = sbom_service.parse(body.sbom)
    except (ValueError, Exception):
        raise HTTPException(status_code=422, detail="Failed to parse SBOM: unsupported format or invalid structure")

    # Cap component count to prevent memory exhaustion during diff (H-7)
    _MAX_COMPONENTS = 50_000
    if len(components) > _MAX_COMPONENTS:
        raise HTTPException(
            status_code=422,
            detail=f"SBOM contains {len(components):,} components; maximum is {_MAX_COMPONENTS:,}",
        )

    # Fetch previous SBOM for diff
    prev_result = await db.execute(
        select(Sbom)
        .where(Sbom.repository_id == repo_id)
        .order_by(Sbom.created_at.desc())
        .limit(1)
    )
    prev_sbom = prev_result.scalar_one_or_none()

    # Persist new snapshot
    sbom = Sbom(
        repository_id=repo_id,
        format=fmt,
        tool=tool,
        component_count=len(components),
        git_ref=body.git_ref,
        components_json=sbom_service.components_to_json(components),
    )
    db.add(sbom)
    await db.flush()

    # Diff and maybe create alert
    alert = None
    if prev_sbom:
        old_components = sbom_service.components_from_json(prev_sbom.components_json)
        changes = sbom_service.diff(old_components, components)
        changes = changes[:10_000]  # Cap diff output to prevent unbounded JSON storage (H-7)
        if changes:
            added = sum(1 for c in changes if c["type"] == "added")
            removed = sum(1 for c in changes if c["type"] == "removed")
            updated = sum(1 for c in changes if c["type"] == "updated")
            alert = SbomAlert(
                repository_id=repo_id,
                sbom_id=sbom.id,
                previous_sbom_id=prev_sbom.id,
                added_count=added,
                removed_count=removed,
                updated_count=updated,
                changes_json=json.dumps(changes),
            )
            db.add(alert)
    else:
        # First SBOM — create an informational alert
        alert = SbomAlert(
            repository_id=repo_id,
            sbom_id=sbom.id,
            previous_sbom_id=None,
            added_count=len(components),
            removed_count=0,
            updated_count=0,
            changes_json=json.dumps([
                {"type": "added", "name": c.name, "new_version": c.version, "purl": c.purl}
                for c in components
            ]),
        )
        db.add(alert)

    await db.commit()

    return {
        "sbom_id": sbom.id,
        "format": fmt,
        "tool": tool,
        "component_count": len(components),
        "alert_created": alert is not None,
        "changes": {
            "added": alert.added_count if alert else 0,
            "removed": alert.removed_count if alert else 0,
            "updated": alert.updated_count if alert else 0,
        },
    }


# ── SBOM history & detail ─────────────────────────────────────────────────────

@router.get("/repositories/{repo_id}/current")
async def get_current_sbom(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Return the latest SBOM snapshot with its component list."""
    result = await db.execute(
        select(Sbom)
        .where(Sbom.repository_id == repo_id)
        .order_by(Sbom.created_at.desc())
        .limit(1)
    )
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(status_code=404, detail="No SBOM found for this repository")
    return _sbom_response(sbom, include_components=True)


@router.get("/repositories/{repo_id}/history")
async def list_sbom_history(
    repo_id: str,
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List SBOM snapshots (newest first, no component detail)."""
    result = await db.execute(
        select(Sbom)
        .where(Sbom.repository_id == repo_id)
        .order_by(Sbom.created_at.desc())
        .limit(limit)
    )
    return [_sbom_response(s) for s in result.scalars().all()]


# ── Alerts ────────────────────────────────────────────────────────────────────

@router.get("/alerts")
async def list_alerts(
    unacknowledged_only: bool = Query(False),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List SBOM change alerts.  Pass unacknowledged_only=true for the badge count."""
    q = select(SbomAlert).order_by(SbomAlert.created_at.desc()).limit(limit)
    if unacknowledged_only:
        q = q.where(SbomAlert.acknowledged_at.is_(None))
    result = await db.execute(q)
    alerts = result.scalars().all()

    # Enrich with repo name
    repo_ids = list({a.repository_id for a in alerts})
    repos = {}
    if repo_ids:
        repo_result = await db.execute(
            select(Repository).where(Repository.id.in_(repo_ids))
        )
        repos = {r.id: r.github_full_name for r in repo_result.scalars().all()}

    return [_alert_response(a, repos.get(a.repository_id)) for a in alerts]


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(SbomAlert).where(SbomAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return {"acknowledged": True}


@router.post("/alerts/acknowledge-all")
async def acknowledge_all_alerts(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(
        select(SbomAlert).where(SbomAlert.acknowledged_at.is_(None))
    )
    now = datetime.now(timezone.utc)
    count = 0
    for alert in result.scalars().all():
        alert.acknowledged_at = now
        count += 1
    await db.commit()
    return {"acknowledged": count}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sbom_response(sbom: Sbom, include_components: bool = False) -> dict:
    d = {
        "id": sbom.id,
        "repository_id": sbom.repository_id,
        "format": sbom.format,
        "tool": sbom.tool,
        "component_count": sbom.component_count,
        "git_ref": sbom.git_ref,
        "created_at": sbom.created_at.isoformat() if sbom.created_at else None,
    }
    if include_components:
        d["components"] = json.loads(sbom.components_json or "[]")
    return d


def _alert_response(alert: SbomAlert, repo_name: Optional[str]) -> dict:
    return {
        "id": alert.id,
        "repository_id": alert.repository_id,
        "repository_name": repo_name,
        "sbom_id": alert.sbom_id,
        "previous_sbom_id": alert.previous_sbom_id,
        "added_count": alert.added_count,
        "removed_count": alert.removed_count,
        "updated_count": alert.updated_count,
        "changes": json.loads(alert.changes_json or "[]"),
        "acknowledged": alert.acknowledged_at is not None,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }
