"""Compliance mapping and reporting API."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key
from app.database import get_db
from app.services import compliance_service

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/frameworks")
async def list_frameworks(_key: str = Depends(require_api_key)):
    """List all supported compliance frameworks."""
    return [
        {"id": fid, **meta}
        for fid, meta in compliance_service.FRAMEWORK_META.items()
    ]


@router.get("/summary")
async def get_compliance_summary(
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Compliance coverage summary across all frameworks."""
    summary = []
    for framework_id, meta in compliance_service.FRAMEWORK_META.items():
        controls = await compliance_service.get_compliance_report(db, framework_id, repository_id)
        total = len(controls)
        compliant = sum(1 for c in controls if c.is_compliant)
        open_total = sum(c.open_count for c in controls)
        pct = round(compliant / total * 100, 1) if total else 100.0
        summary.append({
            "framework_id": framework_id,
            "name": meta["name"],
            "compliance_pct": pct,
            "compliant_controls": compliant,
            "total_controls": total,
            "open_findings": open_total,
        })
    return summary


@router.get("/report/{framework_id}/controls/{control_id}/findings")
async def get_control_findings(
    framework_id: str,
    control_id: str,
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Open findings mapped to a specific compliance control, grouped by repository."""
    if framework_id not in compliance_service.FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")
    result = await compliance_service.get_control_findings(db, framework_id, control_id, repository_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in framework '{framework_id}'")
    return result


@router.get("/report/{framework_id}")
async def get_compliance_report(
    framework_id: str,
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Full compliance report for a specific framework."""
    if framework_id not in compliance_service.FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")

    controls = await compliance_service.get_compliance_report(db, framework_id, repository_id)
    total_controls = len(controls)
    compliant_controls = sum(1 for c in controls if c.is_compliant)
    overall_pct = round(compliant_controls / total_controls * 100, 1) if total_controls else 100.0

    return {
        "framework_id": framework_id,
        "framework": compliance_service.FRAMEWORK_META[framework_id],
        "overall_compliance_pct": overall_pct,
        "compliant_controls": compliant_controls,
        "total_controls": total_controls,
        "controls": [
            {
                "id": c.control.id,
                "title": c.control.title,
                "description": c.control.description,
                "open_findings": c.open_count,
                "total_findings": c.total_count,
                "is_compliant": c.is_compliant,
                "coverage_pct": c.coverage_pct,
                "cwe_ids": c.control.cwe_ids,
                "owasp_categories": c.control.owasp_categories,
            }
            for c in controls
        ],
    }
