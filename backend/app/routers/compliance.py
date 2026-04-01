"""Compliance mapping and reporting API — built-in and custom frameworks."""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key, require_scope, SCOPE_ADMIN, SCOPE_ANALYST
from app.database import get_db
from app.models.custom_compliance import CustomControl, CustomFramework
from app.services import compliance_service

router = APIRouter(prefix="/compliance", tags=["compliance"])


# ── Built-in frameworks ───────────────────────────────────────────────────────

@router.get("/frameworks")
async def list_frameworks(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List all supported compliance frameworks — built-in and custom."""
    built_in = [
        {"id": fid, "source": "built_in", **meta}
        for fid, meta in compliance_service.FRAMEWORK_META.items()
    ]

    custom_result = await db.execute(select(CustomFramework).order_by(CustomFramework.name))
    custom = [
        {
            "id": f.slug,
            "source": "custom",
            "name": f.name,
            "description": f.description or "",
            "created_by": f.created_by,
        }
        for f in custom_result.scalars().all()
    ]

    return built_in + custom


@router.get("/summary")
async def get_compliance_summary(
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Compliance coverage summary across all frameworks (built-in + custom)."""
    summary = []

    # Built-in
    for framework_id, meta in compliance_service.FRAMEWORK_META.items():
        controls = await compliance_service.get_compliance_report(db, framework_id, repository_id)
        total = len(controls)
        compliant = sum(1 for c in controls if c.is_compliant)
        open_total = sum(c.open_count for c in controls)
        pct = round(compliant / total * 100, 1) if total else 100.0
        summary.append({
            "framework_id": framework_id,
            "source": "built_in",
            "name": meta["name"],
            "compliance_pct": pct,
            "compliant_controls": compliant,
            "total_controls": total,
            "open_findings": open_total,
        })

    # Custom
    custom_result = await db.execute(select(CustomFramework))
    for fw in custom_result.scalars().all():
        controls = await compliance_service.get_compliance_report(
            db, fw.slug, repository_id, custom_framework=fw
        )
        total = len(controls)
        compliant = sum(1 for c in controls if c.is_compliant)
        open_total = sum(c.open_count for c in controls)
        pct = round(compliant / total * 100, 1) if total else 100.0
        summary.append({
            "framework_id": fw.slug,
            "source": "custom",
            "name": fw.name,
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
    # Try built-in first
    if framework_id in compliance_service.FRAMEWORKS:
        result = await compliance_service.get_control_findings(db, framework_id, control_id, repository_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in framework '{framework_id}'")
        return result

    # Try custom framework
    fw = await _get_custom_framework(db, framework_id)
    result = await compliance_service.get_control_findings(
        db, framework_id, control_id, repository_id, custom_framework=fw
    )
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
    """Full compliance report for a specific framework (built-in or custom)."""
    # Built-in
    if framework_id in compliance_service.FRAMEWORKS:
        controls = await compliance_service.get_compliance_report(db, framework_id, repository_id)
        return _format_report(framework_id, compliance_service.FRAMEWORK_META[framework_id], controls)

    # Custom
    fw = await _get_custom_framework(db, framework_id)
    controls = await compliance_service.get_compliance_report(
        db, framework_id, repository_id, custom_framework=fw
    )
    meta = {"name": fw.name, "description": fw.description or ""}
    return _format_report(framework_id, meta, controls)


# ── Custom framework CRUD ─────────────────────────────────────────────────────

@router.post("/frameworks", status_code=201)
async def create_custom_framework(
    body: dict,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """
    Create a new custom compliance framework.

    Body: { "slug": "my-policy", "name": "My Security Policy", "description": "..." }
    """
    slug = str(body.get("slug", "")).strip().lower().replace(" ", "-")
    name = str(body.get("name", "")).strip()

    if not slug or not name:
        raise HTTPException(status_code=400, detail="'slug' and 'name' are required")
    if len(slug) > 100 or len(name) > 200:
        raise HTTPException(status_code=400, detail="slug (max 100) and name (max 200) length exceeded")
    if slug in compliance_service.FRAMEWORKS:
        raise HTTPException(status_code=409, detail=f"'{slug}' is a reserved built-in framework ID")

    # Check uniqueness
    existing = await db.execute(
        select(CustomFramework).where(CustomFramework.slug == slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Framework with slug '{slug}' already exists")

    fw = CustomFramework(
        slug=slug,
        name=name,
        description=body.get("description", ""),
        created_by=_key,
    )
    db.add(fw)
    await db.commit()
    await db.refresh(fw)
    return {"id": fw.id, "slug": fw.slug, "name": fw.name, "description": fw.description}


@router.get("/frameworks/{framework_id}/controls")
async def list_custom_controls(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List all controls in a custom framework."""
    fw = await _get_custom_framework(db, framework_id)
    result = await db.execute(
        select(CustomControl).where(CustomControl.framework_id == fw.id)
    )
    controls = result.scalars().all()
    return [_serialize_control(c) for c in controls]


@router.post("/frameworks/{framework_id}/controls", status_code=201)
async def add_custom_control(
    framework_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """
    Add a control to a custom framework.

    Body: {
      "control_id": "SEC-1.1",
      "title": "SQL Injection Prevention",
      "description": "...",
      "cwe_ids": ["CWE-89"],
      "owasp_categories": ["A03"]
    }
    """
    fw = await _get_custom_framework(db, framework_id)

    control_id = str(body.get("control_id", "")).strip()
    title = str(body.get("title", "")).strip()
    if not control_id or not title:
        raise HTTPException(status_code=400, detail="'control_id' and 'title' are required")

    cwe_ids = body.get("cwe_ids", [])
    owasp_categories = body.get("owasp_categories", [])
    if not isinstance(cwe_ids, list) or not isinstance(owasp_categories, list):
        raise HTTPException(status_code=400, detail="'cwe_ids' and 'owasp_categories' must be arrays")

    ctrl = CustomControl(
        framework_id=fw.id,
        control_id=control_id[:100],
        title=title[:300],
        description=str(body.get("description", ""))[:2000],
        cwe_ids_json=json.dumps(cwe_ids),
        owasp_categories_json=json.dumps(owasp_categories),
    )
    db.add(ctrl)
    await db.commit()
    await db.refresh(ctrl)
    return _serialize_control(ctrl)


@router.patch("/frameworks/{framework_id}/controls/{control_db_id}")
async def update_custom_control(
    framework_id: str,
    control_db_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """Update a custom control's title, description, CWE IDs, or OWASP categories."""
    fw = await _get_custom_framework(db, framework_id)
    ctrl_result = await db.execute(
        select(CustomControl).where(
            CustomControl.id == control_db_id,
            CustomControl.framework_id == fw.id,
        )
    )
    ctrl = ctrl_result.scalar_one_or_none()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    if "title" in body:
        ctrl.title = str(body["title"])[:300]
    if "description" in body:
        ctrl.description = str(body["description"])[:2000]
    if "cwe_ids" in body:
        if not isinstance(body["cwe_ids"], list):
            raise HTTPException(status_code=400, detail="'cwe_ids' must be an array")
        ctrl.cwe_ids_json = json.dumps(body["cwe_ids"])
    if "owasp_categories" in body:
        if not isinstance(body["owasp_categories"], list):
            raise HTTPException(status_code=400, detail="'owasp_categories' must be an array")
        ctrl.owasp_categories_json = json.dumps(body["owasp_categories"])

    await db.commit()
    await db.refresh(ctrl)
    return _serialize_control(ctrl)


@router.delete("/frameworks/{framework_id}", status_code=204)
async def delete_custom_framework(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ADMIN)),
):
    """Delete a custom framework and all its controls."""
    fw = await _get_custom_framework(db, framework_id)
    await db.delete(fw)
    await db.commit()


@router.delete("/frameworks/{framework_id}/controls/{control_db_id}", status_code=204)
async def delete_custom_control(
    framework_id: str,
    control_db_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """Remove a control from a custom framework."""
    fw = await _get_custom_framework(db, framework_id)
    ctrl_result = await db.execute(
        select(CustomControl).where(
            CustomControl.id == control_db_id,
            CustomControl.framework_id == fw.id,
        )
    )
    ctrl = ctrl_result.scalar_one_or_none()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")
    await db.delete(ctrl)
    await db.commit()


# ── Risk acceptance workflow endpoints ────────────────────────────────────────

@router.get("/risk-acceptances")
async def list_risk_acceptances(
    finding_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """List formal risk acceptance records."""
    from app.models.risk_acceptance import RiskAcceptance
    stmt = select(RiskAcceptance)
    if finding_id:
        stmt = stmt.where(RiskAcceptance.finding_id == finding_id)
    if status:
        stmt = stmt.where(RiskAcceptance.approval_status == status)
    result = await db.execute(stmt.order_by(RiskAcceptance.created_at.desc()))
    acceptances = result.scalars().all()
    return [_serialize_risk_acceptance(ra) for ra in acceptances]


@router.post("/risk-acceptances", status_code=201)
async def create_risk_acceptance(
    body: dict,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """
    Create a formal risk acceptance for a finding.

    Body: {
      "finding_id": "...",
      "business_justification": "...",
      "compensating_controls": "...",  # optional
      "evidence_url": "...",            # optional
      "approved_by": "...",             # optional — set when formally approved
      "expires_in_days": 180            # optional — 0 = no expiry
    }
    """
    from datetime import datetime, timezone
    from app.models.risk_acceptance import RiskAcceptance
    from app.models.finding import Finding
    from app.services.audit_service import log_event

    finding_id = str(body.get("finding_id", "")).strip()
    justification = str(body.get("business_justification", "")).strip()
    if not finding_id or not justification:
        raise HTTPException(status_code=400, detail="'finding_id' and 'business_justification' are required")

    # Verify finding exists
    finding_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = finding_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    now = datetime.now(timezone.utc)
    expires_in_days = int(body.get("expires_in_days", 180))
    expires_at = now + timedelta(days=expires_in_days) if expires_in_days > 0 else None

    approved_by = body.get("approved_by", "").strip() or None
    approval_status = "approved" if approved_by else "pending_approval"

    ra = RiskAcceptance(
        finding_id=finding_id,
        requested_by=_key,
        approved_by=approved_by,
        business_justification=justification[:5000],
        compensating_controls=str(body.get("compensating_controls", ""))[:2000] or None,
        evidence_url=str(body.get("evidence_url", ""))[:2000] or None,
        expires_at=expires_at,
        approved_at=now if approved_by else None,
        approval_status=approval_status,
    )
    db.add(ra)

    # Update finding status if approved
    if approved_by and finding.status in ("OPEN", "IN_REMEDIATION"):
        finding.status = "ACCEPTED_RISK"

    await log_event(
        db, actor=_key, action="risk_acceptance.created",
        resource_type="finding", resource_id=finding_id,
        metadata={
            "approval_status": approval_status,
            "approved_by": approved_by,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    await db.commit()
    await db.refresh(ra)
    return _serialize_risk_acceptance(ra)


@router.patch("/risk-acceptances/{acceptance_id}/approve")
async def approve_risk_acceptance(
    acceptance_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """Formally approve a pending risk acceptance."""
    from datetime import datetime, timezone
    from app.models.risk_acceptance import RiskAcceptance
    from app.models.finding import Finding
    from app.services.audit_service import log_event

    result = await db.execute(
        select(RiskAcceptance).where(RiskAcceptance.id == acceptance_id)
    )
    ra = result.scalar_one_or_none()
    if not ra:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    if ra.approval_status != "pending_approval":
        raise HTTPException(status_code=400, detail=f"Acceptance is already in state '{ra.approval_status}'")

    now = datetime.now(timezone.utc)
    ra.approved_by = _key
    ra.approved_at = now
    ra.approval_status = "approved"

    # Update associated finding
    finding_res = await db.execute(select(Finding).where(Finding.id == ra.finding_id))
    finding = finding_res.scalar_one_or_none()
    if finding and finding.status in ("OPEN", "IN_REMEDIATION"):
        finding.status = "ACCEPTED_RISK"

    await log_event(
        db, actor=_key, action="risk_acceptance.approved",
        resource_type="finding", resource_id=ra.finding_id,
        metadata={"acceptance_id": acceptance_id},
    )
    await db.commit()
    await db.refresh(ra)
    return _serialize_risk_acceptance(ra)


@router.patch("/risk-acceptances/{acceptance_id}/revoke")
async def revoke_risk_acceptance(
    acceptance_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """Revoke an active risk acceptance — finding returns to OPEN."""
    from app.models.risk_acceptance import RiskAcceptance
    from app.models.finding import Finding
    from app.services.audit_service import log_event

    result = await db.execute(
        select(RiskAcceptance).where(RiskAcceptance.id == acceptance_id)
    )
    ra = result.scalar_one_or_none()
    if not ra:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")

    ra.approval_status = "revoked"

    # Reopen the finding
    finding_res = await db.execute(select(Finding).where(Finding.id == ra.finding_id))
    finding = finding_res.scalar_one_or_none()
    if finding and finding.status == "ACCEPTED_RISK":
        finding.status = "OPEN"

    await log_event(
        db, actor=_key, action="risk_acceptance.revoked",
        resource_type="finding", resource_id=ra.finding_id,
        metadata={"acceptance_id": acceptance_id},
    )
    await db.commit()
    await db.refresh(ra)
    return _serialize_risk_acceptance(ra)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_custom_framework(db: AsyncSession, slug: str) -> CustomFramework:
    result = await db.execute(
        select(CustomFramework).where(CustomFramework.slug == slug)
    )
    fw = result.scalar_one_or_none()
    if not fw:
        raise HTTPException(status_code=404, detail=f"Framework '{slug}' not found")
    return fw


def _serialize_control(c: CustomControl) -> dict:
    return {
        "id": c.id,
        "framework_id": c.framework_id,
        "control_id": c.control_id,
        "title": c.title,
        "description": c.description,
        "cwe_ids": json.loads(c.cwe_ids_json or "[]"),
        "owasp_categories": json.loads(c.owasp_categories_json or "[]"),
    }


def _serialize_risk_acceptance(ra) -> dict:
    return {
        "id": ra.id,
        "finding_id": ra.finding_id,
        "requested_by": ra.requested_by,
        "approved_by": ra.approved_by,
        "approval_status": ra.approval_status,
        "business_justification": ra.business_justification,
        "compensating_controls": ra.compensating_controls,
        "evidence_url": ra.evidence_url,
        "expires_at": ra.expires_at.isoformat() if ra.expires_at else None,
        "approved_at": ra.approved_at.isoformat() if ra.approved_at else None,
        "created_at": ra.created_at.isoformat() if ra.created_at else None,
    }


def _format_report(framework_id: str, meta: dict, controls) -> dict:
    total_controls = len(controls)
    compliant_controls = sum(1 for c in controls if c.is_compliant)
    overall_pct = round(compliant_controls / total_controls * 100, 1) if total_controls else 100.0

    return {
        "framework_id": framework_id,
        "framework": meta,
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
