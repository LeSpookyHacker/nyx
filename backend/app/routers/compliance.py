"""Compliance mapping and reporting API — built-in and custom frameworks."""
from __future__ import annotations

import json
import re as _re
from datetime import timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key, require_scope, SCOPE_ADMIN, SCOPE_ANALYST
from app.database import get_db
from app.models.custom_compliance import CustomControl, CustomFramework
from app.services import compliance_service

router = APIRouter(prefix="/compliance", tags=["compliance"])


# ─── Request models (SEC-315 through SEC-321) ─────────────────────────────────

class CustomFrameworkCreate(BaseModel):
    slug: str = Field(..., max_length=100, pattern=r"^[a-z0-9][a-z0-9\-]{0,98}[a-z0-9]$")
    name: str = Field(..., max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class CustomControlCreate(BaseModel):
    title: str = Field(..., max_length=300)
    description: Optional[str] = Field(None, max_length=2000)
    cwe_ids: List[str] = Field(default_factory=list, max_length=50)
    owasp_categories: List[str] = Field(default_factory=list, max_length=20)
    severity_guidance: Optional[str] = Field(None, max_length=1000)

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def validate_cwe_ids(cls, v: list) -> list:
        for item in v:
            if not isinstance(item, str) or not _re.match(r"^CWE-\d+$", item):
                raise ValueError(f"Invalid CWE ID: {item!r} — must match CWE-\\d+")
        return v

    @field_validator("owasp_categories", mode="before")
    @classmethod
    def validate_owasp_categories(cls, v: list) -> list:
        for item in v:
            if not isinstance(item, str) or not _re.match(r"^A\d{2}:\d{4}$|^[A-Z]\d{2}$", item):
                raise ValueError(f"Invalid OWASP category: {item!r}")
        return v


class CustomControlUpdate(BaseModel):
    title: Optional[str] = Field(None, max_length=300)
    description: Optional[str] = Field(None, max_length=2000)
    cwe_ids: Optional[List[str]] = Field(None, max_length=50)
    owasp_categories: Optional[List[str]] = Field(None, max_length=20)
    severity_guidance: Optional[str] = Field(None, max_length=1000)

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def validate_cwe_ids(cls, v: Optional[list]) -> Optional[list]:
        if v is None:
            return v
        for item in v:
            if not isinstance(item, str) or not _re.match(r"^CWE-\d+$", item):
                raise ValueError(f"Invalid CWE ID: {item!r}")
        return v

    @field_validator("owasp_categories", mode="before")
    @classmethod
    def validate_owasp_categories(cls, v: Optional[list]) -> Optional[list]:
        if v is None:
            return v
        for item in v:
            if not isinstance(item, str) or not _re.match(r"^A\d{2}:\d{4}$|^[A-Z]\d{2}$", item):
                raise ValueError(f"Invalid OWASP category: {item!r}")
        return v


class RiskAcceptanceCreate(BaseModel):
    finding_id: str = Field(..., max_length=255)
    business_justification: str = Field(..., max_length=5000)
    expires_in_days: int = Field(180, ge=0, le=730)  # SEC-318: max 2 years
    evidence_url: Optional[str] = Field(None, max_length=2000)
    compensating_controls: Optional[str] = Field(None, max_length=2000)

    @field_validator("evidence_url")
    @classmethod
    def validate_evidence_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if parsed.scheme not in ("https", "http", ""):
            raise ValueError("evidence_url must be an http or https URL")
        return v


class ApproveRiskAcceptanceRequest(BaseModel):
    pass  # SEC-321: typed model prevents unbounded body ingestion


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
    body: CustomFrameworkCreate,  # SEC-315
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_ANALYST, SCOPE_ADMIN)),
):
    """
    Create a new custom compliance framework.

    Body: { "slug": "my-policy", "name": "My Security Policy", "description": "..." }
    """
    slug = body.slug
    name = body.name

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
        description=body.description or "",
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
    body: CustomControlCreate,  # SEC-316
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

    ctrl = CustomControl(
        framework_id=fw.id,
        control_id="",
        title=body.title,
        description=body.description or "",
        cwe_ids_json=json.dumps(body.cwe_ids),
        owasp_categories_json=json.dumps(body.owasp_categories),
    )
    db.add(ctrl)
    await db.commit()
    await db.refresh(ctrl)
    return _serialize_control(ctrl)


@router.patch("/frameworks/{framework_id}/controls/{control_db_id}")
async def update_custom_control(
    framework_id: str,
    control_db_id: str,
    body: CustomControlUpdate,  # SEC-317
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

    if body.title is not None:
        ctrl.title = body.title
    if body.description is not None:
        ctrl.description = body.description
    if body.cwe_ids is not None:
        ctrl.cwe_ids_json = json.dumps(body.cwe_ids)
    if body.owasp_categories is not None:
        ctrl.owasp_categories_json = json.dumps(body.owasp_categories)

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
    body: RiskAcceptanceCreate,  # SEC-318
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
      "expires_in_days": 180            # optional — 0 = no expiry, max 730 (2 years)
    }
    """
    from datetime import datetime, timezone
    from app.models.risk_acceptance import RiskAcceptance
    from app.models.finding import Finding
    from app.services.audit_service import log_event

    finding_id = body.finding_id
    justification = body.business_justification

    # Verify finding exists
    finding_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = finding_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    now = datetime.now(timezone.utc)
    expires_in_days = body.expires_in_days
    expires_at = now + timedelta(days=expires_in_days) if expires_in_days > 0 else None

    # SEC-218: never allow self-approval at create time — always require a separate
    # /approve call from a second principal. Accepting approved_by in the create body
    # would let a single ANALYST bypass the separation-of-duties control.
    approval_status = "pending_approval"

    ra = RiskAcceptance(
        finding_id=finding_id,
        requested_by=_key,
        approved_by=None,
        business_justification=justification,
        compensating_controls=body.compensating_controls,
        evidence_url=body.evidence_url,
        expires_at=expires_at,
        approved_at=None,
        approval_status=approval_status,
    )
    db.add(ra)

    await log_event(
        db, actor=_key, action="risk_acceptance.created",
        resource_type="finding", resource_id=finding_id,
        metadata={
            "approval_status": approval_status,
            "approved_by": None,  # SEC-218: always pending at create time; set by /approve
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    await db.commit()
    await db.refresh(ra)
    return _serialize_risk_acceptance(ra)


@router.patch("/risk-acceptances/{acceptance_id}/approve")
async def approve_risk_acceptance(
    acceptance_id: str,
    body: ApproveRiskAcceptanceRequest,  # SEC-321
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
