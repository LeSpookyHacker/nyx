"""Scans API router."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, field_validator
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import ScanStatus, ScanTrigger
from app.core.limiter import limiter
from app.core.security import require_api_key, require_scope, verify_submission_hmac, SCOPE_SCANNER, SCOPE_ANALYST
from app.database import get_db
from app.models.repository import Repository
from app.models.scan import Scan
from app.schemas.scan import ScanResponse, ScanTriggerRequest
from app.workers.scan_worker import process_scan_results
from app.services.audit_service import log_event

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    repository_id: Optional[str] = Query(None, max_length=36, pattern=r"^[0-9a-f-]{36}$"),
    scanner: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    stmt = select(Scan).order_by(desc(Scan.created_at)).limit(200)
    if repository_id:
        stmt = stmt.where(Scan.repository_id == repository_id)
    if scanner:
        stmt = stmt.where(Scan.scanner == scanner.upper())
    result = await db.execute(stmt)
    return result.scalars().all()


def _check_json_depth(obj: Any, max_depth: int = 20, _current: int = 0) -> None:
    """Reject excessively nested JSON objects to prevent JSON bomb DoS (H3)."""
    if _current > max_depth:
        raise ValueError(f"JSON payload exceeds maximum nesting depth of {max_depth}")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_json_depth(v, max_depth, _current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_json_depth(item, max_depth, _current + 1)


class ScanImportJsonRequest(BaseModel):
    repository_id: str
    scanner: str
    git_ref: Optional[str] = None
    data: Any  # raw scanner output — dict or list

    @field_validator("data")
    @classmethod
    def validate_depth(cls, v: Any) -> Any:
        try:
            _check_json_depth(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return v


@router.post("/import-json", response_model=ScanResponse, status_code=202)
@limiter.limit("30/minute")
async def import_scan_results_json(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_scope(SCOPE_SCANNER, SCOPE_ANALYST)),
):
    """
    Import raw scanner JSON output via a JSON body (CI/CD-friendly alternative to multipart).

    Optionally include X-Nyx-Submission-HMAC header for provenance verification:
        HMAC-SHA256(key=repo_webhook_secret, msg=SHA256(request_body_bytes))
    Verified scans are flagged as submission_verified=True in the database.

    Example (GitHub Actions / curl):
        jq -n --arg repo "$REPO_ID" --arg scanner "SEMGREP" --arg ref "$GIT_REF" \\
               --slurpfile data results.json \\
           '{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$data[0]}' \\
           > /tmp/nyx_payload.json
        HMAC=$(openssl dgst -sha256 -binary /tmp/nyx_payload.json \\
          | openssl dgst -sha256 -hmac "$NYX_WEBHOOK_SECRET" | awk '{print $2}')
        curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
             -H "Content-Type: application/json" -H "X-API-Key: $NYX_API_KEY" \\
             -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
             -d @/tmp/nyx_payload.json
    """
    _MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB
    # SEC-209: read body then check actual byte length — the Content-Length-only check
    # is bypassable via chunked transfer encoding (no Content-Length header). The
    # body_size_limit_middleware in main.py enforces this at the ASGI level too, so
    # chunked bodies exceeding the limit are already truncated before reaching here.
    # This len() check is a defence-in-depth layer that works for all transfer modes.
    body_bytes = await request.body()
    if len(body_bytes) > _MAX_IMPORT_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large (max 50 MB)")
    try:
        body = ScanImportJsonRequest.model_validate_json(body_bytes)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid request body: {exc}") from exc

    repo_result = await db.execute(select(Repository).where(Repository.id == body.repository_id))
    repo = repo_result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Verify optional submission HMAC for provenance checking
    submission_hmac_header = request.headers.get("X-Nyx-Submission-HMAC")
    submission_verified = False
    if repo.webhook_secret:
        submission_verified = verify_submission_hmac(body_bytes, submission_hmac_header, repo.webhook_secret)

    scan = Scan(
        repository_id=body.repository_id,
        scanner=body.scanner.upper(),
        trigger=ScanTrigger.IMPORT.value,
        status=ScanStatus.PENDING.value,
        git_ref=body.git_ref,
        raw_output=json.dumps(body.data),
        started_at=datetime.now(timezone.utc),
        submission_verified=submission_verified,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(process_scan_results, scan.id, body.data)
    await log_event(db, actor=_key, action="scan.imported", resource_type="scan",
        resource_id=scan.id,
        metadata={
            "scanner": scan.scanner,
            "repository_id": body.repository_id,
            "git_ref": body.git_ref,
            "submission_verified": submission_verified,
        })
    await db.commit()
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/import", response_model=ScanResponse, status_code=202)
@limiter.limit("30/minute")
async def import_scan_results(
    request: Request,
    repository_id: str = Form(...),
    scanner: str = Form(...),
    git_ref: Optional[str] = Form(None),
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Import raw scanner JSON output for a repository.
    The file should be the direct JSON output from the scanner
    (e.g., `semgrep --json`, `trivy fs --format json`).
    """
    # Verify repo exists
    repo_result = await db.execute(select(Repository).where(Repository.id == repository_id))
    repo = repo_result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Parse uploaded JSON — enforce 10 MB cap to prevent memory exhaustion (H-5)
    _MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
    try:
        content = await file.read(_MAX_UPLOAD_BYTES + 1)
        if len(content) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Upload exceeds 10 MB limit")
        raw_data = json.loads(content)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    # Create scan record
    scan = Scan(
        repository_id=repository_id,
        scanner=scanner.upper(),
        trigger=ScanTrigger.IMPORT.value,
        status=ScanStatus.PENDING.value,
        git_ref=git_ref,
        raw_output=json.dumps(raw_data),
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Process in background
    background_tasks.add_task(process_scan_results, scan.id, raw_data)

    return scan


@router.get("/{scan_id}/raw")
async def get_scan_raw_output(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Download the original scanner JSON output."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.raw_output:
        raise HTTPException(status_code=404, detail="No raw output stored for this scan")
    return json.loads(scan.raw_output)
