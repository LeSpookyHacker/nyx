"""Repositories API router."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_client_ip, require_api_key
from app.core.exceptions import GitHubError
from app.database import get_db
from app.models.repo_risk_history import RepoRiskHistory
from app.models.repository import Repository
from app.schemas.repository import RepositoryCreate, RepositoryResponse, RepositoryUpdate
from app.services import github_service
from app.services.audit_service import log_event

router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.get("", response_model=List[RepositoryResponse])
async def list_repositories(
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Repository).order_by(Repository.risk_score.desc()))
    return result.scalars().all()


@router.post("", response_model=RepositoryResponse, status_code=201)
async def add_repository(
    body: RepositoryCreate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Register a GitHub repository with Nyx and install the webhook."""
    # Check not already registered
    result = await db.execute(
        select(Repository).where(Repository.github_full_name == body.github_full_name)
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Repository already registered")

    # Fetch repo metadata from GitHub (optional — skipped if no token configured)
    gh_info: dict = {}
    try:
        gh_info = await github_service.get_repository_info(body.github_full_name)
    except Exception:
        pass  # No token or private repo — metadata will be empty, still functional

    repo = Repository(
        github_full_name=body.github_full_name,
        github_repo_id=gh_info.get("github_repo_id"),
        default_branch=gh_info.get("default_branch", "main"),
        description=gh_info.get("description"),
        language=gh_info.get("language"),
        is_private=gh_info.get("is_private", False),
        enabled_scanners=",".join(body.enabled_scanners),
    )

    # Register webhook
    try:
        webhook_id, webhook_secret = await github_service.register_webhook(body.github_full_name)
        repo.webhook_id = webhook_id
        repo.webhook_secret = webhook_secret
        repo.webhook_active = True
    except Exception:
        # Non-fatal — webhook can be registered later
        repo.webhook_active = False

    db.add(repo)
    await db.commit()
    await db.refresh(repo)
    await log_event(db, actor=_key, action="repository.registered", resource_type="repository",
        resource_id=repo.id, metadata={"github_full_name": repo.github_full_name})
    await db.commit()
    return repo


@router.get("/{repo_id}", response_model=RepositoryResponse)
async def get_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


@router.patch("/{repo_id}", response_model=RepositoryResponse)
async def update_repository(
    request: Request,
    repo_id: str,
    body: RepositoryUpdate,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    changes: dict = {}
    if body.enabled_scanners is not None:
        repo.enabled_scanners = ",".join(body.enabled_scanners)
        changes["enabled_scanners"] = body.enabled_scanners
    if body.default_branch is not None:
        repo.default_branch = body.default_branch
        changes["default_branch"] = body.default_branch

    await log_event(db, actor=_key, action="repository.updated", resource_type="repository",
        resource_id=repo_id,
        metadata={"github_full_name": repo.github_full_name, "changes": changes},
        ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(repo)
    return repo


@router.delete("/{repo_id}", status_code=204)
async def delete_repository(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    if repo.webhook_id and repo.webhook_active:
        try:
            await github_service.remove_webhook(repo.github_full_name, repo.webhook_id)
        except Exception:
            pass

    await log_event(db, actor=_key, action="repository.deleted", resource_type="repository",
        resource_id=repo_id, metadata={"github_full_name": repo.github_full_name})
    await db.delete(repo)
    await db.commit()


@router.post("/{repo_id}/sync-code-scanning")
async def sync_code_scanning(
    request: Request,
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Manually trigger a GitHub Code Scanning sync for this repository.

    Fetches all open alerts from GitHub's Code Scanning API and imports
    them as findings.  Requires GITHUB_TOKEN with `security_events` scope.
    """
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    from app.services.code_scanning_service import sync_repository
    outcome = await sync_repository(repo.id, repo.github_full_name, force=True)
    await log_event(db, actor=_key, action="repository.code_scanning_synced",
        resource_type="repository", resource_id=repo_id,
        metadata={"github_full_name": repo.github_full_name,
                  "imported": outcome.get("imported", 0) if isinstance(outcome, dict) else None},
        ip_address=get_client_ip(request))
    await db.commit()
    return outcome


@router.post("/{repo_id}/webhook", response_model=RepositoryResponse)
async def refresh_webhook(
    request: Request,
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Re-register the GitHub webhook for a repository."""
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    try:
        webhook_id, webhook_secret = await github_service.register_webhook(repo.github_full_name)
        repo.webhook_id = webhook_id
        repo.webhook_secret = webhook_secret
        repo.webhook_active = True
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to register webhook")

    await log_event(db, actor=_key, action="repository.webhook_refreshed",
        resource_type="repository", resource_id=repo_id,
        metadata={"github_full_name": repo.github_full_name, "webhook_id": str(webhook_id)},
        ip_address=get_client_ip(request))
    await db.commit()
    await db.refresh(repo)
    return repo


@router.post("/{repo_id}/push-workflow")
async def push_workflow(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Push (create or update) the canonical nyx-scan.yml workflow file into the
    repository via the GitHub API.  The repo_id is hardcoded in the file so
    users only need NYX_URL (var) and NYX_API_KEY (secret) configured in GitHub.
    ZAP DAST is enabled by setting the NYX_ZAP_TARGET repository variable.
    """
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    try:
        outcome = await github_service.push_nyx_workflow(
            repo.github_full_name,
            repo_id,
            repo.default_branch,
        )
    except GitHubError as e:
        import logging as _logging
        _logging.getLogger("nyx.repositories").error(
            "GitHub API error pushing workflow for repo %s: %s", repo_id, e
        )
        raise HTTPException(status_code=502, detail="Failed to push workflow to GitHub")
    await log_event(db, actor=_key, action="repository.workflow_pushed", resource_type="repository",
        resource_id=repo_id, metadata={"github_full_name": repo.github_full_name, "created": outcome["created"]})
    await db.commit()
    return {
        "created": outcome["created"],
        "html_url": outcome["html_url"],
        "repository": repo.github_full_name,
    }


@router.post("/{repo_id}/detect-scanners")
async def detect_scanners(
    repo_id: str,
    auto_apply: bool = Query(False, description="Automatically update enabled_scanners with detected tools"),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    Analyse the repository's file tree on GitHub and detect which scanners
    are applicable.  Pass auto_apply=true to update enabled_scanners in the DB.

    The canonical nyx-scan.yml uses hashFiles() conditions so Hadolint/Snyk/etc
    activate automatically when their trigger files exist — this endpoint keeps
    the DB in sync so Nyx's UI and scan records stay accurate.
    """
    result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    from app.services.scanner_detection_service import (
        detect_from_github_tree, merge_scanners, SCANNER_TRIGGERS
    )

    detections = await detect_from_github_tree(repo.github_full_name)
    current = repo.scanner_list
    updated, added = merge_scanners(current, detections)

    if auto_apply and added:
        repo.enabled_scanners = ",".join(sorted(updated))
        await log_event(
            db, actor=_key,
            action="repository.scanners_auto_detected",
            resource_type="repository",
            resource_id=repo_id,
            metadata={"added": added, "reasons": detections, "github_full_name": repo.github_full_name},
        )
        await db.commit()

    return {
        "repository": repo.github_full_name,
        "current_scanners": current,
        "recommended_scanners": sorted(updated),
        "newly_detected": added,
        "detection_reasons": detections,
        "applied": auto_apply and bool(added),
    }


@router.get("/{repo_id}/risk-history")
async def get_risk_history(
    repo_id: str,
    days: int = Query(30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Historical risk score snapshots for a repository."""
    from datetime import datetime, timedelta, timezone
    from datetime import date as date_type
    since = datetime.now(timezone.utc).date() - timedelta(days=days)
    result = await db.execute(
        select(RepoRiskHistory)
        .where(RepoRiskHistory.repository_id == repo_id, RepoRiskHistory.snapshot_date >= since)
        .order_by(RepoRiskHistory.snapshot_date)
    )
    rows = result.scalars().all()
    return [
        {
            "snapshot_date": str(r.snapshot_date),
            "risk_score": r.risk_score,
            "open_critical": r.open_critical,
            "open_high": r.open_high,
            "open_medium": r.open_medium,
            "open_low": r.open_low,
            "total_findings": r.total_findings,
        }
        for r in rows
    ]
