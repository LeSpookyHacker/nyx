"""
GitHub Code Scanning sync service.

Polls the GitHub Code Scanning API for each registered repository and imports
open alerts as Nyx findings.  Requires GITHUB_TOKEN with `security_events` scope
(or `repo` scope for private repos).

Two entry points:
  - sync_repository(repo)        called per-repo from the router or background loop
  - sync_all_repositories()      called by the background polling loop
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_settings

logger = logging.getLogger("nyx.code_scanning")

# In-memory rate-limit: track last successful sync per repo_id.
# Resets on restart — intentional, keeps it simple with no DB schema changes.
_last_synced: Dict[str, datetime] = {}

_GITHUB_API = "https://api.github.com"


async def sync_repository(
    repo_id: str,
    github_full_name: str,
    *,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Fetch all open Code Scanning alerts for one repo and submit them as a scan.

    Returns a status dict suitable for returning from the API endpoint.
    """
    settings = get_settings()
    if not settings.GITHUB_TOKEN:
        return {"status": "skipped", "reason": "GITHUB_TOKEN not configured"}

    # Respect minimum poll interval unless forced
    if not force:
        last = _last_synced.get(repo_id)
        if last:
            age = (datetime.now(timezone.utc) - last).total_seconds()
            if age < settings.CODE_SCANNING_POLL_INTERVAL:
                return {"status": "skipped", "reason": "synced recently", "next_sync_in": int(settings.CODE_SCANNING_POLL_INTERVAL - age)}

    owner, repo_name = github_full_name.split("/", 1)
    alerts = await _fetch_alerts(owner, repo_name, settings.GITHUB_TOKEN)

    if alerts is None:
        return {"status": "skipped", "reason": "Code Scanning not enabled for this repository"}

    if not alerts:
        _last_synced[repo_id] = datetime.now(timezone.utc)
        return {"status": "ok", "alerts_found": 0, "scan_created": False}

    # Submit to the scan worker
    scan_id = await _submit_scan(repo_id, alerts)
    _last_synced[repo_id] = datetime.now(timezone.utc)

    return {
        "status": "ok",
        "alerts_found": len(alerts),
        "scan_created": True,
        "scan_id": scan_id,
    }


async def sync_all_repositories() -> None:
    """Sync Code Scanning alerts for every registered repository."""
    from sqlalchemy import select
    from app.database import AsyncSessionLocal
    from app.models.repository import Repository

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Repository))
        repos = result.scalars().all()

    logger.info(f"Code Scanning sync: checking {len(repos)} repositories")
    for repo in repos:
        try:
            result = await sync_repository(repo.id, repo.github_full_name)
            if result["status"] == "ok" and result.get("alerts_found", 0) > 0:
                logger.info(
                    f"Code Scanning sync: {repo.github_full_name} — "
                    f"{result['alerts_found']} alerts imported"
                )
        except Exception as e:
            logger.warning(f"Code Scanning sync failed for {repo.github_full_name}: {e}")
        # Brief pause between repos to avoid hammering the API
        await asyncio.sleep(1)


async def run_poll_loop() -> None:
    """
    Background asyncio task — runs forever, polling on CODE_SCANNING_POLL_INTERVAL.
    Started from the FastAPI lifespan if CODE_SCANNING_SYNC_ENABLED=true.
    """
    settings = get_settings()
    logger.info(
        f"Code Scanning poll loop started "
        f"(interval: {settings.CODE_SCANNING_POLL_INTERVAL}s)"
    )
    # Initial delay so startup isn't immediately hammered
    await asyncio.sleep(60)
    while True:
        try:
            await sync_all_repositories()
        except Exception as e:
            logger.error(f"Code Scanning poll loop error: {e}")
        await asyncio.sleep(settings.CODE_SCANNING_POLL_INTERVAL)


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _fetch_alerts(
    owner: str, repo: str, token: str
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch all open Code Scanning alerts, paginated.
    Returns None if Code Scanning is not enabled (404).
    """
    alerts: List[Dict[str, Any]] = []
    page = 1
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient(base_url=_GITHUB_API, headers=headers, timeout=30.0) as client:
        while True:
            resp = await client.get(
                f"/repos/{owner}/{repo}/code-scanning/alerts",
                params={"state": "open", "per_page": 100, "page": page},
            )
            if resp.status_code == 404:
                return None  # Code Scanning not enabled
            if resp.status_code == 403:
                logger.warning(
                    f"GitHub 403 for {owner}/{repo} code scanning — "
                    "token may lack `security_events` scope"
                )
                return []
            resp.raise_for_status()

            batch = resp.json()
            if not batch:
                break
            alerts.extend(batch)
            if len(batch) < 100:
                break
            page += 1

    return alerts


async def _submit_scan(repo_id: str, alerts: List[Dict[str, Any]]) -> str:
    """Create a Scan record and process the alerts through the scan worker."""
    from datetime import datetime, timezone

    from sqlalchemy import select

    from app.core.constants import ScanStatus, ScanTrigger
    from app.database import AsyncSessionLocal
    from app.models.scan import Scan
    from app.workers.scan_worker import process_scan_results

    async with AsyncSessionLocal() as db:
        scan = Scan(
            repository_id=repo_id,
            scanner="CODE_SCANNING",
            trigger=ScanTrigger.SCHEDULED.value,
            status=ScanStatus.PENDING.value,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        scan_id = scan.id

    # Process outside the session (scan_worker opens its own)
    await process_scan_results(scan_id, alerts)
    return scan_id
