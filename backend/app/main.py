"""
Nyx — Security Findings Dashboard
FastAPI application entry point.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.core.limiter import limiter
from app.core.security import warn_insecure_config
from app.database import init_db
from app.routers import (
    audit, api_keys, compliance, dashboard, findings, jira, remediation,
    repositories, reports, sbom, scans, schedules, sla_policies, webhooks,
    regression_alerts,
)
# Ensure new models are registered with SQLAlchemy metadata
from app.models import repo_risk_history, scan_schedule, sla_policy, suppression_pattern  # noqa: F401
from app.models.api_key import ApiKey  # noqa: F401 — register api_keys table

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("nyx")

# ── Rate limiter (shared instance from app.core.limiter) ───────────────────────


async def _risk_history_snapshot_loop() -> None:
    """Take daily risk score snapshots for all repositories."""
    import asyncio
    from datetime import date
    from sqlalchemy import func, select
    from app.database import AsyncSessionLocal
    from app.models.finding import Finding as FindingModel
    from app.models.repository import Repository
    from app.models.repo_risk_history import RepoRiskHistory

    await asyncio.sleep(15)  # Brief delay on startup
    while True:
        try:
            async with AsyncSessionLocal() as db:
                repos_result = await db.execute(select(Repository))
                repos = repos_result.scalars().all()
                today = date.today()
                for repo in repos:
                    total_q = await db.execute(
                        select(func.count()).select_from(FindingModel).where(
                            FindingModel.repository_id == repo.id
                        )
                    )
                    total = total_q.scalar_one()
                    existing = await db.execute(
                        select(RepoRiskHistory).where(
                            RepoRiskHistory.repository_id == repo.id,
                            RepoRiskHistory.snapshot_date == today,
                        )
                    )
                    snap = existing.scalar_one_or_none()
                    if snap:
                        snap.risk_score = repo.risk_score
                        snap.open_critical = repo.open_critical
                        snap.open_high = repo.open_high
                        snap.open_medium = repo.open_medium
                        snap.open_low = repo.open_low
                        snap.open_info = repo.open_info
                        snap.total_findings = total
                    else:
                        db.add(RepoRiskHistory(
                            repository_id=repo.id,
                            snapshot_date=today,
                            risk_score=repo.risk_score,
                            open_critical=repo.open_critical,
                            open_high=repo.open_high,
                            open_medium=repo.open_medium,
                            open_low=repo.open_low,
                            open_info=repo.open_info,
                            total_findings=total,
                        ))
                await db.commit()
                logger.info("Risk history snapshot completed for %d repos", len(repos))
        except Exception:
            logger.exception("Error in risk history snapshot loop")
        await asyncio.sleep(86400)  # Daily


async def _sla_breach_check_loop() -> None:
    """Hourly: find SLA-breached findings and escalate per policy."""
    import asyncio
    from datetime import datetime, timezone
    from sqlalchemy import select, update
    from app.database import AsyncSessionLocal
    from app.models.finding import Finding
    from app.models.sla_policy import SlaPolicy
    from app.services.notification_service import notify_sla_breach

    while True:
        await asyncio.sleep(3600)
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.now(timezone.utc)
                result = await db.execute(
                    select(Finding).where(
                        Finding.status == "OPEN",
                        Finding.sla_breach_at <= now,
                        Finding.sla_breach_at.isnot(None),
                        Finding.sla_notified_at.is_(None),
                    ).limit(200)
                )
                breached = result.scalars().all()

                for finding in breached:
                    # Look up applicable policy (repo-specific first)
                    policy = None
                    for repo_filter in [finding.repository_id, None]:
                        pol_result = await db.execute(
                            select(SlaPolicy).where(
                                SlaPolicy.enabled == True,  # noqa: E712
                                SlaPolicy.repository_id == repo_filter,
                                SlaPolicy.severity.in_([finding.severity, "ALL"]),
                            ).limit(1)
                        )
                        policy = pol_result.scalar_one_or_none()
                        if policy:
                            break

                    action = policy.escalation_action if policy else "NOTIFY"
                    days_overdue = int((now - finding.sla_breach_at).days) if finding.sla_breach_at else 0

                    from app.models.repository import Repository
                    repo_res = await db.execute(
                        select(Repository).where(Repository.id == finding.repository_id)
                    )
                    repo = repo_res.scalar_one_or_none()
                    repo_name = repo.github_full_name if repo else finding.repository_id

                    if action in ("NOTIFY", "BOTH"):
                        asyncio.create_task(notify_sla_breach(
                            finding.id, finding.title, finding.severity, repo_name, days_overdue
                        ))

                    if action in ("JIRA", "BOTH"):
                        from app.models.jira_link import JiraLink
                        existing_link = await db.execute(
                            select(JiraLink).where(JiraLink.finding_id == finding.id)
                        )
                        if not existing_link.scalar_one_or_none():
                            try:
                                from app.services import jira_service
                                ticket = await jira_service.create_jira_ticket(finding)
                                db.add(JiraLink(
                                    finding_id=finding.id,
                                    jira_issue_key=ticket["key"],
                                    jira_issue_url=ticket["url"],
                                    jira_project_key=policy.jira_project_key or ticket["key"].rsplit("-", 1)[0],
                                    jira_status=ticket.get("status"),
                                    jira_priority=ticket.get("priority"),
                                ))
                            except Exception:
                                pass

                    finding.sla_notified_at = now

                await db.commit()
                if breached:
                    logger.info("SLA breach check: escalated %d finding(s)", len(breached))
        except Exception:
            logger.exception("Error in SLA breach check loop")


async def _scan_schedule_loop() -> None:
    """Every 5 minutes: trigger any due scan schedules."""
    import asyncio
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from app.database import AsyncSessionLocal
    from app.models.scan_schedule import ScanSchedule
    from app.models.scan import Scan
    from app.core.constants import ScanStatus, ScanTrigger
    from app.workers.scan_worker import process_scan_results

    while True:
        await asyncio.sleep(300)  # Check every 5 minutes
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.now(timezone.utc)
                result = await db.execute(
                    select(ScanSchedule).where(
                        ScanSchedule.enabled == True,  # noqa: E712
                        (ScanSchedule.next_run_at <= now) | ScanSchedule.next_run_at.is_(None),
                    )
                )
                due = result.scalars().all()

                for schedule in due:
                    scanners = [s.strip() for s in schedule.enabled_scanners.split(",") if s.strip()]
                    for scanner in scanners:
                        scan = Scan(
                            repository_id=schedule.repository_id,
                            scanner=scanner,
                            trigger=ScanTrigger.WEBHOOK.value,
                            status=ScanStatus.PENDING.value,
                            started_at=now,
                        )
                        db.add(scan)
                        await db.flush()
                        asyncio.create_task(process_scan_results(scan.id, {}))

                    schedule.last_run_at = now
                    schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)

                if due:
                    await db.commit()
                    logger.info("Scan schedules: triggered %d schedule(s)", len(due))
        except Exception:
            logger.exception("Error in scan schedule loop")


async def _suppression_expiry_loop() -> None:
    """Periodically reopen findings whose suppression or accepted-risk period has expired (M-7)."""
    from datetime import datetime, timezone
    from sqlalchemy import update, or_
    from app.database import AsyncSessionLocal
    from app.models.finding import Finding

    while True:
        await asyncio.sleep(3600)  # Check every hour
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.now(timezone.utc)
                # Reopen expired SUPPRESSED findings
                suppressed_result = await db.execute(
                    update(Finding)
                    .where(
                        Finding.status == "SUPPRESSED",
                        Finding.resolved_at.isnot(None),
                        Finding.resolved_at < now,
                    )
                    .values(
                        status="OPEN",
                        suppression_reason=None,
                        suppressed_by=None,
                        suppressed_at=None,
                        resolved_at=None,
                    )
                )
                # Reopen expired ACCEPTED_RISK findings
                accepted_result = await db.execute(
                    update(Finding)
                    .where(
                        Finding.status == "ACCEPTED_RISK",
                        Finding.resolved_at.isnot(None),
                        Finding.resolved_at < now,
                    )
                    .values(
                        status="OPEN",
                        resolved_at=None,
                    )
                )
                await db.commit()
                if suppressed_result.rowcount:
                    logger.info("Suppression expiry: reopened %d suppressed finding(s)", suppressed_result.rowcount)
                if accepted_result.rowcount:
                    logger.info("Accepted-risk expiry: reopened %d finding(s) for re-review", accepted_result.rowcount)
        except Exception:
            logger.exception("Error in suppression expiry loop")


async def _seed_api_key_from_env() -> None:
    """
    On first boot, register NYX_API_KEY as a DB-backed key named 'bootstrap'
    so the DB auth path is immediately active without manual provisioning.
    Only runs when the api_keys table is empty — safe to call on every startup.
    """
    import hashlib as _hashlib
    from sqlalchemy import func, select as sa_select
    from app.database import AsyncSessionLocal
    from app.models.api_key import ApiKey

    if not settings.NYX_API_KEY:
        return

    try:
        async with AsyncSessionLocal() as db:
            count_result = await db.execute(sa_select(func.count()).select_from(ApiKey))
            if count_result.scalar_one() == 0:
                key_hash = _hashlib.sha256(settings.NYX_API_KEY.encode()).hexdigest()
                db.add(ApiKey(
                    name="bootstrap",
                    key_hash=key_hash,
                    is_active=True,
                    created_by="system",
                    scopes="admin",
                ))
                await db.commit()
                logger.info("Seeded bootstrap API key from NYX_API_KEY environment variable")
    except Exception:
        logger.exception("Failed to seed bootstrap API key — DB auth will fall back to env var")


async def _api_key_expiry_warning_loop() -> None:
    """Daily: warn about API keys expiring within 7 days."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from app.database import AsyncSessionLocal
    from app.models.api_key import ApiKey
    from app.services.audit_service import log_event

    await asyncio.sleep(60)  # Brief startup delay
    while True:
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.now(timezone.utc)
                soon = now + timedelta(days=7)
                result = await db.execute(
                    select(ApiKey).where(
                        ApiKey.is_active.is_(True),
                        ApiKey.expires_at.isnot(None),
                        ApiKey.expires_at <= soon,
                        ApiKey.expires_at > now,
                    )
                )
                expiring = result.scalars().all()
                for key in expiring:
                    days_left = (key.expires_at - now).days
                    logger.warning(
                        "API_KEY_EXPIRY_SOON key_id=%s name=%r days_left=%d",
                        key.id, key.name, days_left,
                    )
                    await log_event(
                        db,
                        actor="system",
                        action="api_key.expiry_warning",
                        resource_type="api_key",
                        resource_id=key.id,
                        metadata={"name": key.name, "days_left": days_left, "scopes": key.scopes},
                    )
                if expiring:
                    await db.commit()
        except Exception:
            logger.exception("Error in API key expiry warning loop")
        await asyncio.sleep(86400)  # Daily


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🌑 Nyx starting up...")

    # Surface security misconfigurations at startup
    warn_insecure_config()

    await init_db()
    await _seed_api_key_from_env()

    tasks = []

    # Suppression expiry — reopen findings whose suppression period has elapsed (M-7)
    tasks.append(asyncio.create_task(_suppression_expiry_loop()))

    # Risk history snapshots — daily snapshot of per-repo risk scores
    tasks.append(asyncio.create_task(_risk_history_snapshot_loop()))

    # SLA breach escalation — hourly check and escalate breached findings
    if settings.SLA_CHECK_ENABLED:
        tasks.append(asyncio.create_task(_sla_breach_check_loop()))

    # Scan schedule runner — triggers due scheduled scans every 5 minutes
    if settings.SCAN_SCHEDULES_ENABLED:
        tasks.append(asyncio.create_task(_scan_schedule_loop()))

    # API key expiry warnings — daily check for keys expiring within 7 days
    tasks.append(asyncio.create_task(_api_key_expiry_warning_loop()))

    if settings.CODE_SCANNING_SYNC_ENABLED:
        from app.services.code_scanning_service import run_poll_loop
        tasks.append(asyncio.create_task(run_poll_loop()))
        logger.info("Code Scanning background poll loop started")

        from app.services.dependabot_service import run_poll_loop as dependabot_poll_loop
        tasks.append(asyncio.create_task(dependabot_poll_loop()))
        logger.info("Dependabot background poll loop started")

    yield

    for t in tasks:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    logger.info("🌑 Nyx shutting down.")


app = FastAPI(
    title="Nyx Security Dashboard",
    description=(
        "Nyx aggregates security scanner findings, prioritizes them, "
        "and provides AI-powered remediation with GitHub integration."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
)

# ── Rate limiting ──────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ───────────────────────────────────────────────────────────────────────
# allow_credentials=True is required so the browser sends X-API-Key from the SPA.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization", "Accept"],
    expose_headers=["Content-Disposition"],
)


# ── Request body size limit ────────────────────────────────────────────────────
_MAX_BODY_BYTES = 52_428_800  # 50 MB — protects import-json and other JSON endpoints


@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large (max 50 MB)"})
    return await call_next(request)


# ── Security headers ───────────────────────────────────────────────────────────
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # HTTPS enforcement
    if settings.HTTPS_ONLY and request.url.scheme == "http":
        url = request.url.replace(scheme="https")
        return JSONResponse(
            status_code=301,
            headers={"Location": str(url)},
            content={"detail": "HTTPS required"},
        )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"  # Modern browsers use CSP instead
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Docs pages load Swagger UI assets from CDN — relax CSP for those paths only
    if request.url.path in ("/docs", "/redoc", "/openapi.json"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "img-src 'self' data: fastapi.tiangolo.com;"
        )
    else:
        response.headers["Content-Security-Policy"] = "default-src 'none'"  # API returns JSON only
    if settings.HTTPS_ONLY:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ── Routers ────────────────────────────────────────────────────────────────────
API_PREFIX = "/api/v1"
app.include_router(repositories.router, prefix=API_PREFIX)
app.include_router(findings.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(remediation.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(webhooks.router, prefix=API_PREFIX)
app.include_router(audit.router, prefix=API_PREFIX)
app.include_router(compliance.router, prefix=API_PREFIX)
app.include_router(jira.router, prefix=API_PREFIX)
app.include_router(sbom.router, prefix=API_PREFIX)
app.include_router(schedules.router, prefix=API_PREFIX)
app.include_router(sla_policies.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(regression_alerts.router, prefix=API_PREFIX)
app.include_router(api_keys.router, prefix=API_PREFIX)


@app.get("/health", tags=["system"])
async def health():
    return {"status": "ok", "service": "nyx"}


@app.get("/ready", tags=["system"])
async def ready():
    """Readiness check — verifies database connectivity."""
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not ready"})
