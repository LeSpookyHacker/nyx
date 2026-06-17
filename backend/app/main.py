"""
Nyx — Security Findings Dashboard
FastAPI application entry point.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.security import require_api_key  # noqa: E402
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.core.limiter import limiter
from app.core.security import require_api_key, warn_insecure_config
from app.database import init_db
from app.routers import (
    audit, api_keys, compliance, dashboard, findings, jira, remediation,
    repositories, reports, saved_filters, sbom, scans, schedules, sla_policies,
    webhooks, regression_alerts,
)
from app.routers import velocity, ai_costs  # new analytics routers
# Ensure new models are registered with SQLAlchemy metadata
from app.models import repo_risk_history, scan_schedule, sla_policy, suppression_pattern  # noqa: F401
from app.models.api_key import ApiKey  # noqa: F401 — register api_keys table
from app.models.auth_lockout import AuthLockout  # noqa: F401
from app.models.custom_compliance import CustomFramework, CustomControl  # noqa: F401
from app.models.risk_acceptance import RiskAcceptance  # noqa: F401

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("nyx")

# ── Background loop intervals (seconds) ─────────────────────────────────────
STARTUP_DELAY_SECONDS = 15
DAILY_INTERVAL_SECONDS = 86_400       # 24 hours
WEEKLY_INTERVAL_SECONDS = 86_400 * 7  # 7 days
HOURLY_INTERVAL_SECONDS = 3_600       # 1 hour
SCAN_CHECK_INTERVAL_SECONDS = 300     # 5 minutes
API_KEY_STARTUP_DELAY_SECONDS = 60    # brief startup delay for key expiry loop
SESSION_COOKIE_MAX_AGE = 86_400 * 7   # 7 days

# AI remediation cap — max requests per actor per 24-hour window
REMEDIATION_DAILY_LIMIT = 50

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

    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            async with AsyncSessionLocal() as db:
                repos_result = await db.execute(select(Repository))
                repos = repos_result.scalars().all()
                today = date.today()

                # Single GROUP BY query instead of N+1 per-repo counts
                count_result = await db.execute(
                    select(
                        FindingModel.repository_id,
                        func.count(),
                    )
                    .group_by(FindingModel.repository_id)
                )
                finding_counts = {row[0]: row[1] for row in count_result}

                for repo in repos:
                    total = finding_counts.get(repo.id, 0)
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
        await asyncio.sleep(DAILY_INTERVAL_SECONDS)


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
        await asyncio.sleep(HOURLY_INTERVAL_SECONDS)
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
                        t = asyncio.create_task(notify_sla_breach(
                            finding.id, finding.title, finding.severity, repo_name, days_overdue
                        ))
                        t.add_done_callback(lambda f: f.exception() if not f.cancelled() and f.exception() else None)

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
                            except Exception as jira_exc:
                                logger.warning("SLA JIRA escalation failed for finding %s: %s", finding.id, jira_exc)

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
        await asyncio.sleep(SCAN_CHECK_INTERVAL_SECONDS)
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
                        t = asyncio.create_task(process_scan_results(scan.id, {}))
                        t.add_done_callback(lambda f: f.exception() if not f.cancelled() and f.exception() else None)

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
        await asyncio.sleep(HOURLY_INTERVAL_SECONDS)
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

    await asyncio.sleep(API_KEY_STARTUP_DELAY_SECONDS)
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
        await asyncio.sleep(DAILY_INTERVAL_SECONDS)


async def _pinned_action_refresh_loop() -> None:
    """
    Weekly: check GitHub for newer releases of pinned GitHub Actions used in the
    generated nyx-scan.yml. When a newer version is found, update the in-memory
    pins and re-push the workflow to all active repos so they stay current without
    any manual intervention.
    """
    from app.services.github_service import refresh_pinned_actions, push_workflow_to_all_repos

    # Run once shortly after startup to catch any pins that went stale while Nyx was offline
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            updated = await refresh_pinned_actions()
            if updated:
                logger.info(
                    "Pinned action refresh: %d action(s) updated (%s) — pushing workflow to all repos",
                    len(updated), ", ".join(updated),
                )
                async with AsyncSessionLocal() as db:
                    count = await push_workflow_to_all_repos(db)
                logger.info("Pinned action refresh: updated workflow in %d repo(s)", count)
            else:
                logger.debug("Pinned action refresh: all pins are current")
        except Exception:
            logger.exception("Error in pinned action refresh loop")
        await asyncio.sleep(WEEKLY_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🌑 Nyx starting up...")

    # Surface security misconfigurations at startup
    warn_insecure_config()

    # Hard-fail when SQLite is used in production — it has no access controls or encryption (M14)
    if settings.ENVIRONMENT == "production" and "sqlite" in settings.DATABASE_URL.lower():
        raise RuntimeError(
            "[SECURITY] DATABASE_URL is SQLite in production. SQLite has no access controls, "
            "no encryption at rest, and is not suitable for multi-user production deployments. "
            "Set DATABASE_URL to a PostgreSQL connection string."
        )

    await init_db()
    await _seed_api_key_from_env()

    # Hydrate brute-force lockout state from DB so container restarts don't reset it
    from app.core.security import hydrate_lockout_from_db
    await hydrate_lockout_from_db()

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

    # Pinned action refresh — weekly check for newer releases; re-pushes workflow to all repos
    tasks.append(asyncio.create_task(_pinned_action_refresh_loop()))

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
    # Fast-path: reject by Content-Length header when present
    # (Content-Length can be spoofed or omitted with chunked encoding — see streaming check below)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body too large (max 50 MB)"})
        except ValueError:
            pass  # malformed Content-Length — fall through to streaming check

    # SEC-105: wrap the ASGI receive callable to enforce the limit on actual bytes received,
    # defeating chunked-encoding and spoofed Content-Length bypass vectors.
    received: list[int] = [0]
    original_receive = request._receive

    async def limited_receive() -> dict:
        msg = await original_receive()
        if msg.get("type") == "http.request":
            received[0] += len(msg.get("body", b""))
            if received[0] > _MAX_BODY_BYTES:
                # Truncate body so the route handler gets an empty payload
                # (body too large — we return 413 after call_next)
                return {"type": "http.request", "body": b"", "more_body": False}
        return msg

    request._receive = limited_receive
    response = await call_next(request)

    if received[0] > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large (max 50 MB)"})
    return response


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
app.include_router(saved_filters.router, prefix=API_PREFIX)
app.include_router(velocity.router, prefix=API_PREFIX)
app.include_router(ai_costs.router, prefix=API_PREFIX)


@app.post("/auth/session", tags=["auth"])
async def create_session(request: Request, response: Response):
    """
    Exchange an API key for an HTTP-only session cookie.

    The cookie is a random opaque token (not the API key itself) — the server-side
    mapping lives in the `user_sessions` table keyed by SHA-256 hash of the token.
    Revoking a session means deleting the row; the stolen cookie is worthless.
    """
    try:
        body = await request.json()
    except Exception:
        from fastapi import HTTPException as _HTTPEx
        raise _HTTPEx(status_code=400, detail="JSON body with 'api_key' field required")

    api_key = (body.get("api_key") or "").strip()
    if not api_key:
        from fastapi import HTTPException as _HTTPEx
        raise _HTTPEx(status_code=400, detail="api_key is required")

    from app.core.security import (
        _compute_key_hashes,
        _clear_auth_failure,
        _record_auth_failure,
        _hash_session_id,
        SCOPE_ADMIN,
    )
    from sqlalchemy import select as _sa_select
    from app.database import AsyncSessionLocal as _ASL
    from app.models.api_key import ApiKey as _ApiKey
    from app.models.user_session import UserSession as _UserSession
    from datetime import datetime, timedelta, timezone
    import secrets as _secrets

    ip = request.client.host if request.client else "unknown"
    identity = "bootstrap"
    scopes = SCOPE_ADMIN
    api_key_id: str | None = None
    key_valid = False

    try:
        key_hashes = _compute_key_hashes(api_key)
        async with _ASL() as db:
            result = await db.execute(
                _sa_select(_ApiKey).where(
                    _ApiKey.key_hash.in_(key_hashes),
                    _ApiKey.is_active.is_(True),
                )
            )
            record = result.scalar_one_or_none()
            if record:
                now = datetime.now(timezone.utc)
                if not (record.expires_at and record.expires_at < now):
                    record.last_used_at = now
                    await db.commit()
                    key_valid = True
                    identity = record.name
                    scopes = record.scopes or SCOPE_ADMIN
                    api_key_id = record.id
    except Exception as db_exc:
        logger.debug("Session DB key lookup failed, falling back to env var: %s", db_exc)

    if not key_valid and settings.NYX_API_KEY:
        key_valid = _secrets.compare_digest(api_key, settings.NYX_API_KEY)

    if not key_valid:
        _record_auth_failure(ip)
        from fastapi import HTTPException as _HTTPEx
        raise _HTTPEx(status_code=401, detail="Invalid API key")

    _clear_auth_failure(ip)

    # Mint an opaque session token and persist the hash
    session_token = _secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    try:
        async with _ASL() as db:
            db.add(_UserSession(
                session_id_hash=_hash_session_id(session_token),
                identity=identity,
                scopes=scopes,
                api_key_id=api_key_id,
                expires_at=now + timedelta(seconds=SESSION_COOKIE_MAX_AGE),
                last_used_at=now,
            ))
            await db.commit()
    except Exception:
        logger.exception("Failed to persist session row")
        from fastapi import HTTPException as _HTTPEx
        raise _HTTPEx(status_code=500, detail="Could not create session")

    response.set_cookie(
        key="nyx_session",
        value=session_token,
        httponly=True,
        samesite="strict",
        secure=settings.HTTPS_ONLY,
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
    )
    return {"status": "ok", "identity": identity, "scopes": scopes}


@app.post("/auth/logout", tags=["auth"])
async def logout(request: Request, response: Response):
    """Delete the session row and clear the cookie."""
    cookie_token = request.cookies.get("nyx_session")
    if cookie_token:
        try:
            from sqlalchemy import delete as _sa_delete
            from app.database import AsyncSessionLocal as _ASL
            from app.models.user_session import UserSession as _UserSession
            from app.core.security import _hash_session_id
            async with _ASL() as db:
                await db.execute(
                    _sa_delete(_UserSession).where(
                        _UserSession.session_id_hash == _hash_session_id(cookie_token)
                    )
                )
                await db.commit()
        except Exception:
            logger.exception("Session delete failed")
    response.delete_cookie(key="nyx_session", path="/", samesite="strict")
    return {"status": "ok"}


@app.get("/auth/whoami", tags=["auth"])
async def whoami(request: Request, _key: str = Depends(require_api_key)):
    """Return the authenticated identity and scopes — used by the frontend ProtectedRoute."""
    scopes = getattr(request.state, "key_scopes", "")
    return {"identity": _key, "scopes": scopes}


@app.get("/health", tags=["system"])
async def health():
    # Minimal response — do not expose service name or version (L5)
    return {"status": "ok"}


@app.get("/health/integrations", tags=["system"])
async def integration_health(_key: str = Depends(require_api_key)):
    """
    Probe each configured integration and report its connectivity status.
    Requires a valid API key — this endpoint reveals integration configuration.

    Returns per-integration status: 'ok' | 'error' | 'not_configured'
    """
    from app.core.security import require_api_key as _req  # already imported above
    results: dict[str, dict] = {}

    # ── Database ──────────────────────────────────────────────────────────────
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        results["database"] = {"status": "ok"}
    except Exception as e:
        results["database"] = {"status": "error", "detail": str(e)[:100]}

    # ── Anthropic / Claude ────────────────────────────────────────────────────
    if not settings.ANTHROPIC_API_KEY:
        results["anthropic"] = {"status": "not_configured"}
    else:
        try:
            import anthropic as _ant
            import httpx
            client = _ant.AsyncAnthropic(
                api_key=settings.ANTHROPIC_API_KEY,
                timeout=httpx.Timeout(10.0),
            )
            # Use the models list endpoint as a lightweight probe
            await client.models.list()
            results["anthropic"] = {"status": "ok", "model": settings.ANTHROPIC_MODEL}
        except Exception as e:
            results["anthropic"] = {"status": "error", "detail": str(e)[:100]}

    # ── GitHub ────────────────────────────────────────────────────────────────
    if not settings.GITHUB_TOKEN:
        results["github"] = {"status": "not_configured"}
    else:
        try:
            from github import Github as _GH
            g = _GH(settings.GITHUB_TOKEN)
            user = g.get_user()
            _ = user.login  # force the API call
            results["github"] = {"status": "ok", "authenticated_as": user.login}
        except Exception as e:
            results["github"] = {"status": "error", "detail": str(e)[:100]}

    # ── JIRA ──────────────────────────────────────────────────────────────────
    if not settings.JIRA_URL or not settings.JIRA_API_TOKEN:
        results["jira"] = {"status": "not_configured" if not settings.JIRA_MOCK_MODE else "mock"}
    else:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=8.0) as hx:
                resp = await hx.get(
                    f"{settings.JIRA_URL.rstrip('/')}/rest/api/3/myself",
                    auth=(settings.JIRA_USER_EMAIL, settings.JIRA_API_TOKEN),
                )
                resp.raise_for_status()
                data = resp.json()
                results["jira"] = {"status": "ok", "authenticated_as": data.get("displayName", "")}
        except Exception as e:
            results["jira"] = {"status": "error", "detail": str(e)[:100]}

    # ── Slack / Notification webhook ─────────────────────────────────────────
    if not settings.NOTIFICATION_WEBHOOK_URL:
        results["notifications"] = {"status": "not_configured"}
    else:
        results["notifications"] = {"status": "ok", "type": "webhook"}

    overall = "ok" if all(v["status"] in ("ok", "not_configured", "mock") for v in results.values()) else "degraded"
    return {"overall": overall, "integrations": results}




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
