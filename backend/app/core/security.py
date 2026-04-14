"""
Security utilities: API key authentication, scope enforcement,
webhook HMAC verification, and scan submission integrity.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("nyx.security")

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Valid scope values
SCOPE_SCANNER = "scanner"
SCOPE_READONLY = "readonly"
SCOPE_ANALYST = "analyst"
SCOPE_ADMIN = "admin"

_ALL_SCOPES = {SCOPE_SCANNER, SCOPE_READONLY, SCOPE_ANALYST, SCOPE_ADMIN}

_LOCKOUT_THRESHOLD = 20      # lock after this many failures
_LOCKOUT_WINDOW_S = 600      # within this rolling window (seconds)
_LOCKOUT_DURATION_S = 900    # lock out for this long (seconds)

# ── Trusted proxy CIDR cache ──────────────────────────────────────────────────
# Parsed once from settings at module load.  An empty list means no proxy is
# trusted, so X-Forwarded-For is *never* believed (safest default).
_TRUSTED_PROXY_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

def _build_trusted_proxy_nets() -> None:
    """Parse TRUSTED_PROXY_CIDRS from settings into network objects."""
    global _TRUSTED_PROXY_NETS
    nets = []
    for cidr in settings.TRUSTED_PROXY_CIDRS.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("TRUSTED_PROXY_CIDRS: invalid CIDR %r — ignored", cidr)
    _TRUSTED_PROXY_NETS = nets


_build_trusted_proxy_nets()


def _is_trusted_proxy(ip: str) -> bool:
    """Return True if the TCP peer IP is within a configured trusted proxy range."""
    if not _TRUSTED_PROXY_NETS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TRUSTED_PROXY_NETS)
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address.

    X-Forwarded-For is ONLY trusted when the direct TCP peer is in TRUSTED_PROXY_CIDRS.
    Without that configuration, the raw TCP peer address is returned — preventing any
    client from spoofing their IP to bypass per-IP brute-force lockouts.
    """
    peer_ip = request.client.host if request.client else "unknown"
    if _is_trusted_proxy(peer_ip):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            # Take the leftmost (client-supplied) entry — the proxy appends its own IP last
            return forwarded_for.split(",")[0].strip()
    return peer_ip


# ── Persistent brute-force lockout ─────────────────────────────────────────────
# The in-memory dict is the fast path; the DB is the source of truth that survives
# container restarts.  We hydrate memory from DB at startup (see hydrate_lockout_from_db).

_FAILED_AUTH: dict[str, tuple[int, datetime]] = {}  # ip -> (failure_count, first_failure_at_utc)
_LOCKOUT_UNTIL: dict[str, datetime] = {}            # ip -> locked_until_utc


def _is_locked_out(ip: str) -> bool:
    """Return True if the IP is currently locked out (memory fast-path)."""
    now = datetime.now(timezone.utc)

    # Active lockout
    locked_until = _LOCKOUT_UNTIL.get(ip)
    if locked_until and now < locked_until:
        return True
    if locked_until:
        _LOCKOUT_UNTIL.pop(ip, None)

    # Failure window check
    entry = _FAILED_AUTH.get(ip)
    if not entry:
        return False
    count, first_ts = entry
    if (now - first_ts).total_seconds() > _LOCKOUT_WINDOW_S:
        _FAILED_AUTH.pop(ip, None)
        return False
    return count >= _LOCKOUT_THRESHOLD


def _record_auth_failure(ip: str) -> None:
    """Increment failure counter for an IP and set lockout if threshold exceeded."""
    now = datetime.now(timezone.utc)
    entry = _FAILED_AUTH.get(ip)
    if entry:
        count, first_ts = entry
        if (now - first_ts).total_seconds() > _LOCKOUT_WINDOW_S:
            _FAILED_AUTH[ip] = (1, now)
            count = 1
        else:
            count += 1
            _FAILED_AUTH[ip] = (count, first_ts)
    else:
        count = 1
        _FAILED_AUTH[ip] = (count, now)
        first_ts = now

    if count >= _LOCKOUT_THRESHOLD:
        locked_until = now + timedelta(seconds=_LOCKOUT_DURATION_S)
        _LOCKOUT_UNTIL[ip] = locked_until
        # Persist asynchronously — fire-and-forget
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_persist_lockout(ip, count, _FAILED_AUTH[ip][1], locked_until))
        except RuntimeError:
            pass  # No running event loop (unit tests etc.)


def _clear_auth_failure(ip: str) -> None:
    """Clear failure state for an IP on successful authentication."""
    _FAILED_AUTH.pop(ip, None)
    _LOCKOUT_UNTIL.pop(ip, None)
    # Persist the clearance asynchronously
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_clear_lockout_db(ip))
    except RuntimeError:
        pass


async def _persist_lockout(ip: str, count: int, first_failure_at: datetime, locked_until: datetime) -> None:
    """Write lockout state to DB (called as a background task)."""
    try:
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        from app.database import AsyncSessionLocal
        from app.models.auth_lockout import AuthLockout
        async with AsyncSessionLocal() as db:
            now = datetime.now(timezone.utc)
            existing = await db.get(AuthLockout, ip)
            if existing:
                existing.failure_count = count
                existing.first_failure_at = first_failure_at
                existing.locked_until = locked_until
                existing.updated_at = now
            else:
                db.add(AuthLockout(
                    ip=ip,
                    failure_count=count,
                    first_failure_at=first_failure_at,
                    locked_until=locked_until,
                    updated_at=now,
                ))
            await db.commit()
    except (OSError, RuntimeError) as exc:
        # Lockout persistence is best-effort — never fail the auth path
        logger.debug("Lockout persistence failed: %s", exc)


async def _clear_lockout_db(ip: str) -> None:
    """Remove lockout record from DB (called as a background task)."""
    try:
        from app.database import AsyncSessionLocal
        from app.models.auth_lockout import AuthLockout
        async with AsyncSessionLocal() as db:
            record = await db.get(AuthLockout, ip)
            if record:
                await db.delete(record)
                await db.commit()
    except (OSError, RuntimeError) as exc:
        logger.debug("Lockout clearance failed: %s", exc)


async def hydrate_lockout_from_db() -> None:
    """
    Called at startup: load active lockout records from DB into the in-memory dicts.
    This ensures brute-force lockout state survives container restarts.
    """
    try:
        from sqlalchemy import select
        from app.database import AsyncSessionLocal
        from app.models.auth_lockout import AuthLockout
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AuthLockout))
            for record in result.scalars().all():
                first_ts = record.first_failure_at
                # If the failure window has elapsed, skip (no need to load stale records)
                if first_ts.tzinfo is None:
                    first_ts = first_ts.replace(tzinfo=timezone.utc)
                age = (now - first_ts).total_seconds()
                if age > _LOCKOUT_WINDOW_S + _LOCKOUT_DURATION_S:
                    # Stale record — clean up
                    await db.delete(record)
                    continue
                _FAILED_AUTH[record.ip] = (record.failure_count, first_ts)
                if record.locked_until:
                    lu = record.locked_until
                    if lu.tzinfo is None:
                        lu = lu.replace(tzinfo=timezone.utc)
                    if lu > now:
                        _LOCKOUT_UNTIL[record.ip] = lu
            await db.commit()
        logger.info("AUTH_LOCKOUT hydrated %d records from DB", len(_FAILED_AUTH))
    except Exception:
        logger.warning("AUTH_LOCKOUT hydration from DB failed — lockout state starts fresh", exc_info=True)


def _key_identity(api_key: str) -> str:
    """Return a short, non-reversible identifier for an API key for audit logs."""
    return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:12]


def _compute_key_hashes(api_key: str) -> list[str]:
    """
    Return the list of hashes to try when looking up an API key in the DB.
    Prefers HMAC-SHA256 (keyed with NYX_SECRET_KEY) over plain SHA-256 (H6).
    Both are returned so old keys stored as SHA-256 still work after migration.
    """
    hashes = []
    if settings.NYX_SECRET_KEY:
        hashes.append(
            hmac.new(settings.NYX_SECRET_KEY.encode(), api_key.encode(), hashlib.sha256).hexdigest()
        )
    # Always include plain SHA-256 for backward compat with pre-NYX_SECRET_KEY keys
    hashes.append(hashlib.sha256(api_key.encode()).hexdigest())
    return hashes


def _is_unsafe_dev_fallback() -> bool:
    """
    Refuse the silent-admin dev fallback when the instance looks production-ish.

    The fallback is only safe when Nyx is running on a developer workstation with
    no NYX_API_KEY configured. If GITHUB_WEBHOOK_ENDPOINT is set, the instance is
    reachable from GitHub, which means granting unauthenticated admin to anyone
    who finds the URL — never acceptable. Same for HTTPS_ONLY (implies real TLS).
    """
    if settings.GITHUB_WEBHOOK_ENDPOINT:
        return True
    if settings.HTTPS_ONLY:
        return True
    return False


def _hash_session_id(session_id: str) -> str:
    """SHA-256 of the random session token — only the hash lives in the DB."""
    return hashlib.sha256(session_id.encode()).hexdigest()


async def require_api_key(
    request: Request,
    api_key: str | None = Security(_api_key_header),
) -> str:
    """
    Dependency that enforces API key authentication.
    Sets request.state.key_scopes on success (used by require_scope).

    Auth order:
      1. Read key from X-API-Key header OR nyx_session HTTP-only cookie.
         - Header path: look up in api_keys table, fall back to NYX_API_KEY env var.
         - Cookie path: resolve the hashed session_id in user_sessions and use the
           scopes stored there. The cookie is NOT an API key — it's an opaque token.
      2. Check per-IP brute-force lockout — memory-fast-path, DB-persistent.

    If NYX_API_KEY is not configured, no DB key matches, and the instance is not
    production-ish, allow with a 'dev' identity and log a warning. Production or
    production-ish deployments refuse the request.
    """
    cookie_token = request.cookies.get("nyx_session")
    from_cookie = api_key is None and cookie_token is not None

    ip = get_client_ip(request)

    # Brute-force lockout check (M8) — persisted across restarts
    if _is_locked_out(ip):
        logger.warning("AUTH_LOCKOUT ip=%s endpoint=%s", ip, request.url.path)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication failures. Try again later.",
        )

    # ── Cookie path: resolve session_id → user_sessions row ──────────────────
    if from_cookie:
        try:
            from sqlalchemy import select as sa_select
            from app.database import AsyncSessionLocal
            from app.models.user_session import UserSession

            token_hash = _hash_session_id(cookie_token)
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    sa_select(UserSession).where(UserSession.session_id_hash == token_hash)
                )
                session_row = result.scalar_one_or_none()
                if session_row is not None:
                    now = datetime.now(timezone.utc)
                    # SQLite loses tz info; assume stored values are UTC.
                    session_exp = session_row.expires_at
                    if session_exp is not None and session_exp.tzinfo is None:
                        session_exp = session_exp.replace(tzinfo=timezone.utc)
                    if session_exp and session_exp < now:
                        await db.delete(session_row)
                        await db.commit()
                        _record_auth_failure(ip)
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session expired",
                            headers={"WWW-Authenticate": "ApiKey"},
                        )
                    session_row.last_used_at = now
                    await db.commit()
                    _clear_auth_failure(ip)
                    request.state.key_scopes = session_row.scopes or SCOPE_ADMIN
                    return f"session:{session_row.identity}"
        except HTTPException:
            raise
        except Exception:
            logger.exception("Session cookie lookup failed")
        # Unknown session id — reject. Do NOT fall back to treating the cookie as
        # an API key: that path is what C1 was trying to close in the first place.
        _record_auth_failure(ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not api_key:
        if not settings.NYX_API_KEY:
            if settings.ENVIRONMENT == "production" or _is_unsafe_dev_fallback():
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Server misconfiguration: authentication is not configured.",
                )
            logger.warning(
                "NYX_API_KEY is not set — request allowed in development mode. "
                "Set NYX_API_KEY to enable authentication."
            )
            request.state.key_scopes = SCOPE_ADMIN
            return "dev"
        logger.warning("AUTH_FAILURE ip=%s endpoint=%s reason=missing", ip, request.url.path)
        _record_auth_failure(ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # ── 1. DB-backed key lookup (HMAC-SHA256 preferred, SHA-256 fallback) (H6) ─
    try:
        from sqlalchemy import select as sa_select
        from app.database import AsyncSessionLocal
        from app.models.api_key import ApiKey

        key_hashes = _compute_key_hashes(api_key)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                sa_select(ApiKey).where(
                    ApiKey.key_hash.in_(key_hashes),
                    ApiKey.is_active.is_(True),
                )
            )
            record = result.scalar_one_or_none()
            if record is not None:
                now = datetime.now(timezone.utc)
                if record.expires_at and record.expires_at < now:
                    logger.warning(
                        "AUTH_FAILURE ip=%s endpoint=%s reason=expired key_id=%s",
                        ip, request.url.path, record.id,
                    )
                    _record_auth_failure(ip)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API key has expired",
                        headers={"WWW-Authenticate": "ApiKey"},
                    )
                record.last_used_at = now
                await db.commit()
                _clear_auth_failure(ip)
                request.state.key_scopes = record.scopes or SCOPE_ADMIN
                return f"apikey:{record.name}"
    except HTTPException:
        raise
    except Exception:
        logger.exception("DB API key lookup failed; falling back to env var auth")

    # ── 2. Env-var fallback (backward compat / bootstrap) ─────────────────────
    if not settings.NYX_API_KEY:
        if settings.ENVIRONMENT == "production" or _is_unsafe_dev_fallback():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Server misconfiguration: authentication is not configured.",
            )
        logger.warning(
            "NYX_API_KEY is not set — request allowed in development mode. "
            "Set NYX_API_KEY to enable authentication."
        )
        request.state.key_scopes = SCOPE_ADMIN
        return "dev"

    if not secrets.compare_digest(api_key, settings.NYX_API_KEY):
        logger.warning(
            "AUTH_FAILURE ip=%s endpoint=%s reason=invalid",
            ip,
            request.url.path,
        )
        _record_auth_failure(ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    _clear_auth_failure(ip)
    request.state.key_scopes = SCOPE_ADMIN
    return _key_identity(api_key)


def require_scope(*required_scopes: str):
    """
    Dependency factory: at least one of the listed scopes must be present,
    OR the key must have 'admin' scope (which supersedes all).

    Usage:
        _key: str = Depends(require_scope("analyst", "admin"))
    """
    async def _check_scope(
        request: Request,
        actor: str = Depends(require_api_key),
    ) -> str:
        key_scopes = set(getattr(request.state, "key_scopes", SCOPE_ADMIN).split(","))
        if SCOPE_ADMIN in key_scopes or any(s in key_scopes for s in required_scopes):
            return actor
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This operation requires one of these scopes: {', '.join(required_scopes)}",
        )
    return _check_scope


def warn_insecure_config() -> None:
    """
    Called at startup to surface security misconfigurations loudly.
    Raises RuntimeError in production for hard failures.
    """
    issues = []

    if not settings.NYX_API_KEY:
        msg = "NYX_API_KEY is not set — the API is open to unauthenticated access"
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(f"[SECURITY] {msg}. Cannot start in production mode without authentication.")
        issues.append(msg)

    if not settings.NYX_SECRET_KEY:
        msg = (
            "NYX_SECRET_KEY is not set — webhook secrets are stored plaintext and "
            "audit HMAC chain uses a weak default key"
        )
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                f"[SECURITY] {msg}. Cannot start in production mode without NYX_SECRET_KEY. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        issues.append(msg)

    if not settings.SNYK_WEBHOOK_SECRET:
        issues.append("SNYK_WEBHOOK_SECRET is not set — Snyk webhooks are accepted without signature verification")

    if not settings.NYX_WEBHOOK_SECRET:
        msg = "NYX_WEBHOOK_SECRET is not set — GitHub webhook repo enumeration is possible before HMAC check"
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                f"[SECURITY] {msg}. Cannot start in production mode without NYX_WEBHOOK_SECRET. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        issues.append(msg)

    if settings.JIRA_MOCK_MODE and settings.ENVIRONMENT == "production":
        issues.append("JIRA_MOCK_MODE=true in production — JIRA tickets will not be created")

    if settings.DEBUG and settings.ENVIRONMENT == "production":
        raise RuntimeError(
            "[SECURITY] DEBUG=true in production — SQL queries and tracebacks may be exposed. "
            "Set DEBUG=false before running in production."
        )

    if not settings.HTTPS_ONLY and settings.ENVIRONMENT == "production":
        issues.append("HTTPS_ONLY=false in production — API traffic is not enforced over HTTPS")

    if settings.API_KEY_MAX_LIFETIME_DAYS == 0 and settings.ENVIRONMENT == "production":
        issues.append(
            "API_KEY_MAX_LIFETIME_DAYS=0 in production — API keys never expire. "
            "Set a maximum lifetime (e.g., API_KEY_MAX_LIFETIME_DAYS=90) to limit credential exposure."
        )

    if not settings.TRUSTED_PROXY_CIDRS and settings.ENVIRONMENT == "production":
        issues.append(
            "TRUSTED_PROXY_CIDRS is not set — X-Forwarded-For is ignored for IP extraction. "
            "If Nyx runs behind a reverse proxy, set TRUSTED_PROXY_CIDRS to the proxy's IP range "
            "so per-IP brute-force lockouts use the real client IP."
        )

    for issue in issues:
        logger.warning("[SECURITY CONFIG] %s", issue)


async def verify_github_signature(request: Request, secret: str) -> bytes:
    """
    Verify the X-Hub-Signature-256 header against the request body
    using the per-repository webhook secret.
    """
    signature_header = request.headers.get("X-Hub-Signature-256", "")
    if not signature_header.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing or malformed X-Hub-Signature-256 header",
        )

    body = await request.body()
    expected_sig = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature_header, expected_sig):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook signature",
        )
    return body


def verify_snyk_signature(body: bytes, secret: str, signature_header: str) -> None:
    """
    Verify the x-hub-signature header from a Snyk webhook.

    Snyk uses HMAC-SHA256 with header format: sha256=<hexdigest>

    If no secret is configured, the request is rejected in production
    and allowed-with-warning in development.
    """
    if not secret:
        if settings.ENVIRONMENT == "production":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Snyk webhook secret not configured — rejecting unverifiable request",
            )
        logger.warning(
            "SNYK_WEBHOOK_SECRET not configured — accepting Snyk webhook without signature verification. "
            "This is insecure. Set SNYK_WEBHOOK_SECRET in production."
        )
        return

    if not signature_header.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing or malformed x-hub-signature header",
        )
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature_header, expected):
        logger.warning("Rejected Snyk webhook: invalid signature")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Snyk webhook signature",
        )


def verify_global_webhook_hmac(body: bytes, signature_header: str) -> None:
    """
    Optional pre-check using NYX_WEBHOOK_SECRET before per-repo DB lookup.
    If NYX_WEBHOOK_SECRET is not set, this is a no-op (backwards compatible).
    """
    if not settings.NYX_WEBHOOK_SECRET:
        return
    if not signature_header.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-Hub-Signature-256 header",
        )
    expected = "sha256=" + hmac.new(
        settings.NYX_WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature_header, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook signature",
        )


def verify_webhook_timestamp(payload: dict, event_type: str, max_age_seconds: int = 600) -> None:
    """
    Validate that a GitHub push webhook payload is recent (within max_age_seconds).
    Only applied to push events — PR and check_run events are not time-constrained.
    Logs a warning and rejects if the push timestamp is too old.
    """
    if event_type != "push":
        return

    # GitHub push payloads include repository.pushed_at (Unix timestamp)
    pushed_at_raw = payload.get("repository", {}).get("pushed_at")
    if not pushed_at_raw:
        # No timestamp available — allow (conservative)
        return

    try:
        pushed_at = datetime.fromtimestamp(int(pushed_at_raw), tz=timezone.utc)
        age = (datetime.now(timezone.utc) - pushed_at).total_seconds()
        if age > max_age_seconds:
            logger.warning(
                "WEBHOOK_REPLAY_SUSPECTED pushed_at=%s age_seconds=%d max=%d",
                pushed_at.isoformat(), int(age), max_age_seconds,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Webhook payload is too old ({int(age)}s). Max allowed: {max_age_seconds}s.",
            )
    except HTTPException:
        raise
    except Exception:
        # If we can't parse the timestamp, allow the request
        logger.debug("Could not parse pushed_at from webhook payload — skipping timestamp check")


def verify_submission_hmac(
    body_bytes: bytes,
    submission_hmac_header: Optional[str],
    repo_webhook_secret: str,
) -> bool:
    """
    Verify the optional X-Nyx-Submission-HMAC header on scan imports.

    The CI workflow computes:
        HMAC-SHA256(key=repo_webhook_secret, msg=SHA256(payload_bytes))
    and sends it as: sha256=<hexdigest>

    Returns True if verified.
    Returns False if header is absent AND REQUIRE_SUBMISSION_HMAC is False.
    Raises 403 if the header is present but invalid, OR if absent and
    REQUIRE_SUBMISSION_HMAC=True.
    """
    if not submission_hmac_header:
        if settings.REQUIRE_SUBMISSION_HMAC:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="X-Nyx-Submission-HMAC header is required (REQUIRE_SUBMISSION_HMAC=true)",
            )
        return False  # Absent and not required — unverified but accepted

    if not submission_hmac_header.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Malformed X-Nyx-Submission-HMAC header (expected sha256=<hex>)",
        )

    payload_hash = hashlib.sha256(body_bytes).digest()
    expected = "sha256=" + hmac.new(
        repo_webhook_secret.encode(), payload_hash, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(submission_hmac_header, expected):
        logger.warning("SCAN_SUBMISSION_HMAC_INVALID: forged or tampered scan payload rejected")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid X-Nyx-Submission-HMAC — scan payload integrity check failed",
        )
    return True


# ── GitHub IP allowlist ────────────────────────────────────────────────────────
# GitHub publishes its webhook source IP ranges at https://api.github.com/meta
# Cache the parsed ranges in memory; refresh lazily on first use.
_GITHUB_WEBHOOK_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None
_GITHUB_NETS_FALLBACK = [
    # Fallback hardcoded ranges if the meta API is unreachable
    # Updated as of 2025-Q1 — should be refreshed periodically
    ipaddress.ip_network("192.30.252.0/22"),
    ipaddress.ip_network("185.199.108.0/22"),
    ipaddress.ip_network("140.82.112.0/20"),
    ipaddress.ip_network("143.55.64.0/20"),
]


async def _load_github_webhook_ips() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Fetch GitHub's current webhook source IP ranges from their meta API."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("https://api.github.com/meta")
            data = resp.json()
            nets = []
            for cidr in data.get("hooks", []):
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
            return nets if nets else _GITHUB_NETS_FALLBACK
    except Exception:
        return _GITHUB_NETS_FALLBACK


async def verify_github_source_ip(request: Request) -> None:
    """
    When GITHUB_WEBHOOK_IP_ALLOWLIST_ENABLED=true, verify the request originates
    from a known GitHub IP range.  Uses TRUSTED_PROXY_CIDRS-aware IP extraction
    so this works correctly behind a reverse proxy.
    """
    if not settings.GITHUB_WEBHOOK_IP_ALLOWLIST_ENABLED:
        return

    global _GITHUB_WEBHOOK_NETS
    if _GITHUB_WEBHOOK_NETS is None:
        _GITHUB_WEBHOOK_NETS = await _load_github_webhook_ips()

    ip_str = get_client_ip(request)
    try:
        addr = ipaddress.ip_address(ip_str)
        if any(addr in net for net in _GITHUB_WEBHOOK_NETS):
            return
    except ValueError:
        pass

    logger.warning("WEBHOOK_IP_BLOCKED ip=%s — not in GitHub IP allowlist", ip_str)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Request does not originate from a known GitHub IP range",
    )


def generate_webhook_secret() -> str:
    """Generate a cryptographically random 32-byte hex webhook secret."""
    return secrets.token_hex(32)


async def rotate_secret_key(new_secret_key: str) -> dict:
    """
    Re-encrypt all Fernet-encrypted database fields with a new NYX_SECRET_KEY.

    This is necessary when rotating the master secret — without this, all
    existing encrypted values (webhook secrets) become unreadable.

    Returns a dict with counts of rotated and failed records.
    """
    from app.database import AsyncSessionLocal
    from app.models.repository import Repository
    from app.core.crypto import EncryptedString
    from sqlalchemy import select

    if not new_secret_key:
        raise ValueError("new_secret_key must not be empty")

    rotated = 0
    failed = 0

    async with AsyncSessionLocal() as db:
        repos_result = await db.execute(select(Repository))
        repos = repos_result.scalars().all()

        for repo in repos:
            try:
                # Read the current plaintext value (decrypted with old key from settings)
                current_secret = repo.webhook_secret
                if not current_secret:
                    continue

                # Re-encrypt with the new key by temporarily using the new key
                from cryptography.fernet import Fernet
                import base64
                import hashlib as _hashlib

                # Derive new Fernet key from new_secret_key
                new_key_bytes = _hashlib.pbkdf2_hmac(
                    "sha256",
                    new_secret_key.encode(),
                    b"nyx-fernet-salt",
                    100_000,
                    dklen=32,
                )
                new_fernet = Fernet(base64.urlsafe_b64encode(new_key_bytes))
                new_encrypted = new_fernet.encrypt(current_secret.encode()).decode()

                # Store raw encrypted value directly (bypass the ORM type decorator)
                from sqlalchemy import update
                await db.execute(
                    update(Repository)
                    .where(Repository.id == repo.id)
                    .values(webhook_secret=new_encrypted)
                )
                rotated += 1
            except Exception as e:
                logger.error("KEY_ROTATION_FAILED repo_id=%s error=%s", repo.id, e)
                failed += 1

        await db.commit()

    logger.info("KEY_ROTATION_COMPLETE rotated=%d failed=%d", rotated, failed)
    return {"rotated": rotated, "failed": failed}
