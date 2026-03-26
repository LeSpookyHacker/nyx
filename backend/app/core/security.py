"""
Security utilities: API key authentication and webhook HMAC verification.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("nyx.security")

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _key_identity(api_key: str) -> str:
    """Return a short, non-reversible identifier for an API key for audit logs."""
    return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:12]


def get_client_ip(request: Request) -> str:
    """
    Extract the most likely real client IP.
    Checks X-Forwarded-For first (set by load balancers/reverse proxies),
    then falls back to the direct TCP peer address.
    """
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def require_api_key(
    request: Request,
    api_key: str | None = Security(_api_key_header),
) -> str:
    """
    Dependency that enforces API key authentication.

    Auth order:
      1. Hash the supplied key and look it up in the api_keys DB table.
         If found (active, not expired): accept and update last_used_at.
      2. Fall back to comparing against NYX_API_KEY env var — this covers
         bootstrap deployments before the DB key is seeded, and is the
         sole path in development mode when NYX_API_KEY is not set.

    If NYX_API_KEY is not configured and no DB key matches:
      - In 'production' ENVIRONMENT: raises 503.
      - Otherwise: allows with a 'dev' identity and logs a warning.
    """
    from datetime import datetime, timezone

    ip = get_client_ip(request)

    if not api_key:
        if not settings.NYX_API_KEY:
            if settings.ENVIRONMENT == "production":
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Server misconfiguration: authentication is not configured.",
                )
            logger.warning(
                "NYX_API_KEY is not set — request allowed in development mode. "
                "Set NYX_API_KEY to enable authentication."
            )
            return "dev"
        logger.warning("AUTH_FAILURE ip=%s endpoint=%s reason=missing", ip, request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # ── 1. DB-backed key lookup ────────────────────────────────────────────────
    try:
        from sqlalchemy import select as sa_select
        from app.database import AsyncSessionLocal
        from app.models.api_key import ApiKey

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                sa_select(ApiKey).where(
                    ApiKey.key_hash == key_hash,
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
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="API key has expired",
                        headers={"WWW-Authenticate": "ApiKey"},
                    )
                record.last_used_at = now
                await db.commit()
                return f"apikey:{record.name}"
    except HTTPException:
        raise
    except Exception:
        logger.exception("DB API key lookup failed; falling back to env var auth")

    # ── 2. Env-var fallback (backward compat / bootstrap) ─────────────────────
    if not settings.NYX_API_KEY:
        if settings.ENVIRONMENT == "production":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Server misconfiguration: authentication is not configured.",
            )
        logger.warning(
            "NYX_API_KEY is not set — request allowed in development mode. "
            "Set NYX_API_KEY to enable authentication."
        )
        return "dev"

    if not secrets.compare_digest(api_key, settings.NYX_API_KEY):
        logger.warning(
            "AUTH_FAILURE ip=%s endpoint=%s reason=invalid",
            ip,
            request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return _key_identity(api_key)


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

    if not settings.SNYK_WEBHOOK_SECRET:
        issues.append("SNYK_WEBHOOK_SECRET is not set — Snyk webhooks are accepted without signature verification")

    if not settings.NYX_WEBHOOK_SECRET:
        issues.append("NYX_WEBHOOK_SECRET is not set — GitHub webhook repo enumeration is possible before HMAC check")

    if settings.JIRA_MOCK_MODE and settings.ENVIRONMENT == "production":
        issues.append("JIRA_MOCK_MODE=true in production — JIRA tickets will not be created")

    if settings.DEBUG and settings.ENVIRONMENT == "production":
        issues.append("DEBUG=true in production — SQL queries and tracebacks may be exposed")

    if not settings.HTTPS_ONLY and settings.ENVIRONMENT == "production":
        issues.append("HTTPS_ONLY=false in production — API traffic is not enforced over HTTPS (L-4)")

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


def generate_webhook_secret() -> str:
    """Generate a cryptographically random 32-byte hex webhook secret."""
    return secrets.token_hex(32)
