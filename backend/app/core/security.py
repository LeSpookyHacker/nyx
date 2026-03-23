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


async def require_api_key(api_key: str | None = Security(_api_key_header)) -> str:
    """
    Dependency that enforces API key authentication.

    If NYX_API_KEY is not configured:
      - In 'production' ENVIRONMENT: raises 500 at startup (see main.py warn_insecure_config).
      - Otherwise: allows all with a 'dev' identity and logs a warning per request.
    """
    if not settings.NYX_API_KEY:
        if settings.ENVIRONMENT == "production":
            # This should have been caught at startup; fail hard here as a backstop.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Server misconfiguration: authentication is not configured.",
            )
        # Development mode — log every unauthenticated request so it is visible.
        logger.warning(
            "NYX_API_KEY is not set — request allowed in development mode. "
            "Set NYX_API_KEY to enable authentication."
        )
        return "dev"

    if not api_key or not secrets.compare_digest(api_key, settings.NYX_API_KEY):
        logger.warning("Rejected request: invalid or missing API key")
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
