"""Audit service — write audit log entries with hash chain integrity."""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import logging
import secrets as _secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger("nyx.audit")

_CHAIN_GENESIS = "0" * 64  # prev_hash for the very first entry

# SEC-309: fallback HMAC key — generated once at import time so the audit chain
# is at least self-consistent within a single process lifetime.
# WARNING: chain cannot be verified across process restarts without NYX_SECRET_KEY.
_FALLBACK_HMAC_KEY: bytes = _secrets.token_bytes(32)


def _get_hmac_key() -> bytes:
    """
    Return the HMAC key for audit chain integrity (H5).
    Raises RuntimeError in production if NYX_SECRET_KEY is not set — a weak fallback
    key would silently undermine tamper-evidence guarantees.
    """
    try:
        from app.config import get_settings
        settings = get_settings()
        if settings.NYX_SECRET_KEY:
            return settings.NYX_SECRET_KEY.encode()
        if settings.ENVIRONMENT == "production":
            raise RuntimeError(
                "[SECURITY] NYX_SECRET_KEY is not set. "
                "Cannot start in production mode without a secret key for audit chain integrity. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
    except RuntimeError:
        raise
    except Exception:
        pass
    # SEC-231 / SEC-309: instead of a well-known hardcoded key, use a random per-process key.
    # The chain is still tamper-evident within a single process lifetime, and
    # on restart a new random key is generated — forensically weaker than a
    # persistent secret but far better than a public constant.
    logger.warning(
        "NYX_SECRET_KEY not set — audit HMAC chain uses a one-time random key. "
        "Chain is self-consistent within this process lifetime but cannot be "
        "verified across restarts. Set NYX_SECRET_KEY before deploying to production."
    )
    return _FALLBACK_HMAC_KEY


def _compute_entry_hash(
    actor: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    metadata_json: Optional[str],
    ip_address: Optional[str],
    created_at: datetime,
    prev_hash: str,
) -> str:
    """HMAC-SHA256 over the canonical representation of this audit entry."""
    canonical = "|".join([
        actor,
        action,
        resource_type,
        resource_id or "",
        metadata_json or "",
        ip_address or "",
        created_at.isoformat(),
        prev_hash,
    ])
    return hmac_mod.new(_get_hmac_key(), canonical.encode(), hashlib.sha256).hexdigest()


async def log_event(
    db: AsyncSession,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Write a single audit log entry with hash chain integrity.
    Call before db.commit() in the caller.
    """
    # Fetch the most recently committed entry's hash to form the chain
    try:
        prev_result = await db.execute(
            select(AuditLog.entry_hash).order_by(
                desc(AuditLog.created_at), desc(AuditLog.id)
            ).limit(1)
        )
        prev_hash = prev_result.scalar_one_or_none() or _CHAIN_GENESIS
    except Exception:
        logger.warning("Could not fetch prev_hash for audit chain — using genesis")
        prev_hash = _CHAIN_GENESIS

    now = datetime.now(timezone.utc)
    metadata_json = json.dumps(metadata, sort_keys=True) if metadata else None

    entry_hash = _compute_entry_hash(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=metadata_json,
        ip_address=ip_address,
        created_at=now,
        prev_hash=prev_hash,
    )

    db.add(AuditLog(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        metadata_json=metadata_json,
        ip_address=ip_address,
        created_at=now,
        entry_hash=entry_hash,
        prev_hash=prev_hash,
    ))
