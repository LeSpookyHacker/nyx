"""Audit log model — append-only record of all user/system actions with hash chain integrity."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import new_uuid


class AuditLog(Base):
    """
    Audit log entry with hash chain for tamper detection.

    entry_hash: HMAC-SHA256 over all content fields of this entry.
    prev_hash:  entry_hash of the previous entry (creates a chain).
                "0" * 64 for the first entry.

    If any entry is modified or deleted, the chain breaks and is detectable
    via GET /api/v1/audit/verify.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    actor: Mapped[str] = mapped_column(String(255), index=True)        # user identity or "system"
    action: Mapped[str] = mapped_column(String(100), index=True)       # "finding.suppressed"
    resource_type: Mapped[str] = mapped_column(String(50), index=True) # "finding", "remediation"
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON payload
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    # Hash chain fields
    entry_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)   # HMAC of this entry
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)    # hash of previous entry
