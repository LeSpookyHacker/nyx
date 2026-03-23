"""Audit log model — immutable record of all user/system actions."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    actor: Mapped[str] = mapped_column(String(255), index=True)        # user identity or "system"
    action: Mapped[str] = mapped_column(String(100), index=True)       # "finding.suppressed"
    resource_type: Mapped[str] = mapped_column(String(50), index=True) # "finding", "remediation"
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON payload
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
