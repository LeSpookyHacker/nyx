"""API key model — database-backed key store enabling rotation and revocation."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # SHA-256 hex
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    # Comma-separated scope list: scanner, readonly, analyst, admin
    # Default is "readonly" — explicit escalation required for elevated scopes (M1)
    scopes: Mapped[str] = mapped_column(String(255), default="readonly")
