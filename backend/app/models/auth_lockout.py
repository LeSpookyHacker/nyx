"""
AuthLockout — persistent brute-force lockout state.

Survives container restarts so an attacker cannot reset lockout state
by triggering a redeploy or OOM kill.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AuthLockout(Base):
    """Per-IP brute-force lockout record, written through to the database."""
    __tablename__ = "auth_lockouts"

    # Primary key is the client IP address (IPv4 or IPv6, max 45 chars for IPv6-mapped IPv4)
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    first_failure_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Set when failure_count reaches the lockout threshold
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
