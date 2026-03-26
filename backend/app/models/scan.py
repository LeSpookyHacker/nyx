"""Scan model — represents one scanner run against a repository."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import ScanStatus, ScanTrigger, ScannerType
from app.database import Base
from app.models.base import TimestampMixin, new_uuid

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.repository import Repository


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    repository_id: Mapped[str] = mapped_column(String(36), ForeignKey("repositories.id"), index=True)

    scanner: Mapped[str] = mapped_column(String(20))  # ScannerType value
    trigger: Mapped[str] = mapped_column(String(20), default=ScanTrigger.MANUAL.value)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING.value)

    # Git context
    git_sha: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    git_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # branch/tag

    # Results
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    new_finding_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_finding_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # GitHub Check Run ID (for PR checks integration)
    check_run_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # GitHub delivery ID — prevents replay of identical webhook events
    delivery_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, unique=True, index=True)

    # Scan submission integrity — True if X-Nyx-Submission-HMAC was present and valid
    submission_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Error info
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    repository: Mapped["Repository"] = relationship("Repository", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan")
