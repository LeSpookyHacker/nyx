"""
Finding — the core data model for Nyx.

Every security issue discovered by any scanner is normalized into this model.
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import FindingCategory, FindingStatus, Severity
from app.database import Base
from app.models.base import TimestampMixin, new_uuid

if TYPE_CHECKING:
    from app.models.remediation import Remediation
    from app.models.repository import Repository
    from app.models.scan import Scan


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    # Stable fingerprint — SHA256 of (scanner + rule_id + repo_id + file_path + line_start)
    # Used for deduplication across scans.
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    # Foreign keys
    repository_id: Mapped[str] = mapped_column(String(36), ForeignKey("repositories.id"), index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True, index=True)

    # ── Identity ────────────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    rule_id: Mapped[str] = mapped_column(String(255), index=True)
    scanner: Mapped[str] = mapped_column(String(20), index=True)       # ScannerType value
    scanner_native_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scanner_sources: Mapped[str] = mapped_column(String(255), default="")  # comma-sep scanners if cross-scanner dedup

    # ── Location ─────────────────────────────────────────────────────────────────
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True, index=True)
    line_start: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    line_end: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # DAST findings

    # ── Classification ────────────────────────────────────────────────────────────
    category: Mapped[str] = mapped_column(String(20), default=FindingCategory.SAST.value)
    cwe_ids: Mapped[str] = mapped_column(String(500), default="")      # JSON array stored as string
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    remediation_guidance: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # From scanner

    # ── Severity & Priority ───────────────────────────────────────────────────────
    severity: Mapped[str] = mapped_column(String(10), index=True)       # Severity value
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    is_exploitable: Mapped[bool] = mapped_column(Boolean, default=False)
    sla_breach_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Status ────────────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.OPEN.value, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fix_pr_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    advisory_issue_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # GitHub Issue for non-code findings

    # Suppression fields (denormalized for query performance)
    suppression_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    suppressed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    suppressed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Engineer notes
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── Assignment ────────────────────────────────────────────────────────────────
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    assigned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Regression Tracking ───────────────────────────────────────────────────────
    is_regression: Mapped[bool] = mapped_column(Boolean, default=False)
    regression_detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Last engineer-set resolution status (ACCEPTED_RISK or SUPPRESSED) — used to auto-restore on regression
    auto_close_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # ── SLA Escalation ────────────────────────────────────────────────────────────
    sla_notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────────
    repository: Mapped["Repository"] = relationship("Repository", back_populates="findings")
    scan: Mapped[Optional["Scan"]] = relationship("Scan", back_populates="findings")
    remediations: Mapped[List["Remediation"]] = relationship(
        "Remediation", back_populates="finding", cascade="all, delete-orphan"
    )
