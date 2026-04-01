"""Remediation model — tracks an AI fix request from request through merged PR."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import RemediationStatus
from app.database import Base
from app.models.base import TimestampMixin, new_uuid

if TYPE_CHECKING:
    from app.models.finding import Finding


class Remediation(Base, TimestampMixin):
    __tablename__ = "remediations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), index=True)
    requested_by: Mapped[str] = mapped_column(String(255), default="engineer")

    status: Mapped[str] = mapped_column(String(20), default=RemediationStatus.PENDING.value, index=True)

    # ── AI Output ─────────────────────────────────────────────────────────────────
    ai_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Plain-English explanation
    ai_fix_diff: Mapped[Optional[str]] = mapped_column(Text, nullable=True)     # Unified diff
    ai_fix_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # One-line PR description
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ai_model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    prompt_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Non-repudiation: stores the exact prompt sent to Claude and a tamper-evident hash of the diff
    ai_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_diff_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Confidence gating: True when ai_confidence < AI_MIN_CONFIDENCE_THRESHOLD
    confidence_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    # JSON array of heuristic security warnings found in the generated diff
    diff_warnings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Additional context provided by engineer for re-generation
    engineer_context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── PR Tracking ───────────────────────────────────────────────────────────────
    pr_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    pr_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pr_branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    pr_merged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deployment_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Staging deployment

    # ── Engineer Feedback ─────────────────────────────────────────────────────────
    engineer_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    engineer_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── CI Check Results ──────────────────────────────────────────────────────────
    # Populated by the check_run webhook when CI runs on the nyx/fix/* branch.
    # Values: None (no data yet) | "pending" | "pass" | "fail"
    ci_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    ci_failure_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── JIRA Tracking ─────────────────────────────────────────────────────────────
    jira_issue_key: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)   # e.g. SEC-42
    jira_issue_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)         # full browser URL

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="remediations")
