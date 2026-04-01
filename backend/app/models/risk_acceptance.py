"""
RiskAcceptance — formal risk acceptance workflow.

When a finding is marked ACCEPTED_RISK, this model records who approved it,
why, when it expires, and any supporting evidence.  This provides the audit
trail required for SOC 2, ISO 27001, and similar compliance frameworks.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class RiskAcceptance(Base, TimestampMixin):
    """Formal approval record for an ACCEPTED_RISK finding."""
    __tablename__ = "risk_acceptances"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), index=True
    )

    # Who submitted the acceptance request
    requested_by: Mapped[str] = mapped_column(String(255))
    # Who formally approved it (can differ from requester)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Structured reason: business justification, compensating controls, etc.
    business_justification: Mapped[str] = mapped_column(Text)
    # Optional compensating controls in place
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Optional link to supporting evidence (ticket URL, document, etc.)
    evidence_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # When this acceptance expires — must be re-approved after this date
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # When the approver formally signed off
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Current state: pending_approval | approved | expired | revoked
    approval_status: Mapped[str] = mapped_column(String(30), default="approved", index=True)

    finding: Mapped["app.models.finding.Finding"] = relationship(  # type: ignore[name-defined]
        "Finding", foreign_keys=[finding_id]
    )
