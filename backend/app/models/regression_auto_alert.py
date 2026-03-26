"""RegressionAutoAlert — raised when regressed findings are automatically restored to their prior status."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class RegressionAutoAlert(Base, TimestampMixin):
    """
    Created whenever the scan worker auto-restores one or more findings to their
    previous ACCEPTED_RISK or SUPPRESSED status upon regression detection.
    """
    __tablename__ = "regression_auto_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # How many findings were auto-sorted in this batch
    auto_sorted_count: Mapped[int] = mapped_column(Integer, default=0)

    # JSON list of {finding_id, title, severity, restored_status}
    findings_json: Mapped[str] = mapped_column(Text, default="[]")

    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
