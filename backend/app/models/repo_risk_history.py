"""RepoRiskHistory — daily risk score snapshots per repository."""
from __future__ import annotations

from datetime import date

from sqlalchemy import Date, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class RepoRiskHistory(Base, TimestampMixin):
    __tablename__ = "repo_risk_history"
    __table_args__ = (
        UniqueConstraint("repository_id", "snapshot_date", name="uq_repo_risk_history_repo_date"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    snapshot_date: Mapped[date] = mapped_column(Date, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    open_critical: Mapped[int] = mapped_column(Integer, default=0)
    open_high: Mapped[int] = mapped_column(Integer, default=0)
    open_medium: Mapped[int] = mapped_column(Integer, default=0)
    open_low: Mapped[int] = mapped_column(Integer, default=0)
    open_info: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
