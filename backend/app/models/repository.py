"""Repository model."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.crypto import EncryptedString
from app.database import Base
from app.models.base import TimestampMixin, new_uuid

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.scan import Scan


class Repository(Base, TimestampMixin):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    github_full_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)  # "org/repo"
    github_repo_id: Mapped[Optional[int]] = mapped_column(Integer, unique=True, nullable=True)
    default_branch: Mapped[str] = mapped_column(String(100), default="main")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    language: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)

    # Webhook configuration — webhook_secret is encrypted at rest when NYX_SECRET_KEY is set
    webhook_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    webhook_secret: Mapped[str] = mapped_column(EncryptedString, default="")
    webhook_active: Mapped[bool] = mapped_column(Boolean, default=False)

    # Enabled scanners (comma-separated)
    enabled_scanners: Mapped[str] = mapped_column(String(255), default="SEMGREP,BANDIT,TRIVY")

    # Cached risk metrics (updated after each scan)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    open_critical: Mapped[int] = mapped_column(Integer, default=0)
    open_high: Mapped[int] = mapped_column(Integer, default=0)
    open_medium: Mapped[int] = mapped_column(Integer, default=0)
    open_low: Mapped[int] = mapped_column(Integer, default=0)
    open_info: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")

    @property
    def scanner_list(self) -> List[str]:
        return [s.strip() for s in self.enabled_scanners.split(",") if s.strip()]
