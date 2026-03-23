"""SuppressionPattern — learned patterns from repeated false positive suppression."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class SuppressionPattern(Base, TimestampMixin):
    __tablename__ = "suppression_patterns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    rule_id: Mapped[str] = mapped_column(String(255), index=True)
    scanner: Mapped[str] = mapped_column(String(20), index=True)
    file_path_pattern: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    # NULL = org-wide; set = repo-specific pattern
    repository_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True, index=True
    )
    suppression_reason: Mapped[str] = mapped_column(Text, default="")
    times_applied: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255), default="engineer")
