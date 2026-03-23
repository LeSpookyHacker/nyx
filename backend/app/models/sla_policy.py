"""SlaPolicy — custom SLA rules per severity and repository."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class SlaPolicy(Base, TimestampMixin):
    __tablename__ = "sla_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255))
    # NULL repository_id = org-wide default; repo-specific takes precedence
    repository_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # CRITICAL, HIGH, MEDIUM, LOW, INFO, or ALL (matches any severity)
    severity: Mapped[str] = mapped_column(String(10), default="ALL")
    max_days: Mapped[int] = mapped_column(Integer, default=30)
    # NOTIFY | JIRA | BOTH | NONE
    escalation_action: Mapped[str] = mapped_column(String(10), default="NOTIFY")
    jira_project_key: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
