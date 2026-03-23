"""JiraLink — tracks JIRA tickets created from Nyx findings."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class JiraLink(Base, TimestampMixin):
    __tablename__ = "jira_links"
    __table_args__ = (UniqueConstraint("finding_id", name="uq_jira_links_finding"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )

    jira_issue_key: Mapped[str] = mapped_column(String(50))    # e.g. SEC-42
    jira_issue_url: Mapped[str] = mapped_column(String(2000))  # full browser URL
    jira_project_key: Mapped[str] = mapped_column(String(20))
    jira_status: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    jira_assignee: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    jira_priority: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
