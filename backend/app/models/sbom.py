"""SBOM — Software Bill of Materials snapshots and change alerts."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class Sbom(Base, TimestampMixin):
    """One SBOM snapshot per submission. Components stored as normalized JSON."""
    __tablename__ = "sboms"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    format: Mapped[str] = mapped_column(String(20))       # cyclonedx | spdx
    tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)   # syft | trivy | etc.
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    git_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Normalized component list — [{name, version, purl, license, type}]
    components_json: Mapped[str] = mapped_column(Text, default="[]")


class SbomAlert(Base, TimestampMixin):
    """Raised whenever an SBOM diff reveals added, removed, or updated components."""
    __tablename__ = "sbom_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    sbom_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sboms.id", ondelete="CASCADE"), index=True
    )
    previous_sbom_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    added_count: Mapped[int] = mapped_column(Integer, default=0)
    removed_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)

    # List of {type: added|removed|updated, name, old_version?, new_version?}
    changes_json: Mapped[str] = mapped_column(Text, default="[]")

    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
