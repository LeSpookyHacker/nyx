"""
Custom compliance framework models.

Allow security teams to define their own control frameworks beyond the built-in
PCI-DSS, SOC 2, HIPAA, NIST CSF, and ISO 27001 definitions.

Each CustomFramework has many CustomControls. Controls map to findings via
CWE IDs and/or OWASP categories — the same mechanism used by built-in frameworks.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class CustomFramework(Base, TimestampMixin):
    """A user-defined compliance framework."""
    __tablename__ = "custom_frameworks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    # Short slug used in API paths, e.g. "my-company-sec-policy"
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="admin")

    controls: Mapped[list["CustomControl"]] = relationship(
        "CustomControl", back_populates="framework", cascade="all, delete-orphan"
    )


class CustomControl(Base, TimestampMixin):
    """A single control within a custom framework."""
    __tablename__ = "custom_controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    framework_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("custom_frameworks.id"), index=True
    )
    # Short control identifier, e.g. "SEC-1.2"
    control_id: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # JSON array of CWE IDs to match, e.g. '["CWE-89", "CWE-79"]'
    cwe_ids_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")
    # JSON array of OWASP category codes, e.g. '["A01", "A03"]'
    owasp_categories_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="[]")

    framework: Mapped["CustomFramework"] = relationship("CustomFramework", back_populates="controls")
