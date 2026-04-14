"""Saved filter model — named, reusable filter presets for FindingsPage.

Global (single-user) for now. When a real user model lands, add a user_id FK
and scope list/create/delete queries by it.
"""
from __future__ import annotations

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class SavedFilter(Base, TimestampMixin):
    __tablename__ = "saved_filters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(100))
    # Free-form filter state serialized to JSON — the client decides what fits
    # (severity, scanner, status, repository_id, search, is_regression, etc.)
    filters_json: Mapped[str] = mapped_column(Text)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # Plain page identifier so future pages (scans, remediation) can reuse the table.
    scope: Mapped[str] = mapped_column(String(30), default="findings")
