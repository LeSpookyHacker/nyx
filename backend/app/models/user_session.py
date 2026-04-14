"""Session store — random session IDs decouple the auth cookie from the raw API key."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, new_uuid


class UserSession(Base, TimestampMixin):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    # SHA-256 of the random session token — the plaintext only lives in the cookie.
    session_id_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Identity shown in audit logs: api_key name, or "bootstrap" for env-var fallback.
    identity: Mapped[str] = mapped_column(String(255), default="bootstrap")
    # Comma-separated scope list copied from the authenticating api key at creation time.
    scopes: Mapped[str] = mapped_column(String(255), default="admin")
    # Optional FK-ish back-reference (not enforced — the referenced ApiKey may be a bootstrap env key).
    api_key_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
