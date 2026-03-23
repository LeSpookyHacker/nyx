"""Pydantic schemas for Scan endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ScanTriggerRequest(BaseModel):
    repository_id: str
    scanner: str
    git_ref: Optional[str] = None  # branch/tag; defaults to repo's default branch


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_id: str
    scanner: str
    trigger: str
    status: str
    git_sha: Optional[str] = None
    git_ref: Optional[str] = None
    finding_count: int
    new_finding_count: int
    fixed_finding_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
