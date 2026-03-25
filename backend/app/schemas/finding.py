"""Pydantic schemas for Finding endpoints."""
from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, field_validator

from app.core.constants import FindingCategory, FindingStatus, Severity


class FindingBase(BaseModel):
    title: str
    description: str = ""
    rule_id: str
    scanner: str
    category: str = FindingCategory.SAST.value
    severity: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    url: Optional[str] = None
    cwe_ids: List[str] = []
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation_guidance: Optional[str] = None


class FindingCreate(FindingBase):
    repository_id: str
    scan_id: Optional[str] = None
    fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    fingerprint: str
    repository_id: str
    scan_id: Optional[str] = None
    title: str
    description: str
    rule_id: str
    scanner: str
    scanner_sources: str
    category: str
    severity: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    url: Optional[str] = None
    cwe_ids: str  # stored as JSON string
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation_guidance: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    priority_score: float
    is_exploitable: bool
    sla_breach_at: Optional[datetime] = None
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    fix_pr_url: Optional[str] = None
    notes: Optional[str] = None
    suppression_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    @property
    def cwe_list(self) -> List[str]:
        try:
            return json.loads(self.cwe_ids) if self.cwe_ids else []
        except Exception:
            return []


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    notes: Optional[str] = None


class FindingSuppressRequest(BaseModel):
    reason: str
    expires_days: Optional[int] = None  # None = permanent


class FindingNoteUpdate(BaseModel):
    notes: str


class FindingListParams(BaseModel):
    severity: Optional[List[str]] = None
    scanner: Optional[List[str]] = None
    status: Optional[List[str]] = None
    category: Optional[List[str]] = None
    repository_id: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    page_size: int = 50
    sort_by: str = "priority_score"
    sort_desc: bool = True


class GeneratePromptRequest(BaseModel):
    finding_ids: List[str]

    @field_validator("finding_ids")
    @classmethod
    def cap_finding_ids(cls, v: List[str]) -> List[str]:
        if len(v) > 100:
            raise ValueError("Cannot generate a prompt for more than 100 findings at once")
        return v


class BulkStatusUpdate(BaseModel):
    finding_ids: List[str]
    status: FindingStatus
    notes: Optional[str] = None

    @field_validator("finding_ids")
    @classmethod
    def cap_finding_ids(cls, v: List[str]) -> List[str]:
        if len(v) > 500:
            raise ValueError("Cannot bulk-update more than 500 findings at once")
        return v
