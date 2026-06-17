"""Pydantic schemas for Remediation endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class RemediationRequest(BaseModel):
    finding_id: str
    requested_by: str = "engineer"
    engineer_context: Optional[str] = None  # Additional context for AI; capped to prevent prompt injection

    from pydantic import field_validator

    @field_validator("engineer_context")
    @classmethod
    def cap_engineer_context(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 2000:
            return v[:2000]
        return v


class RemediationApprove(BaseModel):
    engineer_notes: Optional[str] = Field(None, max_length=5000)  # SEC-330
    auto_merge: bool = False
    jira_assignee: Optional[str] = None


class RemediationReject(BaseModel):
    engineer_notes: str = Field(..., max_length=5000)  # SEC-330


class RemediationRegenerate(BaseModel):
    engineer_context: str  # Engineer tells Claude what's wrong / additional context

    from pydantic import field_validator

    @field_validator("engineer_context")
    @classmethod
    def cap_engineer_context(cls, v: str) -> str:
        return v[:2000] if len(v) > 2000 else v


class RemediationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    requested_by: str
    status: str
    ai_explanation: Optional[str] = None
    ai_fix_diff: Optional[str] = None
    ai_fix_summary: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_model: Optional[str] = None
    # ai_prompt is intentionally excluded from API responses (M4 — information disclosure).
    # The prompt is stored in the DB for audit non-repudiation but not returned to clients.
    ai_diff_sha256: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    pr_branch: Optional[str] = None
    pr_merged_at: Optional[datetime] = None
    deployment_url: Optional[str] = None
    engineer_approved: Optional[bool] = None
    engineer_notes: Optional[str] = None
    error_message: Optional[str] = None
    ci_status: Optional[str] = None
    ci_failure_details: Optional[str] = None
    jira_issue_key: Optional[str] = None
    jira_issue_url: Optional[str] = None
    # Auto PR Mode — distinguishes auto-triggered remediations and exposes audit/check status.
    # audit_result is the parsed security-audit verdict (passed/risk_level/findings/summary).
    is_auto_triggered: bool = False
    audit_result: Optional[str] = None
    audit_passed: Optional[bool] = None
    check_run_id: Optional[int] = None
    check_run_conclusion: Optional[str] = None
    created_at: datetime
    updated_at: datetime
