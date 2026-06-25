"""Pydantic schemas for Repository endpoints."""
from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# owner/repo — allow alphanumerics, hyphens, underscores, dots; no path traversal
_FULL_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,100}/[a-zA-Z0-9._-]{1,100}$")

# Git branch name — no consecutive dots (path traversal), no leading/trailing dots or slashes
_BRANCH_RE = re.compile(r"^[a-zA-Z0-9._/\-]{1,255}$")
_BRANCH_TRAVERSAL_RE = re.compile(r"\.\.")

# Whitelist of scanner identifiers accepted by the scan worker (H-3)
_VALID_SCANNERS = frozenset({
    "SEMGREP", "BANDIT", "TRIVY", "GRYPE", "CHECKOV", "SNYK",
    "CODE_SCANNING", "GITLEAKS", "TRUFFLEHOG", "OSQUERY", "ZAP", "HADOLINT",
})


def _validate_scanners(scanners: List[str]) -> List[str]:
    upper = [s.upper().strip() for s in scanners]
    invalid = [s for s in upper if s not in _VALID_SCANNERS]
    if invalid:
        raise ValueError(f"Unknown scanner(s): {', '.join(invalid)}. Valid: {', '.join(sorted(_VALID_SCANNERS))}")
    return upper


class RepositoryCreate(BaseModel):
    github_full_name: str
    enabled_scanners: List[str] = ["SEMGREP", "BANDIT", "TRIVY"]

    @field_validator("github_full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        if not _FULL_NAME_RE.match(v):
            raise ValueError(
                "github_full_name must be in 'owner/repo' format "
                "(alphanumerics, hyphens, underscores, dots only)"
            )
        return v

    @field_validator("enabled_scanners")
    @classmethod
    def validate_scanners(cls, v: List[str]) -> List[str]:
        return _validate_scanners(v)


class RepositoryUpdate(BaseModel):
    enabled_scanners: Optional[List[str]] = None
    default_branch: Optional[str] = None

    # Auto PR Mode configuration
    auto_pr_mode: Optional[bool] = None
    auto_pr_severity_threshold: Optional[str] = None
    auto_pr_daily_token_budget: Optional[int] = Field(None, ge=1000, le=500000)
    auto_pr_skip_low_confidence: Optional[bool] = None
    auto_pr_require_passing_checks: Optional[bool] = None
    auto_pr_security_audit: Optional[bool] = None

    @field_validator("auto_pr_severity_threshold")
    @classmethod
    def validate_severity_threshold(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        _VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        parts = [p.strip().upper() for p in v.split(",") if p.strip()]
        if not parts:
            raise ValueError("at least one severity must be selected")
        invalid = [p for p in parts if p not in _VALID_SEVERITIES]
        if invalid:
            raise ValueError(f"invalid severity values: {', '.join(invalid)}")
        return ",".join(parts)

    @field_validator("default_branch")
    @classmethod
    def validate_branch(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            if not _BRANCH_RE.match(v):
                raise ValueError("default_branch contains invalid characters (allowed: alphanumerics, - _ . /)")
            if _BRANCH_TRAVERSAL_RE.search(v):
                raise ValueError("default_branch must not contain '..' (path traversal)")
        return v

    @field_validator("enabled_scanners")
    @classmethod
    def validate_scanners(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            return _validate_scanners(v)
        return v


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    github_full_name: str
    github_repo_id: Optional[int] = None
    default_branch: str
    description: Optional[str] = None
    language: Optional[str] = None
    is_private: bool
    webhook_active: bool
    # SEC-220: webhook_secret intentionally excluded — it is the HMAC signing key for
    # GitHub webhook verification and must not be exposed in API responses. Use a
    # dedicated admin endpoint to rotate it when needed.
    enabled_scanners: str
    risk_score: float
    open_critical: int
    open_high: int
    open_medium: int
    open_low: int
    open_info: int
    last_scan_at: Optional[datetime] = None
    # Auto PR Mode config + live budget usage
    auto_pr_mode: bool = False
    auto_pr_severity_threshold: str = "CRITICAL,HIGH"
    auto_pr_daily_token_budget: int = 50000
    auto_pr_tokens_used_today: int = 0
    auto_pr_skip_low_confidence: bool = True
    auto_pr_require_passing_checks: bool = True
    auto_pr_security_audit: bool = True
    created_at: datetime
    updated_at: datetime

    @property
    def scanner_list(self) -> List[str]:
        return [s.strip() for s in self.enabled_scanners.split(",") if s.strip()]
