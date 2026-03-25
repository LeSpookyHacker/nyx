"""
Shared enumerations and constants used across the Nyx codebase.
"""
from __future__ import annotations

import enum


class ScannerType(str, enum.Enum):
    SEMGREP = "SEMGREP"
    ZAP = "ZAP"
    SNYK = "SNYK"
    TRIVY = "TRIVY"
    BANDIT = "BANDIT"
    GRYPE = "GRYPE"
    CHECKOV = "CHECKOV"
    HADOLINT = "HADOLINT"
    GITLEAKS = "GITLEAKS"
    DEPENDABOT = "DEPENDABOT"
    CODE_SCANNING = "CODE_SCANNING"


class FindingCategory(str, enum.Enum):
    SAST = "SAST"       # Static analysis (Semgrep, Bandit)
    DAST = "DAST"       # Dynamic analysis (ZAP)
    SCA = "SCA"         # Software composition analysis (Snyk, Grype)
    CONTAINER = "CONTAINER"  # Container image scanning (Trivy)
    IAC = "IAC"         # Infrastructure-as-code (Checkov, Trivy)
    SECRETS = "SECRETS" # Hardcoded secrets (Semgrep rules, Bandit)


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        return {
            "CRITICAL": 1.0,
            "HIGH": 0.75,
            "MEDIUM": 0.45,
            "LOW": 0.15,
            "INFO": 0.05,
        }[self.value]

    @property
    def sla_days(self) -> int:
        from app.config import get_settings
        s = get_settings()
        return {
            "CRITICAL": s.SLA_CRITICAL_DAYS,
            "HIGH": s.SLA_HIGH_DAYS,
            "MEDIUM": s.SLA_MEDIUM_DAYS,
            "LOW": s.SLA_LOW_DAYS,
            "INFO": 365,
        }[self.value]


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REMEDIATION = "IN_REMEDIATION"
    FIXED = "FIXED"
    SUPPRESSED = "SUPPRESSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanTrigger(str, enum.Enum):
    WEBHOOK = "WEBHOOK"
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"
    IMPORT = "IMPORT"


class RemediationStatus(str, enum.Enum):
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    REVIEW = "REVIEW"          # AI produced a diff, awaiting engineer approval
    PR_CREATING = "PR_CREATING"
    PR_OPEN = "PR_OPEN"
    MERGED = "MERGED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"


# OWASP Top 10 2021 mapping
OWASP_TOP_10 = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery",
}

CWE_TO_OWASP: dict[str, str] = {
    "CWE-22": "A01",
    "CWE-89": "A03",
    "CWE-79": "A03",
    "CWE-78": "A03",
    "CWE-94": "A03",
    "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-330": "A02",
    "CWE-798": "A02",
    "CWE-295": "A02",
    "CWE-502": "A08",
    "CWE-611": "A05",
    "CWE-918": "A10",
}
