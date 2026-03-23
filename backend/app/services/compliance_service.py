"""
Compliance mapping service.

Maps CWE IDs and OWASP categories to requirements in common security frameworks.
Supported: PCI-DSS 4.0, SOC 2 Type II, HIPAA, NIST CSF 2.0, ISO 27001:2022
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus


@dataclass
class ComplianceControl:
    id: str
    title: str
    description: str
    framework: str
    cwe_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)


@dataclass
class ControlResult:
    control: ComplianceControl
    open_count: int
    total_count: int

    @property
    def is_compliant(self) -> bool:
        return self.open_count == 0

    @property
    def coverage_pct(self) -> float:
        if self.total_count == 0:
            return 100.0
        return round((self.total_count - self.open_count) / self.total_count * 100, 1)


# ─── Framework Control Definitions ───────────────────────────────────────────

FRAMEWORKS: Dict[str, List[ComplianceControl]] = {
    "pci-dss": [
        ComplianceControl(
            id="PCI-6.2.4-INJECTION",
            title="Req 6.2.4 — Injection Attack Prevention",
            description="Software must be protected against injection attacks (SQL, command, LDAP, XML).",
            framework="pci-dss",
            cwe_ids=["CWE-89", "CWE-78", "CWE-94", "CWE-917", "CWE-611"],
            owasp_categories=["A03"],
        ),
        ComplianceControl(
            id="PCI-6.2.4-XSS",
            title="Req 6.2.4 — Cross-Site Scripting Prevention",
            description="Software must be protected against reflected, stored, and DOM-based XSS.",
            framework="pci-dss",
            cwe_ids=["CWE-79", "CWE-80", "CWE-116"],
            owasp_categories=["A03"],
        ),
        ComplianceControl(
            id="PCI-6.2.4-CRYPTO",
            title="Req 6.2.4 — Cryptographic Failures",
            description="Cryptographic implementations must use strong, approved algorithms and key sizes.",
            framework="pci-dss",
            cwe_ids=["CWE-326", "CWE-327", "CWE-330", "CWE-338"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="PCI-6.2.4-SECRETS",
            title="Req 6.2.4 — Hardcoded Secrets",
            description="Cryptographic keys and passwords must not be hardcoded in source code.",
            framework="pci-dss",
            cwe_ids=["CWE-798", "CWE-259"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="PCI-6.2.4-ACCESS",
            title="Req 6.2.4 — Broken Access Control",
            description="Applications must enforce proper access controls and prevent IDOR, path traversal, and privilege escalation.",
            framework="pci-dss",
            cwe_ids=["CWE-22", "CWE-284", "CWE-862", "CWE-863", "CWE-269", "CWE-250"],
            owasp_categories=["A01"],
        ),
        ComplianceControl(
            id="PCI-6.2.4-SSRF",
            title="Req 6.2.4 — SSRF & Deserialization",
            description="Applications must be protected against SSRF and insecure deserialization.",
            framework="pci-dss",
            cwe_ids=["CWE-918", "CWE-502"],
            owasp_categories=["A08", "A10"],
        ),
        ComplianceControl(
            id="PCI-6.3.3",
            title="Req 6.3.3 — Vulnerable Components",
            description="All software components must be free of known vulnerabilities. Patch within SLA.",
            framework="pci-dss",
            cwe_ids=["CWE-1035", "CWE-937"],
            owasp_categories=["A06"],
        ),
        ComplianceControl(
            id="PCI-8.3.6",
            title="Req 8.3.6 — Password Strength",
            description="Passwords and passphrases must meet minimum complexity and hashing requirements.",
            framework="pci-dss",
            cwe_ids=["CWE-521", "CWE-916"],
            owasp_categories=["A07"],
        ),
        ComplianceControl(
            id="PCI-10.7",
            title="Req 10.7 — Security Event Logging",
            description="Failures of critical security controls must be detected, logged, and alerted promptly.",
            framework="pci-dss",
            cwe_ids=["CWE-778", "CWE-223"],
            owasp_categories=["A09"],
        ),
    ],

    "soc2": [
        ComplianceControl(
            id="SOC2-CC6.1",
            title="CC6.1 — Logical Access Controls",
            description="Logical access to systems is restricted to authorized users via access controls and authentication.",
            framework="soc2",
            cwe_ids=["CWE-284", "CWE-287", "CWE-306", "CWE-862", "CWE-863"],
            owasp_categories=["A01", "A07"],
        ),
        ComplianceControl(
            id="SOC2-CC6.2",
            title="CC6.2 — Authentication & Credential Management",
            description="User credentials are protected with appropriate hashing, storage, and rotation mechanisms.",
            framework="soc2",
            cwe_ids=["CWE-287", "CWE-916", "CWE-521", "CWE-798", "CWE-259"],
            owasp_categories=["A07", "A02"],
        ),
        ComplianceControl(
            id="SOC2-CC6.6",
            title="CC6.6 — Transmission Encryption",
            description="Confidential data transmitted over networks is protected with strong encryption protocols.",
            framework="soc2",
            cwe_ids=["CWE-319", "CWE-295", "CWE-326", "CWE-327"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="SOC2-CC6.7",
            title="CC6.7 — Data Integrity Controls",
            description="Data at rest and in transit is protected from unauthorized modification.",
            framework="soc2",
            cwe_ids=["CWE-345", "CWE-346", "CWE-347", "CWE-502"],
            owasp_categories=["A08"],
        ),
        ComplianceControl(
            id="SOC2-CC7.1",
            title="CC7.1 — Vulnerability Management",
            description="Known vulnerabilities in software components are identified and remediated within SLAs.",
            framework="soc2",
            cwe_ids=["CWE-1035", "CWE-937"],
            owasp_categories=["A06"],
        ),
        ComplianceControl(
            id="SOC2-CC8.1",
            title="CC8.1 — Input Validation",
            description="System inputs are validated to prevent injection and other input-based vulnerabilities.",
            framework="soc2",
            cwe_ids=["CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-917"],
            owasp_categories=["A03"],
        ),
    ],

    "hipaa": [
        ComplianceControl(
            id="HIPAA-164.312(a)(1)",
            title="§164.312(a)(1) — Access Control",
            description="Electronic systems containing ePHI must restrict access to authorized users only.",
            framework="hipaa",
            cwe_ids=["CWE-284", "CWE-287", "CWE-306", "CWE-862"],
            owasp_categories=["A01", "A07"],
        ),
        ComplianceControl(
            id="HIPAA-164.312(a)(2)(iv)",
            title="§164.312(a)(2)(iv) — Encryption & Decryption",
            description="Mechanisms to encrypt and decrypt ePHI must use strong, approved algorithms.",
            framework="hipaa",
            cwe_ids=["CWE-326", "CWE-327", "CWE-330"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="HIPAA-164.312(e)(2)(ii)",
            title="§164.312(e)(2)(ii) — Encryption in Transit",
            description="ePHI transmitted over electronic networks must be encrypted against unauthorized access.",
            framework="hipaa",
            cwe_ids=["CWE-319", "CWE-295"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="HIPAA-164.312(c)(1)",
            title="§164.312(c)(1) — Integrity Controls",
            description="ePHI must not be improperly altered or destroyed; integrity controls must be implemented.",
            framework="hipaa",
            cwe_ids=["CWE-345", "CWE-502", "CWE-347"],
            owasp_categories=["A08"],
        ),
        ComplianceControl(
            id="HIPAA-164.312(b)",
            title="§164.312(b) — Audit Controls",
            description="Hardware, software, and procedures to record and examine system activity containing ePHI.",
            framework="hipaa",
            cwe_ids=["CWE-778", "CWE-223"],
            owasp_categories=["A09"],
        ),
        ComplianceControl(
            id="HIPAA-164.306(a)(1)",
            title="§164.306(a)(1) — Confidentiality Safeguards",
            description="Technical safeguards must protect confidentiality of ePHI including preventing injection and SSRF.",
            framework="hipaa",
            cwe_ids=["CWE-89", "CWE-918", "CWE-798"],
            owasp_categories=["A03", "A10"],
        ),
    ],

    "nist-csf": [
        ComplianceControl(
            id="NIST-PR.DS-1",
            title="PR.DS-1 — Data at Rest Protection",
            description="Data-at-rest is protected using appropriate cryptographic mechanisms.",
            framework="nist-csf",
            cwe_ids=["CWE-326", "CWE-327", "CWE-916"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="NIST-PR.DS-2",
            title="PR.DS-2 — Data in Transit Protection",
            description="Data-in-transit is protected using approved encryption protocols.",
            framework="nist-csf",
            cwe_ids=["CWE-319", "CWE-295"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="NIST-PR.AC-1",
            title="PR.AC-1 — Identity and Credential Management",
            description="Identities and credentials are issued, managed, and revoked for authorized users.",
            framework="nist-csf",
            cwe_ids=["CWE-287", "CWE-916", "CWE-798", "CWE-259", "CWE-521"],
            owasp_categories=["A07", "A02"],
        ),
        ComplianceControl(
            id="NIST-PR.AC-4",
            title="PR.AC-4 — Access Permissions & Least Privilege",
            description="Access permissions are managed incorporating least privilege and separation of duties.",
            framework="nist-csf",
            cwe_ids=["CWE-250", "CWE-269", "CWE-284", "CWE-862", "CWE-22"],
            owasp_categories=["A01"],
        ),
        ComplianceControl(
            id="NIST-PR.IP-12",
            title="PR.IP-12 — Vulnerability Management Plan",
            description="A vulnerability management plan is developed and implemented.",
            framework="nist-csf",
            cwe_ids=["CWE-1035", "CWE-937"],
            owasp_categories=["A06"],
        ),
        ComplianceControl(
            id="NIST-DE.CM-8",
            title="DE.CM-8 — Vulnerability Scanning",
            description="Vulnerability scans are performed regularly to detect injection, SSRF, and deserialization flaws.",
            framework="nist-csf",
            cwe_ids=["CWE-89", "CWE-79", "CWE-918", "CWE-502", "CWE-94"],
            owasp_categories=["A03", "A08", "A10"],
        ),
        ComplianceControl(
            id="NIST-RS.MI-3",
            title="RS.MI-3 — Newly Identified Vulnerabilities",
            description="Newly identified vulnerabilities are mitigated or documented as accepted risks.",
            framework="nist-csf",
            cwe_ids=["CWE-89", "CWE-79", "CWE-918", "CWE-502", "CWE-798"],
            owasp_categories=["A03", "A10"],
        ),
    ],

    "iso27001": [
        ComplianceControl(
            id="ISO-A.8.8",
            title="A.8.8 — Technical Vulnerability Management",
            description="Technical vulnerabilities shall be identified and appropriate countermeasures evaluated and taken.",
            framework="iso27001",
            cwe_ids=["CWE-1035", "CWE-937"],
            owasp_categories=["A06"],
        ),
        ComplianceControl(
            id="ISO-A.8.24",
            title="A.8.24 — Use of Cryptography",
            description="Rules for effective use of cryptography and cryptographic key management shall be defined.",
            framework="iso27001",
            cwe_ids=["CWE-326", "CWE-327", "CWE-338", "CWE-330", "CWE-916"],
            owasp_categories=["A02"],
        ),
        ComplianceControl(
            id="ISO-A.8.25",
            title="A.8.25 — Secure Development Lifecycle",
            description="Rules for secure development shall be established and applied to software within the organization.",
            framework="iso27001",
            cwe_ids=["CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-502", "CWE-918"],
            owasp_categories=["A03", "A08", "A10"],
        ),
        ComplianceControl(
            id="ISO-A.8.3",
            title="A.8.3 — Information Access Restriction",
            description="Access to information and associated assets shall be restricted per the access control policy.",
            framework="iso27001",
            cwe_ids=["CWE-284", "CWE-862", "CWE-863", "CWE-22"],
            owasp_categories=["A01"],
        ),
        ComplianceControl(
            id="ISO-A.5.17",
            title="A.5.17 — Authentication Information",
            description="Allocation and management of authentication information shall be controlled.",
            framework="iso27001",
            cwe_ids=["CWE-287", "CWE-916", "CWE-798", "CWE-259", "CWE-521"],
            owasp_categories=["A07"],
        ),
        ComplianceControl(
            id="ISO-A.8.16",
            title="A.8.16 — Monitoring Activities",
            description="Networks, systems, and applications shall be monitored for anomalous behaviour.",
            framework="iso27001",
            cwe_ids=["CWE-778", "CWE-223"],
            owasp_categories=["A09"],
        ),
        ComplianceControl(
            id="ISO-A.5.14",
            title="A.5.14 — Information Transfer",
            description="Information transfer rules, procedures, and controls shall protect data in transit.",
            framework="iso27001",
            cwe_ids=["CWE-319", "CWE-295"],
            owasp_categories=["A02"],
        ),
    ],
}

FRAMEWORK_META: Dict[str, Dict] = {
    "pci-dss": {
        "name": "PCI-DSS 4.0",
        "description": "Payment Card Industry Data Security Standard version 4.0",
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2 — Security, Availability, Confidentiality",
    },
    "hipaa": {
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act Security Rule",
    },
    "nist-csf": {
        "name": "NIST CSF 2.0",
        "description": "NIST Cybersecurity Framework version 2.0",
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "description": "Information Security Management Systems — Requirements",
    },
}


async def get_control_findings(
    db: AsyncSession,
    framework_id: str,
    control_id: str,
    repository_id: Optional[str] = None,
) -> Optional[dict]:
    """
    Return open findings (with repository info) matched to a specific control.
    Findings are grouped by repository.
    """
    from app.models.finding import Finding
    from app.models.repository import Repository

    controls = FRAMEWORKS.get(framework_id, [])
    control = next((c for c in controls if c.id == control_id), None)
    if control is None:
        return None

    cwe_conditions = [Finding.cwe_ids.like(f"%{cwe}%") for cwe in control.cwe_ids]
    owasp_conditions = [
        Finding.owasp_category.like(f"%{cat}%") for cat in control.owasp_categories
    ]
    combined = or_(*cwe_conditions, *owasp_conditions)

    conditions = [
        combined,
        Finding.status == FindingStatus.OPEN.value,
    ]
    if repository_id:
        conditions.append(Finding.repository_id == repository_id)

    stmt = (
        select(Finding, Repository.github_full_name)
        .join(Repository, Finding.repository_id == Repository.id)
        .where(and_(*conditions))
        .order_by(Finding.priority_score.desc())
        .limit(200)
    )
    rows = (await db.execute(stmt)).all()

    # Group by repository
    grouped: dict[str, dict] = {}
    for finding, repo_full_name in rows:
        repo_name = repo_full_name.split("/")[-1]
        if finding.repository_id not in grouped:
            grouped[finding.repository_id] = {
                "repository_id": finding.repository_id,
                "repository_name": repo_name,
                "repository_full_name": repo_full_name,
                "findings": [],
            }
        grouped[finding.repository_id]["findings"].append({
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "scanner": finding.scanner,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "priority_score": round(finding.priority_score, 1),
            "cve_id": finding.cve_id,
            "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
        })

    return {
        "control_id": control_id,
        "control_title": control.title,
        "repositories": list(grouped.values()),
        "total_open": len(rows),
    }


async def get_compliance_report(
    db: AsyncSession,
    framework_id: str,
    repository_id: Optional[str] = None,
) -> List[ControlResult]:
    """
    For each control in the framework, count open and total (non-suppressed) findings
    whose CWE IDs or OWASP category match.
    """
    from app.models.finding import Finding

    controls = FRAMEWORKS.get(framework_id, [])
    results: List[ControlResult] = []

    for control in controls:
        cwe_conditions = [Finding.cwe_ids.like(f"%{cwe}%") for cwe in control.cwe_ids]
        owasp_conditions = [
            Finding.owasp_category.like(f"%{cat}%") for cat in control.owasp_categories
        ]
        combined = or_(*cwe_conditions, *owasp_conditions)

        base = [
            combined,
            Finding.status.notin_([FindingStatus.SUPPRESSED.value]),
        ]
        if repository_id:
            base.append(Finding.repository_id == repository_id)

        total_q = await db.execute(
            select(func.count()).select_from(Finding).where(and_(*base))
        )
        total = total_q.scalar() or 0

        open_q = await db.execute(
            select(func.count()).select_from(Finding).where(
                and_(*base, Finding.status == FindingStatus.OPEN.value)
            )
        )
        open_count = open_q.scalar() or 0

        results.append(ControlResult(control=control, open_count=open_count, total_count=total))

    return results
