"""GitHub Dependabot vulnerability alerts normalizer.

Processes alerts from the GitHub Dependabot Alerts API:
    GET /repos/{owner}/{repo}/dependabot/alerts
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding, cvss_to_severity

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class DependabotNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Any) -> List[NormalizedFinding]:
        if not isinstance(raw_output, list):
            return []

        findings: List[NormalizedFinding] = []
        for alert in raw_output:
            try:
                findings.append(self._normalize_alert(alert))
            except Exception:
                continue
        return findings

    def _normalize_alert(self, alert: Dict[str, Any]) -> NormalizedFinding:
        advisory = alert.get("security_advisory", {})
        vuln = alert.get("security_vulnerability", {})
        dep = alert.get("dependency", {})
        package = dep.get("package", {}) or vuln.get("package", {})

        pkg_name = package.get("name", "unknown")
        ecosystem = package.get("ecosystem", "")
        manifest_path = dep.get("manifest_path", "")

        # Severity — prefer CVSS score, fall back to advisory severity label
        cvss_score = advisory.get("cvss", {}).get("score")
        if cvss_score is not None:
            severity = cvss_to_severity(float(cvss_score))
        else:
            raw_sev = advisory.get("severity", vuln.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(raw_sev, "MEDIUM")

        cve_id: Optional[str] = advisory.get("cve_id")
        ghsa_id: str = advisory.get("ghsa_id", "")
        summary: str = advisory.get("summary", f"Vulnerable dependency: {pkg_name}")
        description: str = advisory.get("description", summary)

        cwe_ids = [
            f"CWE-{c['cwe_id'].replace('CWE-', '')}"
            for c in advisory.get("cwes", [])
            if c.get("cwe_id")
        ]

        # Fix info
        patched = vuln.get("first_patched_version", {})
        fix_version = patched.get("identifier") if patched else None
        vuln_range = vuln.get("vulnerable_version_range", "")

        remediation_parts = []
        if fix_version:
            remediation_parts.append(f"Update `{pkg_name}` to version `{fix_version}` or later.")
        elif vuln_range:
            remediation_parts.append(f"Affected versions: `{vuln_range}`. No patched version available yet — monitor for updates.")
        if ghsa_id:
            remediation_parts.append(f"Advisory: https://github.com/advisories/{ghsa_id}")

        rule_id = cve_id or ghsa_id or f"dependabot.{pkg_name}"

        return NormalizedFinding(
            title=summary,
            description=description,
            rule_id=f"dependabot.{rule_id}",
            scanner="DEPENDABOT",
            severity=severity,
            category=FindingCategory.SCA.value,
            file_path=manifest_path or None,
            cve_ids=[cve_id] if cve_id else [],
            cwe_ids=cwe_ids,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            remediation_guidance="\n".join(remediation_parts),
            scanner_native_id=str(alert.get("number", ghsa_id)),
            raw=alert,
        )
