"""Snyk JSON output normalizer.

Run with: snyk test --json > results.json
         snyk container test <image> --json > results.json
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.core.constants import FindingCategory
from app.services.normalization.base import (
    AbstractNormalizer,
    NormalizedFinding,
    cvss_to_severity,
    map_severity,
)


class SnykNormalizer(AbstractNormalizer):
    def normalize_webhook_issues(self, issues: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize the `newIssues` array from a Snyk webhook payload."""
        findings: List[NormalizedFinding] = []
        for issue in issues:
            if issue.get("isIgnored") or issue.get("isPatched"):
                continue
            try:
                findings.append(self._normalize_webhook_issue(issue))
            except Exception:
                continue
        return findings

    def _normalize_webhook_issue(self, issue: Dict[str, Any]) -> NormalizedFinding:
        data = issue.get("issueData", {})
        cvss = data.get("cvssScore")
        if cvss is not None:
            try:
                cvss = float(cvss)
                severity = cvss_to_severity(cvss)
            except (ValueError, TypeError):
                severity = map_severity(data.get("severity", "medium"))
                cvss = None
        else:
            severity = map_severity(data.get("severity", "medium"))

        identifiers = data.get("identifiers", {})
        cwe_ids = identifiers.get("CWE", [])
        cve_id = (identifiers.get("CVE") or [None])[0]

        exploit = data.get("exploitMaturity", "No Known Exploit")
        # SEC-109: guard against non-string scanner data before calling .lower()
        exploit_str = exploit if isinstance(exploit, str) else "No Known Exploit"
        is_exploitable = exploit_str.lower() not in ("no known exploit", "unproven", "not defined")

        fix_in = data.get("fixedIn", [])
        pkg = issue.get("pkgName", "")
        # SEC-109: coerce elements to str to prevent TypeError if scanner sends non-string versions
        fix_in_strs = [str(v) for v in fix_in] if isinstance(fix_in, list) else []
        remediation = f"Upgrade {pkg} to {', '.join(fix_in_strs)}" if fix_in_strs else data.get("description", "")

        return NormalizedFinding(
            title=data.get("title", issue.get("id", "Snyk Vulnerability")),
            description=data.get("description", ""),
            rule_id=f"snyk.{data.get('id', issue.get('id', 'unknown'))}",
            scanner="SNYK",
            severity=severity,
            category=FindingCategory.SCA.value,
            cwe_ids=cwe_ids,
            cve_id=cve_id,
            remediation_guidance=remediation,
            cvss_score=cvss,
            is_exploitable=is_exploitable,
            scanner_native_id=data.get("id") or issue.get("id"),
            raw=issue,
        )

    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        # Snyk can return a list (multi-project) or single object
        if isinstance(raw_output, list):
            results = raw_output
        else:
            results = [raw_output]

        findings: List[NormalizedFinding] = []
        for result in results:
            if result.get("ok", True) is True and not result.get("vulnerabilities"):
                continue
            for vuln in result.get("vulnerabilities", []):
                try:
                    findings.append(self._normalize_vuln(vuln))
                except Exception:
                    continue
        return findings

    def _normalize_vuln(self, v: Dict[str, Any]) -> NormalizedFinding:
        cvss = v.get("cvssScore") or v.get("CVSSv3Score")
        if cvss is not None:
            try:
                cvss = float(cvss)
                severity = cvss_to_severity(cvss)
            except (ValueError, TypeError):
                severity = map_severity(v.get("severity", "medium"))
                cvss = None
        else:
            severity = map_severity(v.get("severity", "medium"))

        cwe_ids = v.get("identifiers", {}).get("CWE", [])
        cve_id = None
        cves = v.get("identifiers", {}).get("CVE", [])
        if cves:
            cve_id = cves[0]

        fix_info = v.get("fixedIn", [])
        fix_text = f"Upgrade to {', '.join(str(item) for item in fix_info)}" if fix_info else ""  # SEC-228
        description = v.get("description", "") or v.get("title", "")

        return NormalizedFinding(
            title=v.get("title", "Snyk Vulnerability"),
            description=description,
            rule_id=f"snyk.{v.get('id', 'unknown')}",
            scanner="SNYK",
            severity=severity,
            category=FindingCategory.SCA.value,
            cwe_ids=cwe_ids,
            cve_id=cve_id,
            remediation_guidance=fix_text or v.get("upgradePath", [None])[0],
            cvss_score=cvss,
            is_exploitable=v.get("isExploitable", False) or v.get("exploit", "Not Defined") not in ("Not Defined", "Unproven"),
            scanner_native_id=v.get("id"),
            raw=v,
        )
