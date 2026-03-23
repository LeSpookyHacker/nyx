"""Trivy JSON output normalizer.

Run with: trivy fs --format json --output results.json .
         trivy image --format json --output results.json <image>
         trivy config --format json --output results.json .
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

_CLASS_TO_CATEGORY = {
    "lang-pkgs": FindingCategory.SCA.value,
    "os-pkgs": FindingCategory.SCA.value,
    "config": FindingCategory.IAC.value,
    "secret": FindingCategory.SECRETS.value,
    "vulnerability": FindingCategory.CONTAINER.value,
}


class TrivyNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        if isinstance(raw_output, list):
            # Trivy may output a list of results directly
            results = raw_output
        else:
            results = raw_output.get("Results", [])

        findings: List[NormalizedFinding] = []
        for result in results:
            target = result.get("Target", "")
            result_class = result.get("Class", "")
            result_type = result.get("Type", "")
            category = _CLASS_TO_CATEGORY.get(result_class, FindingCategory.CONTAINER.value)

            # Vulnerabilities (SCA / container)
            for vuln in result.get("Vulnerabilities") or []:
                try:
                    findings.append(self._normalize_vuln(vuln, target, category))
                except Exception:
                    continue

            # Misconfigurations (IaC)
            for misconf in result.get("Misconfigurations") or []:
                try:
                    findings.append(self._normalize_misconf(misconf, target))
                except Exception:
                    continue

            # Secrets
            for secret in result.get("Secrets") or []:
                try:
                    findings.append(self._normalize_secret(secret, target))
                except Exception:
                    continue

        return findings

    def _normalize_vuln(self, v: Dict[str, Any], target: str, category: str) -> NormalizedFinding:
        cvss_data = v.get("CVSS", {})
        cvss_score: float | None = None
        for source in ("nvd", "ghsa", "redhat"):
            if source in cvss_data:
                cvss_score = cvss_data[source].get("V3Score") or cvss_data[source].get("V2Score")
                if cvss_score:
                    break

        severity = cvss_to_severity(float(cvss_score)) if cvss_score else map_severity(v.get("Severity", "medium"))

        fix_version = v.get("FixedVersion", "")
        fix_text = f"Upgrade {v.get('PkgName', '')} to {fix_version}" if fix_version else "No fix available"

        return NormalizedFinding(
            title=f"{v.get('VulnerabilityID', '')} in {v.get('PkgName', target)}",
            description=v.get("Description", ""),
            rule_id=f"trivy.{v.get('VulnerabilityID', 'unknown')}",
            scanner="TRIVY",
            severity=severity,
            category=category,
            file_path=target or None,
            cwe_ids=v.get("CweIDs", []) or [],
            cve_id=v.get("VulnerabilityID") if v.get("VulnerabilityID", "").startswith("CVE") else None,
            remediation_guidance=fix_text,
            cvss_score=cvss_score,
            is_exploitable=bool(v.get("PublishedDate")),  # Has a published date = known
            scanner_native_id=v.get("VulnerabilityID"),
            raw=v,
        )

    def _normalize_misconf(self, m: Dict[str, Any], target: str) -> NormalizedFinding:
        severity = map_severity(m.get("Severity", "medium"))
        return NormalizedFinding(
            title=m.get("Title", "Misconfiguration"),
            description=m.get("Description", ""),
            rule_id=f"trivy.{m.get('ID', 'unknown')}",
            scanner="TRIVY",
            severity=severity,
            category=FindingCategory.IAC.value,
            file_path=target or None,
            line_start=m.get("CauseMetadata", {}).get("StartLine"),
            line_end=m.get("CauseMetadata", {}).get("EndLine"),
            remediation_guidance=m.get("Resolution", ""),
            scanner_native_id=m.get("ID"),
            raw=m,
        )

    def _normalize_secret(self, s: Dict[str, Any], target: str) -> NormalizedFinding:
        return NormalizedFinding(
            title=f"Secret Detected: {s.get('Title', s.get('RuleID', 'Unknown Secret'))}",
            description=f"Secret detected in {target}. Category: {s.get('Category', '')}",
            rule_id=f"trivy.secret.{s.get('RuleID', 'unknown')}",
            scanner="TRIVY",
            severity="HIGH",
            category=FindingCategory.SECRETS.value,
            file_path=target or None,
            line_start=s.get("StartLine"),
            line_end=s.get("EndLine"),
            code_snippet=s.get("Match", "")[:500],
            scanner_native_id=s.get("RuleID"),
            raw=s,
        )
