"""Grype JSON output normalizer (Anchore's vulnerability scanner).

Run with: grype <image> -o json > results.json
         grype dir:. -o json > results.json
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


class GrypeNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        if isinstance(raw_output, list):
            matches = raw_output
        else:
            matches = raw_output.get("matches", [])

        findings: List[NormalizedFinding] = []
        for match in matches:
            try:
                findings.append(self._normalize_match(match))
            except Exception:
                continue
        return findings

    def _normalize_match(self, match: Dict[str, Any]) -> NormalizedFinding:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        # CVSS from vulnerability
        cvss_list = vuln.get("cvss", [])
        cvss_score: float | None = None
        for c in cvss_list:
            score = c.get("metrics", {}).get("baseScore")
            if score is not None:
                cvss_score = float(score)
                break

        severity = (
            cvss_to_severity(cvss_score)
            if cvss_score is not None
            else map_severity(vuln.get("severity", "medium"))
        )

        cwe_ids = vuln.get("cpes", [])[:0]  # Grype doesn't include CWEs directly
        data_sources = vuln.get("dataSource", "")

        fix_versions = vuln.get("fix", {}).get("versions", [])
        fix_state = vuln.get("fix", {}).get("state", "unknown")
        if fix_versions:
            fix_text = f"Fixed in version(s): {', '.join(fix_versions)}"
        elif fix_state == "wont-fix":
            fix_text = "Vendor will not fix this vulnerability."
        else:
            fix_text = "No fix available yet."

        return NormalizedFinding(
            title=f"{vuln.get('id', 'Unknown')} in {artifact.get('name', 'unknown')} {artifact.get('version', '')}",
            description=vuln.get("description", ""),
            rule_id=f"grype.{vuln.get('id', 'unknown')}",
            scanner="GRYPE",
            severity=severity,
            category=FindingCategory.SCA.value,
            cve_id=vuln.get("id") if vuln.get("id", "").startswith("CVE") else None,
            remediation_guidance=fix_text,
            cvss_score=cvss_score,
            scanner_native_id=vuln.get("id"),
            raw=match,
        )
