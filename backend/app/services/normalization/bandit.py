"""Bandit JSON output normalizer.

Run with: bandit -r . -f json -o results.json
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding, map_severity

_CONFIDENCE_MAP = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}


class BanditNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        if isinstance(raw_output, list):
            results = raw_output
        else:
            results = raw_output.get("results", [])

        findings: List[NormalizedFinding] = []
        for r in results:
            try:
                findings.append(self._normalize_result(r))
            except Exception:
                continue
        return findings

    def _normalize_result(self, r: Dict[str, Any]) -> NormalizedFinding:
        severity = map_severity(r.get("issue_severity", "MEDIUM"))

        # Bandit has issue_confidence too; HIGH confidence + HIGH severity = exploitable
        confidence = r.get("issue_confidence", "LOW")
        is_exploitable = (
            severity in ("HIGH", "CRITICAL") and confidence == "HIGH"
        )

        cwe_raw = r.get("issue_cwe", {})
        cwe_ids: List[str] = []
        if isinstance(cwe_raw, dict):
            cwe_id = cwe_raw.get("id")
            if cwe_id:
                cwe_ids = [f"CWE-{cwe_id}"]
        elif isinstance(cwe_raw, str) and cwe_raw:
            cwe_ids = [cwe_raw]

        test_id = r.get("test_id", "bandit.unknown")

        return NormalizedFinding(
            title=r.get("test_name", test_id).replace("_", " ").title(),
            description=r.get("issue_text", ""),
            rule_id=f"bandit.{test_id}",
            scanner="BANDIT",
            severity=severity,
            category=FindingCategory.SAST.value,
            file_path=r.get("filename"),
            line_start=r.get("line_number"),
            line_end=r.get("line_range", [None])[-1] if r.get("line_range") else r.get("line_number"),
            code_snippet=r.get("code", "")[:2000],
            cwe_ids=cwe_ids,
            remediation_guidance=r.get("more_info", ""),
            is_exploitable=is_exploitable,
            scanner_native_id=test_id,
            raw=r,
        )
