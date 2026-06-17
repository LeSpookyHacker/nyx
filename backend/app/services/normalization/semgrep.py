"""Semgrep JSON output normalizer.

Run semgrep with: semgrep --json --output results.json
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.core.constants import FindingCategory, Severity
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding, map_severity

# CWE tags that indicate secrets detection
_SECRETS_TAGS = {"secret", "secrets", "credentials", "password", "api-key", "token"}


class SemgrepNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        if isinstance(raw_output, list):
            # Some semgrep versions wrap results differently
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
        meta = r.get("extra", {})
        severity_raw = meta.get("severity", "WARNING")
        message = meta.get("message", r.get("check_id", ""))
        metadata = meta.get("metadata", {})

        # Severity mapping
        sev_map = {
            "ERROR": Severity.HIGH.value,
            "WARNING": Severity.MEDIUM.value,
            "INFO": Severity.INFO.value,
        }
        severity = sev_map.get(severity_raw.upper(), map_severity(severity_raw))

        # Override with metadata severity if present
        if "severity" in metadata:
            severity = map_severity(metadata["severity"], severity)

        # CWE extraction
        cwe_ids: List[str] = []
        cwe_raw = metadata.get("cwe", [])
        if isinstance(cwe_raw, str):
            cwe_ids = [cwe_raw]
        elif isinstance(cwe_raw, list):
            cwe_ids = cwe_raw

        # Category detection
        tags = set(t.lower() for t in metadata.get("tags", []))
        if tags & _SECRETS_TAGS:
            category = FindingCategory.SECRETS.value
        else:
            category = FindingCategory.SAST.value

        # Location
        path = r.get("path", "")
        start = r.get("start", {})
        end = r.get("end", {})
        code_snippet = meta.get("lines", "")

        # OWASP mapping from metadata
        owasp = metadata.get("owasp", None)
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else None

        rule_id = r.get("check_id", "semgrep.unknown")

        return NormalizedFinding(
            title=rule_id.split(".")[-1].replace("-", " ").replace("_", " ").title(),
            description=message,
            rule_id=rule_id,
            scanner="SEMGREP",
            severity=severity,
            category=category,
            file_path=path or None,
            line_start=start.get("line"),
            line_end=end.get("line"),
            code_snippet=(code_snippet if isinstance(code_snippet, str) else str(code_snippet))[:2000] if code_snippet else None,  # SEC-240
            cwe_ids=cwe_ids,
            owasp_category=owasp,
            remediation_guidance=metadata.get("fix-regex") or metadata.get("fix"),
            scanner_native_id=r.get("check_id"),
            cvss_score=None,
            raw=r,
        )
