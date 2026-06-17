"""GitHub Code Scanning API alert normalizer.

GitHub Code Scanning returns alerts from tools like CodeQL, Semgrep (via Actions),
and any SARIF-compliant tool. This normalizer maps the alert JSON to NormalizedFinding.

API reference: GET /repos/{owner}/{repo}/code-scanning/alerts
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "error": "HIGH",
    "medium": "MEDIUM",
    "warning": "MEDIUM",
    "low": "LOW",
    "note": "LOW",
    "none": "INFO",
}

# GitHub Code Scanning security-severity overrides rule.severity
_SECURITY_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class CodeScanningNormalizer(AbstractNormalizer):
    """
    Normalizes the list of alert objects returned by the GitHub Code Scanning API.

    raw_output is either:
      - A list of alert dicts (direct API response)
      - A dict with key "alerts" containing the list (for internal use by the sync service)
    """

    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        if isinstance(raw_output, list):
            alerts = raw_output
        else:
            alerts = raw_output.get("alerts", [])

        findings: List[NormalizedFinding] = []
        for alert in alerts:
            # Skip dismissed alerts
            if alert.get("state") in ("dismissed", "fixed"):
                continue
            try:
                findings.append(self._normalize_alert(alert))
            except Exception:
                logger.debug("Normalizer skipped malformed item", exc_info=True)  # SEC-314
                continue
        return findings

    def _normalize_alert(self, alert: Dict[str, Any]) -> NormalizedFinding:
        rule = alert.get("rule", {})
        instance = alert.get("most_recent_instance", {})
        location = instance.get("location", {})
        tool_name = alert.get("tool", {}).get("name", "CODE_SCANNING")

        # Severity: prefer security_severity over severity
        sec_sev = (rule.get("security_severity") or "").lower()
        raw_sev = (rule.get("severity") or "warning").lower()
        severity = (
            _SECURITY_SEVERITY_MAP.get(sec_sev)
            or _SEVERITY_MAP.get(raw_sev)
            or "MEDIUM"
        )

        description = (
            instance.get("message", {}).get("text")
            or rule.get("description")
            or rule.get("name", "")
        )

        rule_id = rule.get("id", "unknown")
        title = rule.get("name") or rule_id.replace("/", " ").replace("-", " ").title()

        # Tags → category
        tags = set(t.lower() for t in (rule.get("tags") or []))
        if "security" in tags:
            category = FindingCategory.SAST.value
        else:
            category = FindingCategory.SAST.value  # Code Scanning is always SAST

        return NormalizedFinding(
            title=f"[{tool_name}] {title}",
            description=description,
            rule_id=f"code_scanning.{rule_id}",
            scanner="CODE_SCANNING",
            severity=severity,
            category=category,
            file_path=location.get("path") or None,
            line_start=location.get("start_line"),
            line_end=location.get("end_line"),
            cwe_ids=[],  # Not exposed in the alerts API (available in SARIF upload)
            remediation_guidance=rule.get("description"),
            scanner_native_id=str(alert.get("number", "")),
            raw=alert,
        )
