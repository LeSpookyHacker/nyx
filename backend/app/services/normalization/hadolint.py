"""Hadolint Dockerfile linter normalizer.

Export from Hadolint with:
    hadolint --format json Dockerfile
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding

_LEVEL_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
    "style": "INFO",
}


class HadolintNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Any) -> List[NormalizedFinding]:
        if not isinstance(raw_output, list):
            return []

        findings: List[NormalizedFinding] = []
        for item in raw_output:
            try:
                findings.append(self._normalize_item(item))
            except Exception:
                continue
        return findings

    def _normalize_item(self, item: Dict[str, Any]) -> NormalizedFinding:
        code = item.get("code", "DL0000")
        level = item.get("level", "warning").lower()
        severity = _LEVEL_MAP.get(level, "MEDIUM")

        return NormalizedFinding(
            title=f"Hadolint {code}: {item.get('message', 'Dockerfile issue')}",
            description=item.get("message", ""),
            rule_id=f"hadolint.{code}",
            scanner="HADOLINT",
            severity=severity,
            category=FindingCategory.IAC.value,
            file_path=item.get("file"),
            line_start=item.get("line"),
            line_end=item.get("line"),
            remediation_guidance=(
                f"See https://github.com/hadolint/hadolint/wiki/{code} for remediation guidance."
            ),
            scanner_native_id=code,
            raw=item,
        )
