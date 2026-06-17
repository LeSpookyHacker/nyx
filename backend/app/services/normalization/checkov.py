"""Checkov JSON output normalizer (Bridgecrew IaC scanner).

Run with: checkov -d . -o json > results.json
         checkov --file Dockerfile -o json > results.json
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding

logger = logging.getLogger(__name__)


class CheckovNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []

        # Checkov output can be a list of framework results or a single result
        if isinstance(raw_output, list):
            for result in raw_output:
                findings.extend(self._process_result(result))
        else:
            findings.extend(self._process_result(raw_output))

        return findings

    def _process_result(self, result: Dict[str, Any]) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []
        # check_type indicates framework: terraform, cloudformation, kubernetes, dockerfile, etc.
        check_type = result.get("check_type", "iac")
        failed_checks = result.get("results", {}).get("failed_checks", [])

        for check in failed_checks:
            try:
                findings.append(self._normalize_check(check, check_type))
            except Exception:
                logger.debug("Normalizer skipped malformed item", exc_info=True)  # SEC-314
                continue
        return findings

    def _normalize_check(self, check: Dict[str, Any], check_type: str) -> NormalizedFinding:
        check_id = check.get("check_id", "unknown")
        check_meta = check.get("check", {})

        # Map check type to severity (Checkov doesn't include severity natively for all rules)
        severity = self._infer_severity(check_id, check.get("severity"))

        file_path = check.get("repo_file_path") or check.get("file_path") or check.get("file_abs_path")

        file_line_range = check.get("file_line_range", [None, None])
        line_start = file_line_range[0] if file_line_range else None
        line_end = file_line_range[1] if len(file_line_range) > 1 else line_start

        code_block = check.get("code_block", [])
        snippet = ""
        if code_block:
            snippet = "".join(line[1] for line in code_block if len(line) > 1)[:2000]

        guideline = check.get("guideline") or check_meta.get("guideline", "")

        return NormalizedFinding(
            title=check_meta.get("name") or check.get("check_name", check_id),
            description=f"[{check_id}] {check_meta.get('name', '')} in {check_type.upper()} configuration.",
            rule_id=f"checkov.{check_id}",
            scanner="CHECKOV",
            severity=severity,
            category=FindingCategory.IAC.value,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=snippet or None,
            remediation_guidance=guideline,
            scanner_native_id=check_id,
            raw=check,
        )

    def _infer_severity(self, check_id: str, raw_severity: str | None) -> str:
        if raw_severity and isinstance(raw_severity, str):  # SEC-313: guard against non-string types
            mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "CRITICAL": "CRITICAL"}
            return mapping.get(raw_severity.upper(), "MEDIUM")
        # Heuristic: CKV_AWS_* networking/iam rules are higher priority
        if any(k in check_id for k in ("_IAM_", "_S3_", "_SECRETS", "_KMS")):
            return "HIGH"
        return "MEDIUM"
