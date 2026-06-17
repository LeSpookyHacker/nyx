"""Gitleaks secret scanner normalizer.

Export from Gitleaks with:
    gitleaks detect --source . --report-format json --report-path gitleaks.json --exit-code 0
"""
from __future__ import annotations

import logging
from typing import Any, List

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding

logger = logging.getLogger(__name__)


class GitleaksNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Any) -> List[NormalizedFinding]:
        if not isinstance(raw_output, list):
            return []

        findings: List[NormalizedFinding] = []
        for item in raw_output:
            try:
                findings.append(self._normalize_item(item))
            except Exception:
                logger.debug("Normalizer skipped malformed item", exc_info=True)  # SEC-314
                continue
        return findings

    def _normalize_item(self, item: dict) -> NormalizedFinding:
        rule_id = item.get("RuleID", item.get("ruleId", "unknown"))
        file_path = item.get("File", item.get("file", ""))
        start_line = item.get("StartLine", item.get("startLine"))
        commit = item.get("Commit", item.get("commit", ""))
        author = item.get("Author", item.get("author", ""))
        tags = item.get("Tags", item.get("tags", []))
        fingerprint = item.get("Fingerprint", item.get("fingerprint", ""))

        description_parts = [
            f"Gitleaks detected a potential secret matching rule **{rule_id}**.",
        ]
        if commit:
            description_parts.append(f"Commit: `{commit[:12]}`")
        if author:
            description_parts.append(f"Author: {author}")
        if tags:
            description_parts.append(f"Tags: {', '.join(str(t) for t in tags)}")  # SEC-227

        return NormalizedFinding(
            title=f"Secret detected: {rule_id}",
            description="\n".join(description_parts),
            rule_id=f"gitleaks.{rule_id}",
            scanner="GITLEAKS",
            # Leaked secrets are always critical — any exposure is a breach risk
            severity="CRITICAL",
            category=FindingCategory.SECRETS.value,
            file_path=file_path or None,
            line_start=start_line,
            line_end=item.get("EndLine", item.get("endLine", start_line)),
            remediation_guidance=(
                "1. Immediately rotate the exposed credential.\n"
                "2. Remove the secret from git history using `git filter-repo` or BFG Repo Cleaner.\n"
                "3. Audit all systems where the credential had access for unauthorized activity.\n"
                "4. Add the secret pattern to `.gitleaksignore` only after confirming it is a false positive."
            ),
            scanner_native_id=fingerprint or rule_id,
            raw=item,
        )
