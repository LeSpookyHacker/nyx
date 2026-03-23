"""
Abstract base for scanner output normalizers.

Each scanner-specific normalizer takes the raw JSON/XML output from that scanner
and produces a list of NormalizedFinding dicts, which are then passed to the
deduplication and prioritization pipeline.
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.constants import FindingCategory, Severity


@dataclass
class NormalizedFinding:
    """Canonical finding representation produced by all normalizers."""
    title: str
    description: str
    rule_id: str
    scanner: str                         # ScannerType value
    severity: str                        # Severity value
    category: str                        # FindingCategory value

    # Location (SAST)
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None

    # Location (DAST)
    url: Optional[str] = None

    # Classification
    cwe_ids: List[str] = field(default_factory=list)
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation_guidance: Optional[str] = None

    # Scoring
    cvss_score: Optional[float] = None
    is_exploitable: bool = False

    # Scanner-native ID for traceability
    scanner_native_id: Optional[str] = None

    # Raw payload for debugging
    raw: Optional[Dict[str, Any]] = None

    def fingerprint(self, repo_id: str) -> str:
        """
        Compute a stable deduplication fingerprint.

        SAST: scanner + rule_id + repo_id + file_path + line_start
        DAST/SCA: scanner + rule_id + repo_id + (url or cve_id)
        """
        if self.file_path:
            key = f"{self.scanner}:{self.rule_id}:{repo_id}:{self.file_path}:{self.line_start or 0}"
        elif self.url:
            # Normalize URL by stripping query params for stability
            base_url = self.url.split("?")[0].rstrip("/")
            key = f"{self.scanner}:{self.rule_id}:{repo_id}:{base_url}"
        elif self.cve_id:
            key = f"{self.scanner}:{self.cve_id}:{repo_id}"
        else:
            key = f"{self.scanner}:{self.rule_id}:{repo_id}"
        return hashlib.sha256(key.encode()).hexdigest()

    def cwe_ids_json(self) -> str:
        return json.dumps(self.cwe_ids)


def map_severity(raw: str, default: str = Severity.MEDIUM.value) -> str:
    """Map various scanner severity strings to Nyx Severity enum values."""
    mapping = {
        # Common
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "moderate": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
        "informational": Severity.INFO.value,
        "note": Severity.INFO.value,
        "warning": Severity.MEDIUM.value,
        "error": Severity.HIGH.value,
        # CVSS numeric
        "none": Severity.INFO.value,
    }
    return mapping.get(raw.lower().strip(), default)


def cvss_to_severity(cvss: float) -> str:
    """Convert a CVSS score (0–10) to a Severity level."""
    if cvss >= 9.0:
        return Severity.CRITICAL.value
    if cvss >= 7.0:
        return Severity.HIGH.value
    if cvss >= 4.0:
        return Severity.MEDIUM.value
    if cvss > 0.0:
        return Severity.LOW.value
    return Severity.INFO.value


class AbstractNormalizer(ABC):
    """All scanner normalizers must implement this interface."""

    @abstractmethod
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        """
        Parse raw scanner output and return a list of NormalizedFinding objects.

        Args:
            raw_output: Parsed JSON from the scanner (dict or list depending on scanner)

        Returns:
            List of NormalizedFinding objects (may be empty if no findings)
        """
        ...
