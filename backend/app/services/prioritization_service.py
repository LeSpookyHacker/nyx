"""
Prioritization Service

Computes a priority_score (0–100) for each finding based on:
  - Severity weight      (35%)
  - CVSS score           (25%)
  - EPSS score           (20%)
  - Exploitability flag  (15%)
  - Age penalty          (5%)  — older OPEN findings drift upward

Higher scores appear first in the dashboard.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

import httpx

from app.config import get_settings
from app.core.constants import Severity
from app.services.normalization.base import NormalizedFinding

settings = get_settings()

_SEVERITY_WEIGHTS = {
    Severity.CRITICAL.value: 1.0,
    Severity.HIGH.value: 0.75,
    Severity.MEDIUM.value: 0.45,
    Severity.LOW.value: 0.15,
    Severity.INFO.value: 0.05,
}


def compute_priority_score(
    finding: NormalizedFinding,
    first_seen_at: datetime | None = None,
) -> float:
    """Return a 0–100 priority score."""
    sev_w = _SEVERITY_WEIGHTS.get(finding.severity, 0.45)

    cvss_norm = 0.0
    if finding.cvss_score is not None:
        cvss_norm = min(finding.cvss_score, 10.0) / 10.0

    epss_norm = 0.0  # Will be enriched asynchronously via enrich_epss()

    exploit_w = 1.0 if finding.is_exploitable else 0.0

    age_w = 0.0
    if first_seen_at:
        days_open = (datetime.now(timezone.utc) - first_seen_at).days
        # Sigmoid-like growth that caps at 1.0 around 180 days
        age_w = 1.0 - math.exp(-days_open / 180)

    score = (
        sev_w * 0.35
        + cvss_norm * 0.25
        + epss_norm * 0.20
        + exploit_w * 0.15
        + age_w * 0.05
    ) * 100

    return round(min(score, 100.0), 2)


def update_priority_score_with_epss(base_score: float, epss_score: float) -> float:
    """Re-compute priority score after EPSS data is available."""
    # We recalculate with the epss term properly filled
    # epss_norm replaces the 0.0 placeholder
    epss_contribution = epss_score * 0.20 * 100
    # The base score was computed without EPSS (i.e., epss term = 0)
    return round(min(base_score + epss_contribution, 100.0), 2)


async def fetch_epss_score(cve_id: str) -> float | None:
    """
    Fetch EPSS score from first.org API.
    Returns None if CVE not found or request fails.
    """
    if not settings.EPSS_API_ENABLED or not cve_id:
        return None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                settings.EPSS_API_BASE_URL,
                params={"cve": cve_id},
            )
            resp.raise_for_status()
            data = resp.json()
            scores = data.get("data", [])
            if scores:
                return float(scores[0].get("epss", 0))
    except Exception:
        pass
    return None
