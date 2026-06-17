"""OWASP ZAP JSON output normalizer.

Export from ZAP with: zap.sh -cmd -quickurl <target> -quickout results.json
Or via ZAP API: /JSON/core/view/alerts/
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.core.constants import FindingCategory
from app.services.normalization.base import AbstractNormalizer, NormalizedFinding, map_severity

logger = logging.getLogger(__name__)

_RISK_MAP = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}


class ZapNormalizer(AbstractNormalizer):
    def normalize(self, raw_output: Dict[str, Any] | List[Any]) -> List[NormalizedFinding]:
        # ZAP output structure varies: may be {"alerts": [...]} or {"site": [{"alerts": [...]}]}
        alerts: List[Dict] = []

        if isinstance(raw_output, list):
            alerts = raw_output
        elif "alerts" in raw_output:
            alerts = raw_output["alerts"]
        elif "site" in raw_output:
            for site in raw_output["site"]:
                alerts.extend(site.get("alerts", []))
        elif "@version" in raw_output:
            # ZAP XML-exported-to-JSON format
            for site in raw_output.get("site", []):
                alerts.extend(site.get("alerts", {}).get("alertitem", []))

        findings: List[NormalizedFinding] = []
        for alert in alerts:
            try:
                findings.append(self._normalize_alert(alert))
            except Exception:
                logger.debug("Normalizer skipped malformed item", exc_info=True)  # SEC-314
                continue
        return findings

    def _normalize_alert(self, alert: Dict[str, Any]) -> NormalizedFinding:
        risk_code = str(alert.get("riskcode", alert.get("risk", "1")))
        severity = _RISK_MAP.get(risk_code.lower(), map_severity(risk_code))

        cwe_raw = str(alert.get("cweid", ""))
        cwe_ids = [f"CWE-{cwe_raw}"] if cwe_raw and cwe_raw != "-1" else []

        alert_id = str(alert.get("pluginid", alert.get("id", "zap.unknown")))
        rule_id = f"zap.{alert_id}"

        description_parts = [
            alert.get("desc", ""),
            f"\n\nEvidence: {alert.get('evidence', '')}" if alert.get("evidence") else "",
            f"\n\nParameter: {alert.get('param', '')}" if alert.get("param") else "",
        ]

        return NormalizedFinding(
            title=alert.get("alert", alert.get("name", "ZAP Finding")),
            description="\n".join(p for p in description_parts if p).strip(),
            rule_id=rule_id,
            scanner="ZAP",
            severity=severity,
            category=FindingCategory.DAST.value,
            url=alert.get("url", alert.get("uri")),
            cwe_ids=cwe_ids,
            owasp_category=alert.get("wascid"),
            remediation_guidance=alert.get("solution", ""),
            scanner_native_id=alert_id,
            raw=alert,
        )
