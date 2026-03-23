"""
Scan Worker — processes raw scanner output into normalized, deduplicated findings.

Flow:
  1. Get the NormalizedFindings from the appropriate scanner normalizer
  2. For each: check deduplication
  3. Insert new / update existing findings
  4. Compute priority scores
  5. Update scan stats and repo risk metrics
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import timedelta

from app.core.constants import FindingStatus, ScanStatus, Severity
from app.database import AsyncSessionLocal
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.scan import Scan
from app.services.deduplication_service import find_existing
from app.services.normalization import get_normalizer
from app.services.prioritization_service import compute_priority_score, fetch_epss_score


async def process_scan_results(scan_id: str, raw_data: Dict[str, Any] | List[Any]) -> None:
    """
    Main entry point called from background tasks.
    Processes scanner output and persists findings.
    """
    async with AsyncSessionLocal() as db:
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING.value
        await db.commit()

        try:
            normalizer = get_normalizer(scan.scanner)
            # Snyk webhooks deliver newIssues under a special key
            if isinstance(raw_data, dict) and "_snyk_webhook_issues" in raw_data:
                from app.services.normalization.snyk import SnykNormalizer
                normalized_findings = SnykNormalizer().normalize_webhook_issues(
                    raw_data["_snyk_webhook_issues"]
                )
            else:
                normalized_findings = normalizer.normalize(raw_data)
        except Exception as e:
            scan.status = ScanStatus.FAILED.value
            scan.error_message = f"Normalization failed: {e}"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        new_count = 0
        existing_count = 0

        for nf in normalized_findings:
            try:
                existing, is_new = await find_existing(db, nf, scan.repository_id)

                if is_new:
                    now = datetime.now(timezone.utc)
                    # Compute SLA breach date
                    sev = Severity(nf.severity) if nf.severity in [s.value for s in Severity] else Severity.MEDIUM
                    sla_breach_at = now + timedelta(days=sev.sla_days)

                    finding = Finding(
                        fingerprint=nf.fingerprint(scan.repository_id),
                        repository_id=scan.repository_id,
                        scan_id=scan.id,
                        title=nf.title,
                        description=nf.description,
                        rule_id=nf.rule_id,
                        scanner=nf.scanner,
                        scanner_native_id=nf.scanner_native_id or "",
                        scanner_sources=nf.scanner,
                        category=nf.category,
                        severity=nf.severity,
                        file_path=nf.file_path,
                        line_start=nf.line_start,
                        line_end=nf.line_end,
                        code_snippet=nf.code_snippet,
                        url=nf.url,
                        cwe_ids=nf.cwe_ids_json(),
                        cve_id=nf.cve_id,
                        owasp_category=nf.owasp_category,
                        remediation_guidance=nf.remediation_guidance,
                        cvss_score=nf.cvss_score,
                        is_exploitable=nf.is_exploitable,
                        status=FindingStatus.OPEN.value,
                        first_seen_at=now,
                        last_seen_at=now,
                        sla_breach_at=sla_breach_at,
                        priority_score=compute_priority_score(nf, first_seen_at=now),
                    )
                    db.add(finding)
                    await db.flush()  # Get ID for EPSS enrichment

                    # Async EPSS enrichment for CVE findings
                    if nf.cve_id:
                        epss = await fetch_epss_score(nf.cve_id)
                        if epss is not None:
                            finding.epss_score = epss
                            # Recompute priority with EPSS
                            from app.services.prioritization_service import update_priority_score_with_epss
                            finding.priority_score = update_priority_score_with_epss(
                                finding.priority_score, epss
                            )

                    new_count += 1
                else:
                    # Update last seen and rescan stats
                    now_ts = datetime.now(timezone.utc)
                    existing.last_seen_at = now_ts
                    # If it was suppressed/fixed, keep that status; otherwise keep OPEN
                    if existing.status == FindingStatus.FIXED.value:
                        # Finding reappeared after being fixed — regression!
                        existing.status = FindingStatus.OPEN.value
                        existing.resolved_at = None
                        existing.is_regression = True
                        existing.regression_detected_at = now_ts
                        new_count += 1  # Count as new since it re-appeared

                        # Fire regression notification (best-effort)
                        try:
                            from app.services.notification_service import notify_regression
                            repo_result_local = await db.execute(
                                select(Repository).where(Repository.id == scan.repository_id)
                            )
                            repo_local = repo_result_local.scalar_one_or_none()
                            repo_name = repo_local.github_full_name if repo_local else scan.repository_id
                            import asyncio as _asyncio
                            _asyncio.create_task(notify_regression(
                                existing.id, existing.title, existing.severity, repo_name
                            ))
                        except Exception:
                            pass
                    else:
                        existing_count += 1

                    # Add this scanner to sources if cross-scanner dedup
                    sources = set(existing.scanner_sources.split(","))
                    sources.add(nf.scanner)
                    existing.scanner_sources = ",".join(s for s in sources if s)

            except Exception:
                continue

        # Update scan stats
        scan.status = ScanStatus.COMPLETED.value
        scan.completed_at = datetime.now(timezone.utc)
        scan.finding_count = len(normalized_findings)
        scan.new_finding_count = new_count

        # Update repository risk metrics
        await _update_repo_risk(db, scan.repository_id)

        await db.commit()

        # Complete GitHub Check Run if this was a PR scan
        if scan.check_run_id and scan.git_sha:
            try:
                from app.config import get_settings as _get_settings
                _settings = _get_settings()
                if _settings.GITHUB_CHECK_RUNS_ENABLED:
                    from app.services.github_service import complete_check_run
                    repo_res = await db.execute(
                        select(Repository).where(Repository.id == scan.repository_id)
                    )
                    pr_repo = repo_res.scalar_one_or_none()
                    if pr_repo:
                        # Fetch new findings for annotations
                        new_findings_res = await db.execute(
                            select(Finding).where(
                                Finding.scan_id == scan.id,
                                Finding.file_path.isnot(None),
                            ).limit(50)
                        )
                        new_findings = new_findings_res.scalars().all()
                        _level_map = {"CRITICAL": "failure", "HIGH": "failure",
                                      "MEDIUM": "warning", "LOW": "notice", "INFO": "notice"}
                        annotations = [
                            {
                                "path": f.file_path,
                                "start_line": f.line_start or 1,
                                "end_line": f.line_end or f.line_start or 1,
                                "annotation_level": _level_map.get(f.severity, "notice"),
                                "title": f"[{f.severity}] {f.scanner}",
                                "message": f.title,
                            }
                            for f in new_findings
                            if f.file_path
                        ]
                        critical_high = sum(1 for f in new_findings
                                            if f.severity in ("CRITICAL", "HIGH"))
                        conclusion = "failure" if critical_high > 0 else "success"
                        summary = (
                            f"Nyx found {len(new_findings)} new finding(s) "
                            f"({critical_high} critical/high) via {scan.scanner}."
                        )
                        await complete_check_run(
                            pr_repo.github_full_name,
                            scan.check_run_id,
                            conclusion,
                            summary,
                            annotations,
                        )
            except Exception:
                pass


async def _update_repo_risk(db: AsyncSession, repo_id: str) -> None:
    """Recompute and cache risk metrics on the Repository record."""
    from sqlalchemy import func

    repo_result = await db.execute(select(Repository).where(Repository.id == repo_id))
    repo = repo_result.scalar_one_or_none()
    if not repo:
        return

    # Count open findings by severity
    for sev in Severity:
        result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.repository_id == repo_id,
                Finding.severity == sev.value,
                Finding.status == FindingStatus.OPEN.value,
            )
        )
        count = result.scalar_one()
        setattr(repo, f"open_{sev.value.lower()}", count)

    # Compute composite risk score (weighted average of open finding severities)
    weights = {
        Severity.CRITICAL.value: 100,
        Severity.HIGH.value: 40,
        Severity.MEDIUM.value: 10,
        Severity.LOW.value: 2,
        Severity.INFO.value: 0,
    }
    score = (
        repo.open_critical * weights["CRITICAL"]
        + repo.open_high * weights["HIGH"]
        + repo.open_medium * weights["MEDIUM"]
        + repo.open_low * weights["LOW"]
    )
    repo.risk_score = min(score / 10, 100.0)  # Normalize to 0-100
    repo.last_scan_at = datetime.now(timezone.utc)
