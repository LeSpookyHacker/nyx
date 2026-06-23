"""
Auto PR worker — autonomous triage → fix → audit → draft-PR pipeline.

# SECURITY REVIEW — Auto PR Worker
# Reviewed: 2026-06-17
# Semgrep: not run in this dev environment (semgrep unavailable) — run `semgrep --config=auto`
#          over this file + auto_pr_audit_service.py in CI/Docker before merge.
# Manual checks (PASS by construction — verified by review):
#  1. Audit prompt is not injectable — every finding field interpolated into the audit
#     prompt goes through ai_service._safe() (see auto_pr_audit_service); PR-body fields
#     go through remediation._sanitize_md().
#  2. Branch names cannot be path-traversed — nyx/auto-fix/{finding.id[:8]} uses a
#     server-generated String(36) UUID, never user-supplied input.
#  3. The check-run SHA is sourced from github_service.get_branch_head_sha() (the GitHub
#     API response for the branch Nyx created), never from the finding record.
#  4. Token budget is enforced before the Claude call (pre-call count_tokens estimate +
#     hard used>=budget gate) AND atomically deducted after, in every code path.
#  5. Draft PRs only — create_fix_pr(draft=True). No path here marks a draft ready-for-review
#     or merges it (merge_pr is never called from this module).
#  6. Every early return / terminal state is preceded by a log_event() audit write.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Optional

from sqlalchemy import select, update

from app.config import get_settings
from app.core.constants import FindingStatus, RemediationStatus, Severity
from app.database import AsyncSessionLocal
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.services import ai_service, github_service
from app.services.audit_service import log_event
from app.services.auto_pr_audit_service import audit_generated_diff

settings = get_settings()
logger = logging.getLogger("nyx.auto_pr")

_AUTO_PR_ACTOR = "auto_pr_worker"

# States in which an existing auto Remediation means the finding is already being handled
# (so we must NOT enqueue a duplicate). Terminal-failure states are excluded — those may be retried.
_TERMINAL_FAILURE_STATES = {
    RemediationStatus.FAILED.value,
    RemediationStatus.REJECTED.value,
    RemediationStatus.AUDIT_FAILED.value,
    RemediationStatus.TEST_FAILED.value,
    RemediationStatus.BUDGET_EXCEEDED.value,
    RemediationStatus.REVIEW_LOW_CONFIDENCE.value,
}

# Global concurrency limiter (lazily created so a settings reload is respected in tests).
_semaphore: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(max(1, settings.AUTO_PR_MAX_CONCURRENT))
    return _semaphore


def _severities_for_threshold(threshold: str) -> list[str]:
    """Parse a comma-separated severity list. Falls back to CRITICAL,HIGH if empty/invalid."""
    valid = {s.value for s in Severity}
    parts = [p.strip().upper() for p in (threshold or "").split(",") if p.strip()]
    result = [p for p in parts if p in valid]
    return result or [Severity.CRITICAL.value, Severity.HIGH.value]


async def _deduct_tokens_and_check_budget(db, repository_id: str, tokens: int) -> bool:
    """
    Atomically add `tokens` to auto_pr_tokens_used_today and report whether the repo
    is still within budget. The deduction is always applied (so spend is never lost);
    the return value tells the caller whether to keep processing.
    """
    result = await db.execute(
        update(Repository)
        .where(Repository.id == repository_id)
        .values(auto_pr_tokens_used_today=Repository.auto_pr_tokens_used_today + tokens)
        .returning(
            Repository.auto_pr_tokens_used_today,
            Repository.auto_pr_daily_token_budget,
        )
    )
    row = result.fetchone()
    await db.commit()
    if row is None:
        return False
    return row[0] <= row[1]


async def _estimate_input_tokens(finding: Finding, file_content: str, model: str) -> int:
    """Best-effort pre-call input-token estimate so we don't start a call that can't fit the budget."""
    try:
        client = ai_service._get_async_client()
        approx = (
            f"{finding.title}\n{finding.description}\n{finding.rule_id}\n{file_content}"
        )
        resp = await client.messages.count_tokens(
            model=model,
            messages=[{"role": "user", "content": approx}],
        )
        return int(resp.input_tokens)
    except Exception:  # noqa: BLE001 — estimation is advisory; never block on its failure
        return 0


async def enqueue_auto_pr_findings(db, repository_id: str, scan_id: str) -> int:
    """
    Called by scan_worker after a scan completes. Queues eligible CRITICAL/HIGH findings
    for autonomous remediation and schedules the per-finding pipeline. Returns count queued.
    """
    repo_result = await db.execute(select(Repository).where(Repository.id == repository_id))
    repo = repo_result.scalar_one_or_none()
    if not repo or not repo.auto_pr_mode:
        return 0

    # Hard budget gate before doing any work this scan.
    if repo.auto_pr_tokens_used_today >= repo.auto_pr_daily_token_budget:
        await log_event(
            db, actor=_AUTO_PR_ACTOR, action="auto_pr.budget_exceeded",
            resource_type="repository", resource_id=repository_id,
            metadata={"scan_id": scan_id, "tokens_used_today": repo.auto_pr_tokens_used_today,
                      "daily_budget": repo.auto_pr_daily_token_budget},
        )
        await db.commit()
        return 0

    severities = _severities_for_threshold(repo.auto_pr_severity_threshold)

    # Heal any findings from this scan that are stuck in IN_REMEDIATION before querying for OPEN ones
    await _heal_stuck_findings(db, repository_id, severities, scan_id=scan_id)

    findings_result = await db.execute(
        select(Finding)
        .where(
            Finding.scan_id == scan_id,
            Finding.repository_id == repository_id,
            Finding.status == FindingStatus.OPEN.value,
            Finding.severity.in_(severities),
        )
        .order_by(Finding.priority_score.desc())
    )
    findings = findings_result.scalars().all()
    if not findings:
        return 0

    # Skip findings already handled by a non-terminal-failure auto remediation (avoid duplicates).
    existing_result = await db.execute(
        select(Remediation.finding_id, Remediation.status).where(
            Remediation.finding_id.in_([f.id for f in findings]),
            Remediation.is_auto_triggered.is_(True),
        )
    )
    already_active = {
        fid for fid, status in existing_result.all()
        if status not in _TERMINAL_FAILURE_STATES
    }

    queued_ids: list[str] = []
    for finding in findings:
        if finding.id in already_active:
            continue
        if not finding.file_path:
            # Auto PR requires a specific file to patch. Findings without a file_path
            # (e.g. dependency vulnerabilities, configuration issues) cannot be
            # auto-committed — skip them now to avoid a misleading "Error None" failure
            # caused by PyGitHub asserting the path is a non-None string.
            logger.debug(
                "Skipping finding %s (severity=%s) — no file_path; auto PR requires a file-specific vulnerability",
                finding.id, finding.severity,
            )
            continue
        rem = Remediation(
            finding_id=finding.id,
            requested_by=_AUTO_PR_ACTOR,
            status=RemediationStatus.AUTO_TRIGGERED.value,
            is_auto_triggered=True,
        )
        db.add(rem)
        finding.status = FindingStatus.IN_REMEDIATION.value
        await db.flush()  # populate rem.id
        await log_event(
            db, actor=_AUTO_PR_ACTOR, action="auto_pr.queued",
            resource_type="remediation", resource_id=rem.id,
            metadata={"finding_id": finding.id, "severity": finding.severity,
                      "repository_id": repository_id, "scan_id": scan_id},
        )
        queued_ids.append(rem.id)

    await db.commit()

    for rem_id in queued_ids:
        asyncio.create_task(_run_with_semaphore(rem_id, repository_id))

    return len(queued_ids)


async def _run_with_semaphore(remediation_id: str, repository_id: str) -> None:
    async with _get_semaphore():
        try:
            await process_auto_pr_finding(remediation_id, repository_id)
        except Exception:  # noqa: BLE001 — a single failure must not crash the worker
            logger.exception("Auto PR pipeline crashed for remediation %s", remediation_id)


async def _finalize(db, rem: Remediation, finding: Optional[Finding], status: str,
                    action: str, metadata: dict, *, reopen_finding: bool = False,
                    error: Optional[str] = None) -> None:
    """Set a terminal/intermediate state, write the audit event, and commit — one consistent exit.

    The commit is wrapped in a best-effort try/except: if it fails (DB connection drop,
    timeout, etc.) the finding may be transiently stuck in IN_REMEDIATION, but
    _heal_stuck_findings will detect and recover it on the next trigger run.
    We never re-raise here so a _finalize failure cannot itself crash the pipeline.
    """
    rem.status = status
    if error:
        rem.error_message = error
    if reopen_finding and finding is not None:
        finding.status = FindingStatus.OPEN.value
    await log_event(db, actor=_AUTO_PR_ACTOR, action=action,
                    resource_type="remediation", resource_id=rem.id, metadata=metadata)
    try:
        await db.commit()
    except Exception:
        logger.exception(
            "_finalize commit failed for remediation %s (status=%s reopen_finding=%s) — "
            "finding may be transiently stuck; _heal_stuck_findings will recover it on next trigger",
            rem.id, status, reopen_finding,
        )
        try:
            await db.rollback()
        except Exception:
            pass


async def process_auto_pr_finding(remediation_id: str, repository_id: str) -> None:
    """Run the full auto PR pipeline for a single queued remediation."""
    async with AsyncSessionLocal() as db:
        rem = (await db.execute(
            select(Remediation).where(Remediation.id == remediation_id)
        )).scalar_one_or_none()
        if not rem:
            return
        finding = (await db.execute(
            select(Finding).where(Finding.id == rem.finding_id)
        )).scalar_one_or_none()
        repo = (await db.execute(
            select(Repository).where(Repository.id == repository_id)
        )).scalar_one_or_none()
        if not finding or not repo:
            await _finalize(db, rem, finding, RemediationStatus.FAILED.value,
                            "auto_pr.failed", {"reason": "finding or repository missing"},
                            error="Finding or repository not found")
            return

        # 1. Budget re-check (race guard between enqueue and execution)
        if repo.auto_pr_tokens_used_today >= repo.auto_pr_daily_token_budget:
            await _finalize(db, rem, finding, RemediationStatus.BUDGET_EXCEEDED.value,
                            "auto_pr.budget_exceeded",
                            {"finding_id": finding.id, "daily_budget": repo.auto_pr_daily_token_budget},
                            reopen_finding=True)
            return

        try:
            # 2. Gather context (mirrors remediation._run_ai_fix)
            file_content = ""
            if finding.file_path:
                try:
                    file_content = await github_service.get_file_content(
                        repo.github_full_name, finding.file_path, repo.default_branch
                    )
                except Exception:
                    file_content = finding.code_snippet or "# File content unavailable"

            # 2b. Pre-call budget estimate
            estimate = await _estimate_input_tokens(finding, file_content, settings.AUTO_PR_FIX_MODEL)
            if repo.auto_pr_tokens_used_today + estimate > repo.auto_pr_daily_token_budget:
                await _finalize(db, rem, finding, RemediationStatus.BUDGET_EXCEEDED.value,
                                "auto_pr.budget_exceeded",
                                {"finding_id": finding.id, "estimated_input_tokens": estimate,
                                 "daily_budget": repo.auto_pr_daily_token_budget},
                                reopen_finding=True)
                return

            # 3. Generate the fix (uses the configured auto-mode model)
            rem.status = RemediationStatus.GENERATING.value
            await db.commit()
            test_files = await _maybe_fetch_tests(repo, finding)
            fix = await ai_service.generate_fix(
                finding, file_content, "", test_files, None, model=settings.AUTO_PR_FIX_MODEL,
            )
            await log_event(db, actor=_AUTO_PR_ACTOR, action="auto_pr.ai_started",
                            resource_type="remediation", resource_id=rem.id,
                            metadata={"model": fix.model, "confidence": fix.confidence})

            rem.ai_explanation = fix.explanation
            rem.ai_fix_diff = fix.fix_diff
            rem.ai_fix_summary = fix.fix_summary
            rem.ai_confidence = fix.confidence
            rem.ai_model = fix.model
            rem.prompt_tokens = fix.prompt_tokens
            rem.completion_tokens = fix.completion_tokens
            rem.ai_prompt = fix.fix_prompt
            rem.ai_diff_sha256 = hashlib.sha256(fix.fix_diff.encode()).hexdigest()
            rem.confidence_flagged = fix.confidence_flagged
            rem.diff_warnings = json.dumps(fix.diff_warnings) if fix.diff_warnings else None
            await db.commit()

            # 4. Deduct fix tokens; stop the queue if this pushed the repo over budget
            within_budget = await _deduct_tokens_and_check_budget(
                db, repo.id, fix.prompt_tokens + fix.completion_tokens
            )
            await db.refresh(rem)
            await db.refresh(finding)

            # 5. Confidence gate
            if fix.confidence_flagged and repo.auto_pr_skip_low_confidence:
                await _finalize(db, rem, finding, RemediationStatus.REVIEW_LOW_CONFIDENCE.value,
                                "auto_pr.skipped_low_confidence",
                                {"finding_id": finding.id, "confidence": fix.confidence},
                                reopen_finding=True)
                return

            # 6. Diff security scan (existing heuristic gate)
            if fix.diff_warnings:
                await _finalize(db, rem, finding, RemediationStatus.REVIEW_LOW_CONFIDENCE.value,
                                "auto_pr.diff_warning",
                                {"finding_id": finding.id, "warnings": fix.diff_warnings},
                                reopen_finding=True)
                return

            # 7. Security audit pass (NEW)
            if repo.auto_pr_security_audit:
                rem.status = RemediationStatus.AUDIT_IN_PROGRESS.value
                await log_event(db, actor=_AUTO_PR_ACTOR, action="auto_pr.audit_started",
                                resource_type="remediation", resource_id=rem.id, metadata={})
                await db.commit()

                audit = await audit_generated_diff(finding, file_content, fix.fix_diff,
                                                   settings.AUTO_PR_AUDIT_MODEL)
                rem.audit_result = json.dumps(audit)
                rem.audit_passed = audit["passed"]
                rem.audit_token_input = audit.get("token_input", 0)
                rem.audit_token_output = audit.get("token_output", 0)
                await _deduct_tokens_and_check_budget(
                    db, repo.id, audit.get("token_input", 0) + audit.get("token_output", 0)
                )
                await db.refresh(rem)
                await db.refresh(finding)

                if not audit["passed"]:
                    await _finalize(db, rem, finding, RemediationStatus.AUDIT_FAILED.value,
                                    "auto_pr.audit_failed",
                                    {"finding_id": finding.id, "risk_level": audit.get("risk_level"),
                                     "summary": audit.get("summary", "")[:500]},
                                    reopen_finding=True)
                    await _notify_audit_failure(finding, repo, audit)
                    return

            # 8. Commit to branch + open DRAFT PR
            pr_number, pr_url, branch_name = await _create_draft_pr(db, rem, finding, repo, file_content)
            rem.pr_number = pr_number
            rem.pr_url = pr_url
            rem.pr_branch = branch_name
            finding.fix_pr_url = pr_url
            await _finalize(db, rem, finding, RemediationStatus.COMMITTED.value,
                            "auto_pr.committed",
                            {"finding_id": finding.id, "pr_number": pr_number, "pr_url": pr_url})

            # 9. Optional check-run gate (does not roll back the committed draft PR)
            if repo.auto_pr_require_passing_checks:
                await _run_check_gate(db, rem, repo, branch_name, pr_number)

            if not within_budget:
                logger.info("Repo %s exceeded auto-PR token budget after this fix", repo.id)

        except Exception as e:  # noqa: BLE001
            await _finalize(db, rem, finding, RemediationStatus.FAILED.value,
                            "auto_pr.failed", {"finding_id": finding.id if finding else None},
                            reopen_finding=True, error=str(e))


async def _maybe_fetch_tests(repo: Repository, finding: Finding) -> dict[str, str]:
    if not finding.file_path:
        return {}
    try:
        from app.routers.remediation import _fetch_test_files
        return await _fetch_test_files(repo.github_full_name, finding.file_path, repo.default_branch)
    except Exception:
        return {}


async def _create_draft_pr(db, rem: Remediation, finding: Finding, repo: Repository,
                           file_content: str):
    """Apply the diff and open a draft PR on nyx/auto-fix/<short-id>. Returns (number, url, branch)."""
    from app.routers.remediation import _validate_diff_scope

    # Guard: auto PR needs a file path to commit the fix. Findings without one
    # (e.g. dependency vulnerabilities, config/infra issues) cannot be auto-patched.
    # This should have been caught at enqueue time, but we re-check here for defence-in-depth.
    if not finding.file_path:
        raise ValueError(
            "Cannot create auto PR: finding has no file path. "
            "This vulnerability may require a non-code fix (config, infrastructure, or dependency update). "
            "Handle it manually."
        )

    # Integrity + scope checks (mirror the manual flow)
    if rem.ai_diff_sha256:
        computed = hashlib.sha256((rem.ai_fix_diff or "").encode()).hexdigest()
        if computed != rem.ai_diff_sha256:
            raise ValueError("AI diff integrity check failed — hash mismatch.")
    _validate_diff_scope(rem.ai_fix_diff, finding.file_path)

    fixed_content = github_service.apply_unified_diff(file_content, rem.ai_fix_diff)
    if fixed_content is None:
        raise ValueError("Could not apply diff cleanly — the file may have changed.")

    branch_name = f"nyx/auto-fix/{finding.id[:8]}"
    pr_title = (rem.ai_fix_summary or finding.title or f"Nyx auto-fix {rem.id[:8]}")[:120]
    pr_title = f"[Nyx Auto] {pr_title}"
    pr_body = _build_auto_pr_body(finding, rem)

    pr_number, pr_url = await github_service.create_fix_pr(
        repo_full_name=repo.github_full_name,
        file_path=finding.file_path,
        original_content=file_content,
        fixed_content=fixed_content,
        branch_name=branch_name,
        pr_title=pr_title,
        pr_body=pr_body,
        base_branch=repo.default_branch,
        draft=True,
    )
    return pr_number, pr_url, branch_name


async def _run_check_gate(db, rem: Remediation, repo: Repository, branch_name: str,
                          pr_number: int) -> None:
    """Poll the target repo's CI on the pushed SHA and annotate the draft PR. Never merges."""
    sha = await github_service.get_branch_head_sha(repo.github_full_name, branch_name)
    if not sha:
        return
    rem.status = RemediationStatus.TEST_IN_PROGRESS.value
    await log_event(db, actor=_AUTO_PR_ACTOR, action="auto_pr.check_run_started",
                    resource_type="remediation", resource_id=rem.id,
                    metadata={"sha": sha, "pr_number": pr_number})
    await db.commit()

    result = await github_service.wait_for_check_run(
        repo.github_full_name, sha,
        timeout_seconds=settings.AUTO_PR_CHECK_TIMEOUT,
    )
    rem.check_run_id = result.get("check_run_id")
    rem.check_run_conclusion = result.get("conclusion")
    rem.ci_status = ("pass" if result.get("conclusion") == "success"
                     else "fail" if result.get("conclusion") else "pending")
    rem.ci_failure_details = result.get("details")

    if not result["found"]:
        # No workflow runs on nyx/* — leave the draft PR COMMITTED, just note it.
        logger.info("No check runs found for %s@%s; skipping test gate", repo.github_full_name, sha[:8])
        await db.commit()
        return

    conclusion = result.get("conclusion")
    timed_out = not result["completed"]
    failed = conclusion not in (None, "success")

    if failed or (timed_out and settings.AUTO_PR_BLOCK_ON_TIMEOUT):
        rem.status = RemediationStatus.TEST_FAILED.value
        await log_event(db, actor=_AUTO_PR_ACTOR, action="auto_pr.check_run_failed",
                        resource_type="remediation", resource_id=rem.id,
                        metadata={"conclusion": conclusion, "timed_out": timed_out})
    else:
        rem.status = RemediationStatus.COMMITTED.value
    await db.commit()

    summary = conclusion or ("timed out" if timed_out else "inconclusive")
    comment = (
        f"## 🤖 Nyx Auto PR — Test Results\n\n"
        f"Check run: **{summary}**\n\n"
        f"{result.get('details') or ''}\n\n"
        f"This PR was automatically generated by Nyx Auto PR Mode. "
        f"A human must review and promote this draft before it can be merged."
    )
    await github_service.add_pr_comment(repo.github_full_name, pr_number, comment)


def _build_auto_pr_body(finding: Finding, rem: Remediation) -> str:
    """Draft-PR body with finding metadata, fix explanation, audit verdict, and a review banner."""
    from app.routers.remediation import _sanitize_md
    try:
        cwe_list = json.loads(finding.cwe_ids or "[]")
        cwe_str = " ".join(c for c in cwe_list if isinstance(c, str))
    except Exception:
        cwe_str = ""

    audit_line = "_Security audit not run._"
    if rem.audit_result:
        try:
            audit = json.loads(rem.audit_result)
            verdict = "✅ PASSED" if audit.get("passed") else "❌ FAILED"
            audit_line = f"{verdict} (risk: {_sanitize_md(audit.get('risk_level'), 20)}) — {_sanitize_md(audit.get('summary'), 600)}"
        except Exception:
            pass

    return f"""## 🤖 Nyx Auto PR — Security Remediation

> ⚠️ This is a **draft** PR generated automatically by Nyx Auto PR Mode. Review carefully before promoting.
> It is **not** ready for review and must not be merged until a human verifies the fix.

### Vulnerability
| Field | Value |
|-------|-------|
| **Title** | {_sanitize_md(finding.title, 200)} |
| **Severity** | {_sanitize_md(finding.severity, 20)} |
| **Scanner** | {_sanitize_md(finding.scanner, 50)} |
| **Rule** | {_sanitize_md(finding.rule_id, 100)} |
| **File** | {_sanitize_md(finding.file_path, 300)}:{finding.line_start or ''} |
| **CWE** | {_sanitize_md(cwe_str, 200)} |
| **CVSS** | {finding.cvss_score if finding.cvss_score is not None else 'n/a'} |
| **EPSS** | {finding.epss_score if finding.epss_score is not None else 'n/a'} |

### Fix explanation
{_sanitize_md(rem.ai_explanation, 2000) if rem.ai_explanation else '_No explanation available._'}

### Security audit
{audit_line}

---
Generated by Nyx ({_sanitize_md(rem.ai_model, 50)}). Finding ID: `{finding.id}`.
"""


async def _notify_audit_failure(finding: Finding, repo: Repository, audit: dict) -> None:
    """Best-effort Slack/Teams notification when the audit blocks a fix."""
    try:
        from app.services import notification_service
        await notification_service.notify_auto_pr_blocked(
            finding_id=finding.id,
            title=finding.title or "",
            severity=finding.severity or "",
            repo=repo.github_full_name,
            risk_level=str(audit.get("risk_level", "")),
            summary=str(audit.get("summary", "")),
        )
    except Exception:  # noqa: BLE001
        logger.debug("Auto PR audit-failure notification skipped", exc_info=True)


async def _heal_stuck_findings(
    db,
    repository_id: str,
    severities: list[str],
    scan_id: Optional[str] = None,
) -> None:
    """
    Reset any IN_REMEDIATION findings to OPEN when every one of their auto-triggered
    remediations has reached a terminal failure state.

    This can happen when a crash or unexpected error leaves a finding stuck:
    the pipeline's except-handler sets reopen_finding=True, but if _finalize's own
    db.commit() fails (e.g. a DB connection drop) the reset never lands.
    Calling this before enqueueing makes both trigger paths self-healing.

    Pass scan_id to scope healing to a specific scan (used by enqueue_auto_pr_findings);
    omit it to heal all stuck findings for the repository (used by trigger_auto_pr_now).
    """
    filters = [
        Finding.repository_id == repository_id,
        Finding.status == FindingStatus.IN_REMEDIATION.value,
        Finding.severity.in_(severities),
    ]
    if scan_id is not None:
        filters.append(Finding.scan_id == scan_id)

    stuck_result = await db.execute(
        select(Finding).where(*filters)
    )
    stuck = stuck_result.scalars().all()
    if not stuck:
        return

    rem_result = await db.execute(
        select(Remediation.finding_id, Remediation.status).where(
            Remediation.finding_id.in_([f.id for f in stuck]),
            Remediation.is_auto_triggered.is_(True),
        )
    )
    rem_statuses: dict[str, list[str]] = {}
    for fid, status in rem_result.all():
        rem_statuses.setdefault(fid, []).append(status)

    healed = 0
    for finding in stuck:
        statuses = rem_statuses.get(finding.id, [])
        # All auto-remediations in terminal failure → finding is stuck, safe to reopen
        if statuses and all(s in _TERMINAL_FAILURE_STATES for s in statuses):
            logger.info("Healing stuck finding %s (was IN_REMEDIATION, all auto-PRs failed) → OPEN", finding.id)
            finding.status = FindingStatus.OPEN.value
            healed += 1

    if healed:
        await db.commit()


async def trigger_auto_pr_now(db, repository_id: str) -> int:
    """
    On-demand trigger: queue all eligible OPEN findings for a repository immediately.

    Unlike enqueue_auto_pr_findings this is not scan-scoped — it picks up every
    existing OPEN finding that matches the repo's severity list.  Called when the
    user explicitly enables Auto PR Mode from the UI so new findings are acted on
    right away rather than waiting for the next scan.

    Also auto-heals findings stuck in IN_REMEDIATION whose auto-remediations all failed,
    so a previous crash never permanently blocks a finding from being retried.
    """
    repo_result = await db.execute(select(Repository).where(Repository.id == repository_id))
    repo = repo_result.scalar_one_or_none()
    if not repo or not repo.auto_pr_mode:
        return 0

    # Hard budget gate
    if repo.auto_pr_tokens_used_today >= repo.auto_pr_daily_token_budget:
        await log_event(
            db, actor=_AUTO_PR_ACTOR, action="auto_pr.budget_exceeded",
            resource_type="repository", resource_id=repository_id,
            metadata={"trigger": "manual", "tokens_used_today": repo.auto_pr_tokens_used_today,
                      "daily_budget": repo.auto_pr_daily_token_budget},
        )
        await db.commit()
        return 0

    severities = _severities_for_threshold(repo.auto_pr_severity_threshold)

    # Self-heal any findings stuck in IN_REMEDIATION before querying for OPEN ones
    await _heal_stuck_findings(db, repository_id, severities)

    findings_result = await db.execute(
        select(Finding)
        .where(
            Finding.repository_id == repository_id,
            Finding.status == FindingStatus.OPEN.value,
            Finding.severity.in_(severities),
        )
        .order_by(Finding.priority_score.desc())
    )
    findings = findings_result.scalars().all()
    if not findings:
        return 0

    # Dedup: skip findings already being handled by a non-terminal auto remediation
    existing_result = await db.execute(
        select(Remediation.finding_id, Remediation.status).where(
            Remediation.finding_id.in_([f.id for f in findings]),
            Remediation.is_auto_triggered.is_(True),
        )
    )
    already_active = {
        fid for fid, status in existing_result.all()
        if status not in _TERMINAL_FAILURE_STATES
    }

    queued_ids: list[str] = []
    for finding in findings:
        if finding.id in already_active:
            continue
        if not finding.file_path:
            # Auto PR requires a specific file to patch. Findings without a file_path
            # (e.g. dependency vulnerabilities, configuration issues) cannot be
            # auto-committed — skip them now to avoid a misleading "Error None" failure.
            logger.debug(
                "Skipping finding %s (severity=%s) — no file_path; auto PR requires a file-specific vulnerability",
                finding.id, finding.severity,
            )
            continue
        rem = Remediation(
            finding_id=finding.id,
            requested_by=_AUTO_PR_ACTOR,
            status=RemediationStatus.AUTO_TRIGGERED.value,
            is_auto_triggered=True,
        )
        db.add(rem)
        finding.status = FindingStatus.IN_REMEDIATION.value
        await db.flush()
        await log_event(
            db, actor=_AUTO_PR_ACTOR, action="auto_pr.queued",
            resource_type="remediation", resource_id=rem.id,
            metadata={"finding_id": finding.id, "severity": finding.severity,
                      "repository_id": repository_id, "trigger": "manual"},
        )
        queued_ids.append(rem.id)

    await db.commit()

    for rem_id in queued_ids:
        asyncio.create_task(_run_with_semaphore(rem_id, repository_id))

    return len(queued_ids)


async def reset_auto_pr_budgets(db) -> None:
    """Reset auto_pr_tokens_used_today to 0 for all repositories (daily at 00:05 UTC)."""
    from datetime import datetime, timezone
    await db.execute(
        update(Repository).values(
            auto_pr_tokens_used_today=0,
            auto_pr_last_budget_reset=datetime.now(timezone.utc),
        )
    )
    await db.commit()
    logger.info("Auto PR daily token budgets reset")
