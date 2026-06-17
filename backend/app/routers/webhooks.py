"""Webhook receivers — GitHub and Snyk."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from sqlalchemy import select

from app.config import get_settings
from app.core.constants import ScanStatus, ScanTrigger
from app.core.limiter import limiter
from app.core.security import verify_github_signature, verify_global_webhook_hmac, verify_snyk_signature, verify_webhook_timestamp
from app.database import AsyncSessionLocal
from app.models.repository import Repository
from app.models.scan import Scan
from app.workers.scan_worker import process_scan_results

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/github")
@limiter.limit("60/minute")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(None),
    x_github_delivery: str = Header(None),
):
    """
    Receive GitHub webhook events.

    Supported events:
    - push: triggers scan on default branch pushes
    - pull_request: tracks PRs created by Nyx (merge detection)
    - check_run: reserved for future status check integration
    """
    body = await request.body()

    # Pre-auth check: if NYX_WEBHOOK_SECRET is configured, verify HMAC before
    # any DB lookup to prevent unauthenticated repository enumeration (H-2)
    signature_header = request.headers.get("X-Hub-Signature-256", "")
    verify_global_webhook_hmac(body, signature_header)

    # Replay deduplication — reject a delivery ID we have already processed
    if x_github_delivery:
        async with AsyncSessionLocal() as dedup_db:
            existing = await dedup_db.execute(
                select(Scan).where(Scan.delivery_id == x_github_delivery).limit(1)
            )
            if existing.scalar_one_or_none() is not None:
                return {"status": "ignored", "reason": "duplicate delivery", "delivery": x_github_delivery}

    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Validate push event timestamp to prevent webhook replay (> 10 min old payloads rejected)
    verify_webhook_timestamp(payload, event_type=x_github_event or "")

    # Look up the repository
    repo_full_name = payload.get("repository", {}).get("full_name", "")
    if not repo_full_name:
        return {"status": "ignored", "reason": "no repository in payload"}

    async with AsyncSessionLocal() as db:
        repo_result = await db.execute(
            select(Repository).where(Repository.github_full_name == repo_full_name)
        )
        repo = repo_result.scalar_one_or_none()

        if not repo:
            # Return identical response regardless of whether repo exists (M8 — enumeration prevention)
            return {"status": "ignored", "reason": "webhook not accepted"}

        if not repo.webhook_secret:
            # Same response as "repo not found" to avoid confirming repo existence (M8)
            return {"status": "ignored", "reason": "webhook not accepted"}

        # Verify HMAC signature using per-repo secret (SEC-007: removed dead
        # try-except fallback — Starlette caches request.body() so the second
        # call inside verify_github_signature works fine; the fallback block
        # was never reached and added maintenance risk).
        await verify_github_signature(request, repo.webhook_secret)

        event = x_github_event or ""

        if event == "push":
            await _handle_push(payload, repo, background_tasks, db, delivery_id=x_github_delivery)
        elif event == "pull_request":
            await _handle_pull_request(payload, repo, db, background_tasks)
        elif event == "check_run":
            await _handle_check_run(payload, db)
        # Other events are accepted but ignored

        await db.commit()

    return {"status": "accepted", "event": event, "delivery": x_github_delivery}


async def _handle_push(payload: dict, repo, background_tasks, db, delivery_id: str | None = None) -> None:
    """On push to default branch: auto-detect new scanners, then create Scan records."""
    ref = payload.get("ref", "")
    default_ref = f"refs/heads/{repo.default_branch}"
    if ref != default_ref:
        return  # Only scan pushes to the default branch

    git_sha = payload.get("after", "")
    git_ref = repo.default_branch

    # ── Auto-detect new scanners from pushed files ─────────────────────────────
    from app.services.scanner_detection_service import detect_from_push_payload, merge_scanners
    from app.services.audit_service import log_event

    detections = detect_from_push_payload(payload)
    if detections:
        current = repo.scanner_list
        updated, added = merge_scanners(current, detections)
        if added:
            repo.enabled_scanners = ",".join(sorted(updated))
            await log_event(
                db,
                actor="webhook",
                action="repository.scanners_auto_detected",
                resource_type="repository",
                resource_id=repo.id,
                metadata={
                    "added": added,
                    "reasons": {k: v for k, v in detections.items() if k in added},
                    "git_sha": git_sha,
                },
            )

    for scanner in repo.scanner_list:
        scan = Scan(
            repository_id=repo.id,
            scanner=scanner,
            trigger=ScanTrigger.WEBHOOK.value,
            status=ScanStatus.PENDING.value,
            git_sha=git_sha,
            git_ref=git_ref,
            started_at=datetime.now(timezone.utc),
            delivery_id=delivery_id,
        )
        db.add(scan)
        await db.flush()
        # Only the first scan record gets the delivery_id to satisfy the unique constraint
        delivery_id = None

        # Actual scan results arrive via POST /api/v1/scans/import-json
        # from the nyx-scan.yml GitHub Actions workflow.


@router.post("/snyk")
@limiter.limit("60/minute")
async def snyk_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature: str = Header(None, alias="x-hub-signature"),
):
    """
    Receive Snyk webhook events.

    Processes `newIssues` from project test webhooks and imports them as findings.
    Configure in Snyk: Settings → Integrations → Webhooks → Add webhook.

    Set SNYK_WEBHOOK_SECRET in .env to match the secret you enter in Snyk.
    """
    body = await request.body()
    settings = get_settings()

    # Verify HMAC signature (skipped if SNYK_WEBHOOK_SECRET is not configured)
    verify_snyk_signature(body, settings.SNYK_WEBHOOK_SECRET, x_hub_signature or "")

    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract GitHub repo full_name from Snyk's remoteRepoUrl
    project = payload.get("project", {})
    remote_url = project.get("remoteRepoUrl", "")
    if not remote_url:
        return {"status": "ignored", "reason": "no remoteRepoUrl in project"}

    # Parse "https://github.com/org/repo.git" → "org/repo"
    repo_full_name = remote_url.rstrip("/").removesuffix(".git")
    if "github.com/" in repo_full_name:
        repo_full_name = repo_full_name.split("github.com/")[-1]

    new_issues = payload.get("newIssues", [])
    if not new_issues:
        return {"status": "accepted", "reason": "no new issues"}

    async with AsyncSessionLocal() as db:
        repo_result = await db.execute(
            select(Repository).where(Repository.github_full_name == repo_full_name)
        )
        repo = repo_result.scalar_one_or_none()

        if not repo:
            return {"status": "ignored", "reason": "repository not registered with Nyx"}

        scan = Scan(
            repository_id=repo.id,
            scanner="SNYK",
            trigger=ScanTrigger.WEBHOOK.value,
            status=ScanStatus.RUNNING.value,
            git_ref=repo.default_branch,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.flush()

        # Pass the newIssues list directly — scan_worker will detect the format
        raw_data = {"_snyk_webhook_issues": new_issues}
        background_tasks.add_task(process_scan_results, str(scan.id), raw_data)
        await db.commit()

    return {"status": "accepted", "new_issues": len(new_issues), "repository": repo_full_name}


async def _handle_pull_request(payload: dict, repo, db, background_tasks) -> None:
    """Handle PR events: merge detection and check run triggering."""
    action = payload.get("action", "")
    pr = payload.get("pull_request", {})
    head_sha = pr.get("head", {}).get("sha", "")

    # ── PR opened / synchronized → trigger a scan + create a pending check run ──
    if action in ("opened", "synchronize") and head_sha:
        settings = get_settings()
        if settings.GITHUB_CHECK_RUNS_ENABLED and repo.scanner_list:
            from app.services.github_service import create_check_run
            check_run_id = await create_check_run(repo.github_full_name, head_sha)

            # Create scan records for this PR head SHA
            pr_ref = pr.get("head", {}).get("ref", "")
            for scanner in repo.scanner_list:
                scan = Scan(
                    repository_id=repo.id,
                    scanner=scanner,
                    trigger=ScanTrigger.WEBHOOK.value,
                    status=ScanStatus.PENDING.value,
                    git_sha=head_sha,
                    git_ref=pr_ref,
                    check_run_id=check_run_id,
                    started_at=datetime.now(timezone.utc),
                )
                db.add(scan)
        return

    # ── PR merged → mark findings fixed ─────────────────────────────────────────
    if action != "closed" or not pr.get("merged"):
        return

    pr_number = pr.get("number")
    pr_url = pr.get("html_url", "")
    if not pr_number:
        return

    from app.core.constants import FindingStatus, RemediationStatus
    from app.models.finding import Finding
    from app.models.jira_link import JiraLink
    from app.models.remediation import Remediation
    from app.services.notification_service import notify_pr_merged

    now = datetime.now(timezone.utc)

    # 1. Close remediations that tracked this PR number
    rem_result = await db.execute(
        select(Remediation).where(Remediation.pr_number == pr_number)
    )
    remediations = rem_result.scalars().all()
    fixed_finding_ids = set()

    for rem in remediations:
        rem.status = RemediationStatus.MERGED.value
        rem.pr_merged_at = now
        fixed_finding_ids.add(rem.finding_id)

    # 2. Also fix any findings directly linked via fix_pr_url (manual PRs)
    if pr_url:
        manual_result = await db.execute(
            select(Finding).where(Finding.fix_pr_url == pr_url)
        )
        for finding in manual_result.scalars().all():
            fixed_finding_ids.add(finding.id)

    # 3. Mark all matched findings as FIXED
    for finding_id in fixed_finding_ids:
        finding_result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = finding_result.scalar_one_or_none()
        if finding and finding.status not in (FindingStatus.FIXED.value,):
            finding.status = FindingStatus.FIXED.value
            finding.resolved_at = now

            # Update linked JIRA ticket status
            jira_result = await db.execute(
                select(JiraLink).where(JiraLink.finding_id == finding_id)
            )
            jira_link = jira_result.scalar_one_or_none()
            if jira_link:
                jira_link.jira_status = "Done"
                jira_link.synced_at = now

            background_tasks.add_task(
                notify_pr_merged, repo.github_full_name, pr_number, finding.title
            )


async def _handle_check_run(payload: dict, db) -> None:
    """
    When a CI check run completes on a nyx/fix/** branch, stamp the matching
    remediation with ci_status=pass|fail and store failure details.

    GitHub delivers check_run events for every individual check (ESLint,
    TypeScript, etc.).  We aggregate: any failure marks the remediation
    ci_status=fail; the first passing conclusion for a branch that has no
    failures yet marks it pass.
    """
    if payload.get("action") != "completed":
        return

    check_run = payload.get("check_run", {})
    conclusion = check_run.get("conclusion")  # success | failure | cancelled | skipped | ...
    branch = check_run.get("check_suite", {}).get("head_branch", "")

    if not branch.startswith("nyx/fix/"):
        return  # Only care about Nyx-created branches

    from app.models.remediation import Remediation

    rem_result = await db.execute(
        select(Remediation).where(Remediation.pr_branch == branch)
    )
    rem = rem_result.scalar_one_or_none()
    if not rem:
        return

    check_name = check_run.get("name", "CI")
    details_url = check_run.get("details_url", "")

    if conclusion in ("failure", "timed_out", "action_required"):
        output = check_run.get("output", {})
        summary = output.get("summary") or output.get("title") or "CI check failed."
        failure_msg = f"**{check_name}** failed"
        if details_url:
            failure_msg += f" — [view details]({details_url})"
        failure_msg += f"\n\n{summary}"

        # Accumulate multiple check failures
        if rem.ci_failure_details:
            rem.ci_failure_details = rem.ci_failure_details + "\n\n---\n\n" + failure_msg
        else:
            rem.ci_failure_details = failure_msg
        rem.ci_status = "fail"

    elif conclusion == "success" and rem.ci_status != "fail":
        # Only set pass if no failure has been recorded yet
        rem.ci_status = "pass"
