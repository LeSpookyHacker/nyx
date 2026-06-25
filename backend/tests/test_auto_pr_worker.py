"""Unit + integration tests for the Auto PR worker.

Run with: pytest backend/tests/test_auto_pr_worker.py
All Anthropic and GitHub calls are mocked — no live calls are made.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, select

from app.core.constants import FindingStatus, RemediationStatus, Severity
from app.database import AsyncSessionLocal, init_db
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.services import ai_service, github_service
from app.services.ai_service import AIFixResult
from app.workers import auto_pr_worker


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(scope="module", autouse=True)
def _db():
    run(init_db())
    yield


@pytest.fixture(autouse=True)
def _clean():
    async def _wipe():
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Remediation))
            await db.execute(delete(Finding))
            await db.execute(delete(Repository))
            await db.execute(delete(AuditLog))
            await db.commit()
    run(_wipe())
    yield


# ── DB helpers ────────────────────────────────────────────────────────────────

async def _make_repo(**overrides) -> Repository:
    async with AsyncSessionLocal() as db:
        repo = Repository(
            github_full_name=overrides.pop("github_full_name", "octo/repo"),
            auto_pr_mode=overrides.pop("auto_pr_mode", True),
            auto_pr_severity_threshold=overrides.pop("auto_pr_severity_threshold", "HIGH"),
            auto_pr_daily_token_budget=overrides.pop("auto_pr_daily_token_budget", 50000),
            auto_pr_tokens_used_today=overrides.pop("auto_pr_tokens_used_today", 0),
            **overrides,
        )
        db.add(repo)
        await db.commit()
        await db.refresh(repo)
        return repo


async def _make_finding(repo_id: str, severity: str = "CRITICAL", scan_id: str = "scan-1",
                        status: str = FindingStatus.OPEN.value, priority: float = 50.0) -> Finding:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        f = Finding(
            fingerprint=f"fp-{severity}-{priority}",
            repository_id=repo_id,
            scan_id=scan_id,
            title=f"{severity} issue",
            rule_id="python.test",
            scanner="SEMGREP",
            severity=severity,
            file_path="app/vuln.py",
            line_start=10,
            priority_score=priority,
            status=status,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(f)
        await db.commit()
        await db.refresh(f)
        return f


async def _enqueue(repo_id: str, scan_id: str = "scan-1") -> int:
    async with AsyncSessionLocal() as db:
        return await auto_pr_worker.enqueue_auto_pr_findings(db, repo_id, scan_id)


async def _get_remediation(rem_id: str) -> Remediation:
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(Remediation).where(Remediation.id == rem_id))).scalar_one()


async def _remediations_for(finding_id: str):
    async with AsyncSessionLocal() as db:
        return (await db.execute(
            select(Remediation).where(Remediation.finding_id == finding_id)
        )).scalars().all()


def _fix_result(confidence: float = 0.9, flagged: bool = False, warnings=None) -> AIFixResult:
    return AIFixResult(
        explanation="Use a parameterized query.",
        fix_diff="--- a/app/vuln.py\n+++ b/app/vuln.py\n@@ -10 +10 @@\n-bad\n+good\n",
        fix_summary="Fix SQL injection",
        confidence=confidence,
        confidence_flagged=flagged,
        model="claude-sonnet-4-6",
        prompt_tokens=100,
        completion_tokens=50,
        fix_prompt="prompt",
        diff_warnings=warnings or [],
    )


def _patch_common(monkeypatch, *, fix: AIFixResult, audit_passed: bool = True):
    """Patch all external calls the pipeline makes up to (and including) PR creation."""
    async def _gen(*_a, **_kw):
        return fix
    async def _est(*_a, **_kw):
        return 100
    async def _tests(*_a, **_kw):
        return {}
    async def _file(*_a, **_kw):
        return "bad\n"
    async def _audit(*_a, **_kw):
        return {"passed": audit_passed, "risk_level": "LOW" if audit_passed else "HIGH",
                "findings": [], "summary": "ok", "token_input": 20, "token_output": 10}
    async def _create_pr(**_kw):
        return 123, "https://github.com/octo/repo/pull/123"

    monkeypatch.setattr(ai_service, "generate_fix", _gen)
    monkeypatch.setattr(auto_pr_worker, "_estimate_input_tokens", _est)
    monkeypatch.setattr(auto_pr_worker, "_maybe_fetch_tests", _tests)
    monkeypatch.setattr(auto_pr_worker, "audit_generated_diff", _audit)
    monkeypatch.setattr(github_service, "get_file_content", _file)
    monkeypatch.setattr(github_service, "apply_unified_diff", lambda *_a, **_kw: "good\n")
    monkeypatch.setattr(github_service, "create_fix_pr", _create_pr)
    # Bypass strict diff-scope validation (validated separately in the manual flow)
    import app.routers.remediation as rem_router
    monkeypatch.setattr(rem_router, "_validate_diff_scope", lambda *_a, **_kw: None)


# ── enqueue() tests ─────────────────────────────────────────────────────────────

def test_enqueue_skips_when_mode_off():
    repo = run(_make_repo(auto_pr_mode=False))
    run(_make_finding(repo.id, "CRITICAL"))
    assert run(_enqueue(repo.id)) == 0


def test_enqueue_skips_when_budget_exhausted():
    repo = run(_make_repo(auto_pr_daily_token_budget=10000, auto_pr_tokens_used_today=10000))
    run(_make_finding(repo.id, "CRITICAL"))
    assert run(_enqueue(repo.id)) == 0
    # An audit event should record the skip
    async def _check():
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(AuditLog).where(AuditLog.action == "auto_pr.budget_exceeded")
            )).scalars().all()
            return len(rows)
    assert run(_check()) >= 1


def test_enqueue_queues_critical_findings(monkeypatch):
    monkeypatch.setattr(auto_pr_worker, "_run_with_semaphore",
                        lambda *_a, **_kw: asyncio.sleep(0))
    repo = run(_make_repo(auto_pr_severity_threshold="HIGH"))
    run(_make_finding(repo.id, "CRITICAL"))
    assert run(_enqueue(repo.id)) == 1


def test_enqueue_queues_high_findings_when_threshold_is_high(monkeypatch):
    monkeypatch.setattr(auto_pr_worker, "_run_with_semaphore",
                        lambda *_a, **_kw: asyncio.sleep(0))
    repo = run(_make_repo(auto_pr_severity_threshold="HIGH"))
    run(_make_finding(repo.id, "CRITICAL", priority=90))
    run(_make_finding(repo.id, "HIGH", priority=80))
    run(_make_finding(repo.id, "MEDIUM", priority=70))  # excluded
    assert run(_enqueue(repo.id)) == 2


def test_enqueue_skips_high_when_threshold_is_critical_only(monkeypatch):
    monkeypatch.setattr(auto_pr_worker, "_run_with_semaphore",
                        lambda *_a, **_kw: asyncio.sleep(0))
    repo = run(_make_repo(auto_pr_severity_threshold="CRITICAL"))
    run(_make_finding(repo.id, "CRITICAL"))
    run(_make_finding(repo.id, "HIGH"))  # excluded under CRITICAL-only
    assert run(_enqueue(repo.id)) == 1


def test_enqueue_marks_finding_in_remediation(monkeypatch):
    monkeypatch.setattr(auto_pr_worker, "_run_with_semaphore",
                        lambda *_a, **_kw: asyncio.sleep(0))
    repo = run(_make_repo())
    f = run(_make_finding(repo.id, "CRITICAL"))
    run(_enqueue(repo.id))
    rems = run(_remediations_for(f.id))
    assert len(rems) == 1
    assert rems[0].is_auto_triggered is True
    assert rems[0].status == RemediationStatus.AUTO_TRIGGERED.value


# ── pipeline tests ──────────────────────────────────────────────────────────────

def test_pipeline_skips_on_low_confidence(monkeypatch):
    repo = run(_make_repo(auto_pr_skip_low_confidence=True))
    f = run(_make_finding(repo.id, "CRITICAL"))
    _patch_common(monkeypatch, fix=_fix_result(confidence=0.2, flagged=True))

    rem_id = run(_seed_auto_remediation(f.id))
    run(auto_pr_worker.process_auto_pr_finding(rem_id, repo.id))
    rem = run(_get_remediation(rem_id))
    assert rem.status == RemediationStatus.REVIEW_LOW_CONFIDENCE.value


def test_pipeline_skips_on_audit_failure(monkeypatch):
    repo = run(_make_repo(auto_pr_security_audit=True))
    f = run(_make_finding(repo.id, "CRITICAL"))
    _patch_common(monkeypatch, fix=_fix_result(), audit_passed=False)

    rem_id = run(_seed_auto_remediation(f.id))
    run(auto_pr_worker.process_auto_pr_finding(rem_id, repo.id))
    rem = run(_get_remediation(rem_id))
    assert rem.status == RemediationStatus.AUDIT_FAILED.value
    assert rem.audit_passed is False


def test_pipeline_commits_draft_pr(monkeypatch):
    """Integration: clean fix + passing audit, checks disabled → COMMITTED draft PR."""
    repo = run(_make_repo(auto_pr_security_audit=True, auto_pr_require_passing_checks=False))
    f = run(_make_finding(repo.id, "CRITICAL"))

    created = {}
    async def _create_pr(**kw):
        created.update(kw)
        return 123, "https://github.com/octo/repo/pull/123"

    _patch_common(monkeypatch, fix=_fix_result(), audit_passed=True)
    monkeypatch.setattr(github_service, "create_fix_pr", _create_pr)

    rem_id = run(_seed_auto_remediation(f.id))
    run(auto_pr_worker.process_auto_pr_finding(rem_id, repo.id))

    rem = run(_get_remediation(rem_id))
    assert rem.status == RemediationStatus.COMMITTED.value
    assert rem.pr_number == 123
    assert rem.audit_passed is True
    assert created.get("draft") is True                       # draft PR, not ready-for-review
    assert created["branch_name"].startswith("nyx/auto-fix/")

    async def _audit_actions():
        async with AsyncSessionLocal() as db:
            return {a for (a,) in (await db.execute(select(AuditLog.action))).all()}
    actions = run(_audit_actions())
    assert "auto_pr.committed" in actions
    assert "auto_pr.audit_started" in actions


# ── budget tests ────────────────────────────────────────────────────────────────

def test_budget_deduction_is_atomic():
    repo = run(_make_repo(auto_pr_daily_token_budget=1000, auto_pr_tokens_used_today=0))

    async def _deduct(n):
        async with AsyncSessionLocal() as db:
            return await auto_pr_worker._deduct_tokens_and_check_budget(db, repo.id, n)

    assert run(_deduct(600)) is True     # 600 <= 1000
    assert run(_deduct(600)) is False    # 1200 > 1000 (deduction still applied)

    async def _used():
        async with AsyncSessionLocal() as db:
            r = (await db.execute(select(Repository).where(Repository.id == repo.id))).scalar_one()
            return r.auto_pr_tokens_used_today
    assert run(_used()) == 1200


def test_budget_reset_zeros_all_repos():
    r1 = run(_make_repo(github_full_name="octo/a", auto_pr_tokens_used_today=999))
    r2 = run(_make_repo(github_full_name="octo/b", auto_pr_tokens_used_today=12345))

    async def _reset():
        async with AsyncSessionLocal() as db:
            await auto_pr_worker.reset_auto_pr_budgets(db)
    run(_reset())

    async def _used(repo_id):
        async with AsyncSessionLocal() as db:
            return (await db.execute(
                select(Repository.auto_pr_tokens_used_today).where(Repository.id == repo_id)
            )).scalar_one()
    assert run(_used(r1.id)) == 0
    assert run(_used(r2.id)) == 0


def test_severities_for_threshold():
    assert auto_pr_worker._severities_for_threshold("CRITICAL") == [Severity.CRITICAL.value]
    assert set(auto_pr_worker._severities_for_threshold("HIGH")) == {Severity.CRITICAL.value, Severity.HIGH.value}


# ── shared seeding helper for pipeline tests ────────────────────────────────────

async def _seed_auto_remediation(finding_id: str) -> str:
    async with AsyncSessionLocal() as db:
        rem = Remediation(
            finding_id=finding_id,
            requested_by="auto_pr_worker",
            status=RemediationStatus.AUTO_TRIGGERED.value,
            is_auto_triggered=True,
        )
        db.add(rem)
        await db.commit()
        await db.refresh(rem)
        return rem.id
