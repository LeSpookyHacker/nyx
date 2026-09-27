"""Regression tests for SECURITY-AUDIT-2026-09-27 (NYX-2026-09-01 … -18).

Each test reproduced its finding against the pre-fix code (it failed there) and
passes once the fix is in place. All GitHub / Anthropic calls are mocked.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from app.config import get_settings
from app.core.constants import FindingStatus, RemediationStatus, ScanStatus, ScanTrigger
from app.database import AsyncSessionLocal, init_db
from app.models.api_key import ApiKey
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.repository import Repository
from app.models.scan import Scan


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean():
    async def _wipe():
        async with AsyncSessionLocal() as db:
            for model in (Remediation, Finding, Scan, Repository):
                await db.execute(delete(model))
            await db.execute(delete(ApiKey).where(ApiKey.name.like("reg-%")))
            await db.commit()
    run(init_db())
    run(_wipe())
    yield


# ── helpers ────────────────────────────────────────────────────────────────────

async def _mk_key(scope: str) -> str:
    from app.core.security import _compute_key_hashes
    raw = secrets.token_urlsafe(24)
    async with AsyncSessionLocal() as db:
        db.add(ApiKey(name=f"reg-{scope}-{raw[:6]}", key_hash=_compute_key_hashes(raw)[0],
                      is_active=True, created_by="test", scopes=scope))
        await db.commit()
    return raw


async def _mk_repo(name: str, **kw) -> Repository:
    async with AsyncSessionLocal() as db:
        r = Repository(github_full_name=name, **kw)
        db.add(r)
        await db.commit()
        await db.refresh(r)
        return r


async def _mk_finding(repo_id: str, **kw) -> Finding:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        f = Finding(fingerprint=kw.pop("fingerprint", os.urandom(8).hex()), repository_id=repo_id,
                    scan_id=kw.pop("scan_id", "s"), title=kw.pop("title", "SQLi"), rule_id="r",
                    scanner="SEMGREP", severity=kw.pop("severity", "CRITICAL"),
                    file_path=kw.pop("file_path", "app/db.py"), line_start=3,
                    status=kw.pop("status", FindingStatus.OPEN.value),
                    first_seen_at=now, last_seen_at=now, **kw)
        db.add(f)
        await db.commit()
        await db.refresh(f)
        return f


async def _mk_remediation(finding_id: str, **kw) -> Remediation:
    async with AsyncSessionLocal() as db:
        rem = Remediation(finding_id=finding_id, requested_by="t", **kw)
        db.add(rem)
        await db.commit()
        await db.refresh(rem)
        return rem


async def _get(model, obj_id):
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(model).where(model.id == obj_id))).scalar_one()


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post_webhook(client, event: str, payload: dict, secret: str, delivery: str):
    body = json.dumps(payload).encode()
    return client.post("/api/v1/webhooks/github", content=body, headers={
        "Content-Type": "application/json", "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery, "X-Hub-Signature-256": _sign(secret, body)})


@pytest.fixture
def no_global_webhook_secret(monkeypatch):
    """Real GitHub deliveries are signed with the per-repo secret only (see NYX-2026-09-08)."""
    monkeypatch.setattr(get_settings(), "NYX_WEBHOOK_SECRET", "")


@pytest.fixture
def auto_pr_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "AUTO_PR_MODE_ENABLED", True)


# ═══ NYX-2026-09-01 — scan import authz + Auto PR provenance gate ══════════════

@pytest.mark.parametrize("scope,expected", [("readonly", 403), ("scanner", 403), ("analyst", 202)])
def test_01_multipart_import_requires_analyst_scope(client, monkeypatch, scope, expected):
    import app.routers.scans as scans_router
    monkeypatch.setattr(scans_router, "process_scan_results", lambda *a, **k: None)
    repo = run(_mk_repo("victim/import", webhook_secret="per-repo"))
    key = run(_mk_key(scope))
    r = client.post("/api/v1/scans/import", headers={"X-API-Key": key},
                    data={"repository_id": repo.id, "scanner": "SEMGREP"},
                    files={"file": ("r.json", b'{"results": []}', "application/json")})
    assert r.status_code == expected


async def _process_scan(repo_id: str, *, trigger: str, verified: bool) -> None:
    from app.workers.scan_worker import process_scan_results
    async with AsyncSessionLocal() as db:
        scan = Scan(repository_id=repo_id, scanner="SEMGREP", trigger=trigger,
                    status=ScanStatus.PENDING.value, started_at=datetime.now(timezone.utc),
                    submission_verified=verified)
        db.add(scan)
        await db.commit()
        scan_id = scan.id
    await process_scan_results(scan_id, {"results": []})


@pytest.mark.parametrize("trigger,verified,should_enqueue", [
    (ScanTrigger.IMPORT.value, False, False),     # unsigned import must not drive Auto PR
    (ScanTrigger.WEBHOOK.value, False, False),    # unsigned Snyk webhook
    (ScanTrigger.IMPORT.value, True, True),       # HMAC-verified CI submission
    (ScanTrigger.SCHEDULED.value, False, True),   # GitHub Code Scanning / Dependabot sync
])
def test_01_auto_pr_only_for_trusted_scans(monkeypatch, auto_pr_enabled, trigger, verified, should_enqueue):
    from app.workers import auto_pr_worker
    calls = []

    async def _spy(db, repo_id, scan_id):
        calls.append(scan_id)
        return 0
    monkeypatch.setattr(auto_pr_worker, "enqueue_auto_pr_findings", _spy)
    repo = run(_mk_repo("victim/gate", auto_pr_mode=True))
    run(_process_scan(repo.id, trigger=trigger, verified=verified))
    assert bool(calls) is should_enqueue


def test_01_snyk_webhook_scan_marked_unverified_without_secret(client, monkeypatch):
    import app.routers.webhooks as wh
    monkeypatch.setattr(get_settings(), "SNYK_WEBHOOK_SECRET", "")
    monkeypatch.setattr(wh, "process_scan_results", lambda *a, **k: None)
    repo = run(_mk_repo("victim/snyk"))
    r = client.post("/api/v1/webhooks/snyk", json={
        "project": {"remoteRepoUrl": f"https://github.com/{repo.github_full_name}.git"},
        "newIssues": [{"id": "SNYK-1"}]})
    assert r.status_code == 200

    async def _scan():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(Scan).where(Scan.repository_id == repo.id))).scalar_one()
    assert run(_scan()).submission_verified is False


def test_01_snyk_webhook_scan_marked_verified_with_valid_signature(client, monkeypatch):
    import app.routers.webhooks as wh
    monkeypatch.setattr(get_settings(), "SNYK_WEBHOOK_SECRET", "snyk-secret")
    monkeypatch.setattr(wh, "process_scan_results", lambda *a, **k: None)
    repo = run(_mk_repo("victim/snyk2"))
    body = json.dumps({"project": {"remoteRepoUrl": f"https://github.com/{repo.github_full_name}"},
                       "newIssues": [{"id": "SNYK-1"}]}).encode()
    r = client.post("/api/v1/webhooks/snyk", content=body, headers={
        "Content-Type": "application/json", "x-hub-signature": _sign("snyk-secret", body)})
    assert r.status_code == 200

    async def _scan():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(Scan).where(Scan.repository_id == repo.id))).scalar_one()
    assert run(_scan()).submission_verified is True


# ═══ NYX-2026-09-02 — audit verdict must fail closed ═════════════════════════

@pytest.mark.parametrize("raw", [
    '{"passed": "false", "risk_level": "LOW", "findings": [], "summary": "x"}',
    '{"passed": "true", "risk_level": "LOW", "findings": [], "summary": "x"}',
    '{"passed": 1, "risk_level": "LOW", "findings": [], "summary": "x"}',
    '{"passed": true, "risk_level": "CRITICAL", "findings": [], "summary": "x"}',
    '{"passed": true, "risk_level": "HIGH", "findings": [], "summary": "x"}',
])
def test_02_audit_parser_rejects_non_boolean_or_high_risk(raw):
    from app.services.auto_pr_audit_service import _parse_audit_response
    assert _parse_audit_response(raw)["passed"] is False


def test_02_audit_parser_does_not_merge_multiple_objects():
    from app.services.auto_pr_audit_service import _parse_audit_response
    text = ('{"passed": false, "risk_level": "CRITICAL", "findings": ["rce"], "summary": "no"}\n'
            'Earlier draft: {"passed": true, "risk_level": "LOW"}')
    assert _parse_audit_response(text)["passed"] is False


def test_02_audit_parser_still_accepts_clean_boolean_true():
    from app.services.auto_pr_audit_service import _parse_audit_response
    v = _parse_audit_response('{"passed": true, "risk_level": "LOW", "findings": [], "summary": "ok"}')
    assert v["passed"] is True and v["risk_level"] == "LOW"


# ═══ NYX-2026-09-03 — diff application must match what the diff claims ═══════

_ORIG = "def handler(req):\n    require_auth(req)\n    return run(req)\n"


def test_03_unmatched_hunk_is_rejected():
    from app.services.github_service import apply_unified_diff
    diff = ("--- a/app/h.py\n+++ b/app/h.py\n@@ -2,1 +2,1 @@\n"
            "-    log.debug('noop')\n+    log.debug('noop')  # tidy\n")
    assert apply_unified_diff(_ORIG, diff) is None


def test_03_multi_file_patch_is_rejected():
    from app.services.github_service import apply_unified_diff
    diff = ("--- a/app/h.py\n+++ b/app/h.py\n@@ -3,1 +3,1 @@\n-    return run(req)\n+    return run2(req)\n"
            "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-x\n+y\n")
    assert apply_unified_diff(_ORIG, diff) is None


def test_03_matching_diff_still_applies_with_offset():
    from app.services.github_service import apply_unified_diff
    # Hunk header is off by two lines; fuzzy search must still locate the exact source line.
    diff = ("--- a/app/h.py\n+++ b/app/h.py\n@@ -1,1 +1,1 @@\n"
            "-    return run(req)\n+    return run(sanitize(req))\n")
    out = apply_unified_diff(_ORIG, diff)
    assert out == "def handler(req):\n    require_auth(req)\n    return run(sanitize(req))\n"


def test_03_pure_insertion_hunk_still_applies():
    from app.services.github_service import apply_unified_diff
    diff = "--- a/app/h.py\n+++ b/app/h.py\n@@ -1,0 +2,1 @@\n+    validate(req)\n"
    out = apply_unified_diff(_ORIG, diff)
    assert out is not None and "validate(req)" in out and "require_auth(req)" in out


def test_03_diff_applies_to_file_without_trailing_newline_and_crlf():
    from app.services.github_service import apply_unified_diff
    diff = "--- a/x.py\n+++ b/x.py\n@@ -2,1 +2,1 @@\n-b = 2\n+b = 3\n"
    assert apply_unified_diff("a = 1\nb = 2", diff) == "a = 1\nb = 3\n"
    assert apply_unified_diff("a = 1\r\nb = 2\r\n", diff) == "a = 1\r\nb = 3\n"


@pytest.mark.parametrize("diff", [
    "--- app/h.py\n+++ .github/workflows/ci.yml\n@@ -1 +1 @@\n-a\n+b\n",   # un-prefixed headers
    "--- a/app/h.py\n+++ b/app/h.py\n--- other.py\n+++ other.py\n@@ -1 +1 @@\n-a\n+b\n",
    "@@ -1 +1 @@\n-a\n+b\n",                                                # no headers at all
])
def test_03_diff_scope_checks_every_header(diff):
    from app.routers.remediation import _validate_diff_scope
    with pytest.raises(ValueError):
        _validate_diff_scope(diff, "app/h.py")


def test_03_diff_scope_ignores_removed_sql_comment_lines():
    from app.routers.remediation import _validate_diff_scope
    diff = ("--- a/db/q.sql\n+++ b/db/q.sql\n@@ -1,2 +1,1 @@\n"
            "--- legacy comment\n SELECT 1;\n")
    _validate_diff_scope(diff, "db/q.sql")


def test_03_diff_scope_accepts_expected_file():
    from app.routers.remediation import _validate_diff_scope
    _validate_diff_scope("--- a/app/h.py\n+++ b/app/h.py\n@@ -1 +1 @@\n-a\n+b\n", "app/h.py")


# ═══ NYX-2026-09-04 — PR-merged webhook is scoped to its repository ═══════════

def test_04_merge_in_other_repo_does_not_close_finding(client, no_global_webhook_secret):
    victim = run(_mk_repo("victim/app", webhook_secret="victim-secret"))
    other = run(_mk_repo("someone/other", webhook_secret="other-secret"))
    finding = run(_mk_finding(victim.id, status=FindingStatus.IN_REMEDIATION.value))
    rem = run(_mk_remediation(finding.id, status=RemediationStatus.PR_OPEN.value, pr_number=7))

    r = _post_webhook(client, "pull_request", {
        "action": "closed", "repository": {"full_name": other.github_full_name},
        "pull_request": {"number": 7, "merged": True,
                         "html_url": "https://github.com/someone/other/pull/7"}}, "other-secret", "reg-04a")
    assert r.status_code == 200
    assert run(_get(Finding, finding.id)).status == FindingStatus.IN_REMEDIATION.value
    assert run(_get(Remediation, rem.id)).status == RemediationStatus.PR_OPEN.value


def test_04_merge_in_same_repo_closes_finding(client, no_global_webhook_secret):
    repo = run(_mk_repo("victim/app", webhook_secret="victim-secret"))
    finding = run(_mk_finding(repo.id, status=FindingStatus.IN_REMEDIATION.value))
    rem = run(_mk_remediation(finding.id, status=RemediationStatus.PR_OPEN.value, pr_number=7))
    r = _post_webhook(client, "pull_request", {
        "action": "closed", "repository": {"full_name": repo.github_full_name},
        "pull_request": {"number": 7, "merged": True,
                         "html_url": "https://github.com/victim/app/pull/7"}}, "victim-secret", "reg-04b")
    assert r.status_code == 200
    assert run(_get(Finding, finding.id)).status == FindingStatus.FIXED.value
    assert run(_get(Remediation, rem.id)).status == RemediationStatus.MERGED.value


def test_04_advisory_issue_number_is_not_treated_as_pr(client, no_global_webhook_secret):
    repo = run(_mk_repo("victim/app", webhook_secret="victim-secret"))
    finding = run(_mk_finding(repo.id, status=FindingStatus.IN_REMEDIATION.value, file_path=None))
    run(_mk_remediation(finding.id, status=RemediationStatus.ADVISORY_OPENED.value, pr_number=9))
    _post_webhook(client, "pull_request", {
        "action": "closed", "repository": {"full_name": repo.github_full_name},
        "pull_request": {"number": 9, "merged": True,
                         "html_url": "https://github.com/victim/app/pull/9"}}, "victim-secret", "reg-04c")
    assert run(_get(Finding, finding.id)).status == FindingStatus.IN_REMEDIATION.value
