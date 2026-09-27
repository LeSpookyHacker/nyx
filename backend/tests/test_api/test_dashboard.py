"""Dashboard aggregation endpoints (regression: func.case → sqlalchemy.case)."""
from __future__ import annotations

import asyncio
import os
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from app.database import AsyncSessionLocal, init_db
from app.models.finding import Finding
from app.models.repo_risk_history import RepoRiskHistory
from app.models.repository import Repository

HEADERS = {"X-API-Key": "nyx-test-bootstrap-key"}   # conftest NYX_API_KEY


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
            for model in (RepoRiskHistory, Finding, Repository):
                await db.execute(delete(model))
            await db.commit()
    run(init_db())
    run(_wipe())
    yield


async def _seed_findings() -> str:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        repo = Repository(github_full_name="org/hot")
        db.add(repo)
        await db.flush()
        for sev, age_days in [("CRITICAL", 1), ("CRITICAL", 2), ("HIGH", 1), ("LOW", 1), ("CRITICAL", 30)]:
            db.add(Finding(fingerprint=os.urandom(8).hex(), repository_id=repo.id, scan_id="s",
                           title="t", rule_id="r", scanner="SEMGREP", severity=sev, status="OPEN",
                           first_seen_at=now - timedelta(days=age_days), last_seen_at=now))
        await db.commit()
        return repo.id


def test_hot_repos_counts_by_severity(client):
    repo_id = run(_seed_findings())
    r = client.get("/api/v1/dashboard/hot-repos", params={"days": 7}, headers=HEADERS)
    assert r.status_code == 200, r.text
    [row] = r.json()
    assert row["id"] == repo_id
    assert row["new_findings"] == 4          # the 30-day-old finding is outside the window
    assert row["open_critical"] == 2
    assert row["open_high"] == 1


def test_org_risk_history_counts_repos_at_risk(client):
    async def _seed():
        async with AsyncSessionLocal() as db:
            repos = [Repository(github_full_name=f"org/r{i}") for i in range(3)]
            db.add_all(repos)
            await db.flush()
            today = date.today()
            for repo, score, crit in zip(repos, (80.0, 50.0, 10.0), (3, 1, 0)):
                db.add(RepoRiskHistory(repository_id=repo.id, snapshot_date=today, risk_score=score,
                                       open_critical=crit, open_high=1, open_medium=0, open_low=0))
            await db.commit()
    run(_seed())
    r = client.get("/api/v1/dashboard/org-risk-history", params={"days": 30}, headers=HEADERS)
    assert r.status_code == 200, r.text
    [day] = r.json()
    assert day["repos_at_risk"] == 2          # scores >= 50
    assert day["total_critical"] == 4
    assert day["total_open"] == 7
    assert day["avg_risk_score"] == round((80 + 50 + 10) / 3, 1)
