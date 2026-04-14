"""Auth and session regression tests — run with `pytest backend/tests/test_api/test_auth.py`."""
from __future__ import annotations

import asyncio
import hashlib

import pytest


@pytest.fixture(scope="module")
def client():
    """TestClient that triggers app lifespan (init_db + background schedulers)."""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _wipe_sessions():
    """Clear session rows + auth lockout state between tests."""
    from app.database import AsyncSessionLocal
    from app.models.user_session import UserSession
    from app.models.auth_lockout import AuthLockout
    from sqlalchemy import delete
    from app.core.security import _FAILED_AUTH  # type: ignore

    async def _wipe():
        async with AsyncSessionLocal() as db:
            await db.execute(delete(UserSession))
            await db.execute(delete(AuthLockout))
            await db.commit()

    asyncio.run(_wipe())
    _FAILED_AUTH.clear()
    yield


def test_protected_endpoint_rejects_missing_key(client):
    r = client.get("/api/v1/repositories")
    assert r.status_code == 401


def test_protected_endpoint_rejects_invalid_key(client):
    r = client.get("/api/v1/repositories", headers={"X-API-Key": "nyx-wrong"})
    assert r.status_code == 401


def test_protected_endpoint_accepts_bootstrap_key(client):
    r = client.get("/api/v1/repositories", headers={"X-API-Key": "nyx-test-bootstrap-key"})
    assert r.status_code == 200


def test_whoami_requires_auth(client):
    r = client.get("/auth/whoami")
    assert r.status_code == 401


def test_whoami_returns_scopes(client):
    r = client.get("/auth/whoami", headers={"X-API-Key": "nyx-test-bootstrap-key"})
    assert r.status_code == 200
    body = r.json()
    assert "identity" in body
    assert "scopes" in body


def test_session_login_sets_opaque_cookie_and_whoami_works(client):
    r = client.post("/auth/session", json={"api_key": "nyx-test-bootstrap-key"})
    assert r.status_code == 200, r.text
    cookie = r.cookies.get("nyx_session")
    assert cookie is not None
    # The cookie value must NOT be the raw API key — that's the C1 regression.
    assert cookie != "nyx-test-bootstrap-key"

    # whoami via cookie only (no header)
    r2 = client.get("/auth/whoami", cookies={"nyx_session": cookie})
    assert r2.status_code == 200


def test_session_login_rejects_bad_key(client):
    r = client.post("/auth/session", json={"api_key": "nyx-wrong"})
    assert r.status_code == 401


def test_logout_deletes_session_row(client):
    login = client.post("/auth/session", json={"api_key": "nyx-test-bootstrap-key"})
    cookie = login.cookies.get("nyx_session")

    out = client.post("/auth/logout", cookies={"nyx_session": cookie})
    assert out.status_code == 200

    # Using the same cookie again must be rejected
    r = client.get("/auth/whoami", cookies={"nyx_session": cookie})
    assert r.status_code == 401


def test_cookie_path_rejects_unknown_session(client):
    r = client.get("/auth/whoami", cookies={"nyx_session": "not-a-real-session"})
    assert r.status_code == 401


def test_raw_api_key_not_accepted_as_cookie(client):
    """Regression: the old bug was that the cookie value was the api key itself."""
    r = client.get("/auth/whoami", cookies={"nyx_session": "nyx-test-bootstrap-key"})
    assert r.status_code == 401


def test_session_hash_stored_not_plaintext(client):
    """DB should store the SHA-256 hash of the session token, not the token itself."""
    from app.database import AsyncSessionLocal
    from app.models.user_session import UserSession
    from sqlalchemy import select

    login = client.post("/auth/session", json={"api_key": "nyx-test-bootstrap-key"})
    cookie = login.cookies.get("nyx_session")
    assert cookie is not None

    async def _fetch():
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(UserSession))
            return result.scalars().all()

    rows = asyncio.run(_fetch())
    assert any(r.session_id_hash == hashlib.sha256(cookie.encode()).hexdigest() for r in rows)
    assert all(r.session_id_hash != cookie for r in rows)


def test_unsafe_dev_fallback_refuses_when_webhook_configured(monkeypatch):
    """Silent-admin dev fallback must refuse when GITHUB_WEBHOOK_ENDPOINT is set."""
    from app.core import security
    monkeypatch.setattr(security.settings, "GITHUB_WEBHOOK_ENDPOINT", "https://nyx.example.com/api/v1/webhooks/github")
    assert security._is_unsafe_dev_fallback() is True

    monkeypatch.setattr(security.settings, "GITHUB_WEBHOOK_ENDPOINT", "")
    monkeypatch.setattr(security.settings, "HTTPS_ONLY", True)
    assert security._is_unsafe_dev_fallback() is True

    monkeypatch.setattr(security.settings, "HTTPS_ONLY", False)
    assert security._is_unsafe_dev_fallback() is False
