"""Webhook HMAC verification tests."""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c


def _sig(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_rejects_missing_signature(client):
    r = client.post(
        "/api/v1/webhooks/github",
        json={"zen": "hello"},
        headers={"X-GitHub-Event": "ping", "X-GitHub-Delivery": "delivery-1"},
    )
    assert r.status_code in (400, 401, 403)


def test_webhook_rejects_invalid_signature(client):
    body = json.dumps({"zen": "hello"}).encode()
    r = client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "delivery-2",
            "X-Hub-Signature-256": "sha256=deadbeef",
        },
    )
    assert r.status_code in (400, 401, 403)


def test_webhook_accepts_valid_ping(client):
    body = json.dumps({"zen": "keep it simple"}).encode()
    sig = _sig("b" * 64, body)  # matches NYX_WEBHOOK_SECRET from conftest
    r = client.post(
        "/api/v1/webhooks/github",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "delivery-3",
            "X-Hub-Signature-256": sig,
        },
    )
    # Ping is either accepted or politely not-accepted — the critical assertion is
    # that a correctly-signed request is never a 401/403 due to HMAC mismatch.
    assert r.status_code < 500
    assert r.status_code not in (401, 403)
