"""Unit tests for the Auto PR security-audit service.

Run with: pytest backend/tests/test_auto_pr_audit_service.py
All Claude API calls are mocked — no live calls are made.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.services import auto_pr_audit_service as audit_mod


def run(coro):
    return asyncio.run(coro)


def _finding():
    return SimpleNamespace(
        id="00000000-0000-0000-0000-000000000001",
        title="SQL injection in login",
        rule_id="python.sqli",
        severity="CRITICAL",
        scanner="SEMGREP",
        description="User input concatenated into a SQL query.",
    )


class _FakeResponse:
    def __init__(self, text: str):
        self.content = [SimpleNamespace(text=text)]
        self.usage = SimpleNamespace(input_tokens=120, output_tokens=40)


class _FakeMessages:
    def __init__(self, text: str):
        self._text = text

    async def create(self, **_kwargs):
        return _FakeResponse(self._text)


class _FakeClient:
    def __init__(self, text: str):
        self.messages = _FakeMessages(text)


def _patch_client(monkeypatch, text: str):
    monkeypatch.setattr(audit_mod, "_get_async_client", lambda: _FakeClient(text))


# ── Pure parser tests (no client needed) ──────────────────────────────────────

def test_audit_parses_haiku_json_correctly():
    result = audit_mod._parse_audit_response(
        '{"passed": true, "risk_level": "LOW", "findings": [], "summary": "Clean fix."}'
    )
    assert result["passed"] is True
    assert result["risk_level"] == "LOW"
    assert result["findings"] == []
    assert result["summary"] == "Clean fix."


def test_audit_parses_json_embedded_in_prose():
    # Models sometimes wrap JSON in prose / code fences — the parser must still find it.
    text = 'Here is my verdict:\n```json\n{"passed": false, "risk_level": "HIGH", "findings": ["eval"], "summary": "bad"}\n```'
    result = audit_mod._parse_audit_response(text)
    assert result["passed"] is False
    assert result["risk_level"] == "HIGH"
    assert "eval" in result["findings"]


def test_audit_handles_malformed_json_response():
    result = audit_mod._parse_audit_response("not json at all")
    assert result["passed"] is False           # fails closed
    assert result["risk_level"] == "HIGH"


def test_audit_invalid_risk_level_falls_back_to_high():
    result = audit_mod._parse_audit_response('{"passed": true, "risk_level": "BOGUS", "findings": [], "summary": ""}')
    assert result["risk_level"] == "HIGH"


# ── Mocked end-to-end audit calls ──────────────────────────────────────────────

def test_audit_returns_passed_for_clean_diff(monkeypatch):
    _patch_client(monkeypatch, '{"passed": true, "risk_level": "LOW", "findings": [], "summary": "Parameterized."}')
    result = run(audit_mod.audit_generated_diff(_finding(), "orig", "--- a\n+++ b\n", "claude-haiku-4-5"))
    assert result["passed"] is True
    assert result["token_input"] == 120
    assert result["token_output"] == 40


def test_audit_returns_failed_for_eval_injection(monkeypatch):
    _patch_client(
        monkeypatch,
        '{"passed": false, "risk_level": "CRITICAL", "findings": ["introduces eval()"], "summary": "unsafe"}',
    )
    result = run(audit_mod.audit_generated_diff(_finding(), "orig", "+ eval(user_input)", "claude-haiku-4-5"))
    assert result["passed"] is False
    assert result["risk_level"] == "CRITICAL"


def test_audit_fails_closed_on_client_error(monkeypatch):
    # An empty/odd response (no content[0]) raises IndexError, which the service
    # catches and converts into a fail-closed verdict.
    class _BoomMessages:
        async def create(self, **_kwargs):
            return SimpleNamespace(content=[], usage=SimpleNamespace(input_tokens=0, output_tokens=0))

    monkeypatch.setattr(audit_mod, "_get_async_client",
                        lambda: SimpleNamespace(messages=_BoomMessages()))
    result = run(audit_mod.audit_generated_diff(_finding(), "orig", "diff", "claude-haiku-4-5"))
    assert result["passed"] is False
    assert result["token_input"] == 0
