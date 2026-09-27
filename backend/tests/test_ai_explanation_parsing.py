"""ai_service._parse_explanation robustness (never crash; unusable confidence fails safe)."""
from __future__ import annotations

import asyncio

import pytest

from app.config import get_settings
from app.services import ai_service
from app.services.ai_service import _parse_explanation


@pytest.mark.parametrize("raw", ["[]", '"just a string"', "42", "null", '["explanation", 0.9]'])
def test_non_object_json_falls_back_instead_of_crashing(raw):
    explanation, summary, confidence = _parse_explanation(raw)
    assert explanation == raw
    assert summary == "fix: address security vulnerability"
    assert confidence == 0.5


@pytest.mark.parametrize("raw_conf", ["NaN", "Infinity", "-Infinity", '"high"', "null"])
def test_unusable_confidence_is_flagged_low(raw_conf):
    _, _, confidence = _parse_explanation(
        f'{{"explanation": "e", "fix_summary": "fix: x", "confidence": {raw_conf}}}'
    )
    assert confidence == 0.0
    assert confidence < get_settings().AI_MIN_CONFIDENCE_THRESHOLD


@pytest.mark.parametrize("raw_conf,expected", [("7", 1.0), ("-3", 0.0), ("0.83", 0.83)])
def test_confidence_is_clamped_to_unit_interval(raw_conf, expected):
    _, _, confidence = _parse_explanation(f'{{"confidence": {raw_conf}}}')
    assert confidence == expected


def test_missing_confidence_keeps_existing_default():
    assert _parse_explanation('{"explanation": "e"}')[2] == 0.7


def test_non_string_text_fields_are_coerced():
    explanation, summary, _ = _parse_explanation(
        '{"explanation": {"a": 1}, "fix_summary": ["x"], "confidence": 0.9}'
    )
    assert isinstance(explanation, str) and isinstance(summary, str)


def test_generate_fix_survives_array_explanation(monkeypatch):
    """End to end: a valid diff must not be discarded because the explanation call returned [] ."""
    from types import SimpleNamespace
    from app.models.finding import Finding
    monkeypatch.setattr(get_settings(), "ANTHROPIC_API_KEY", "test")
    replies = iter(["--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n", "[]"])

    class _Messages:
        async def create(self, **kw):
            return SimpleNamespace(content=[SimpleNamespace(text=next(replies))],
                                   usage=SimpleNamespace(input_tokens=1, output_tokens=1))
    monkeypatch.setattr(ai_service, "_get_async_client", lambda: SimpleNamespace(messages=_Messages()))
    f = Finding(id="f", title="t", rule_id="r", severity="HIGH", scanner="SEMGREP", description="d",
                file_path="app/x.py", line_start=1, cwe_ids=None, remediation_guidance=None)
    result = asyncio.run(ai_service.generate_fix(f, "x = 1\n", ""))
    assert "+x = 2" in result.fix_diff
    assert result.confidence == 0.5
