"""Tests for Semgrep normalizer."""
import pytest
from app.services.normalization.semgrep import SemgrepNormalizer


SAMPLE_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "path": "app/db.py",
            "start": {"line": 42, "col": 4},
            "end": {"line": 42, "col": 60},
            "extra": {
                "message": "Detected possible formatted SQL query. Use parameterized queries instead.",
                "severity": "ERROR",
                "lines": "    cursor.execute(f'SELECT * FROM {table}')",
                "metadata": {
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021 - Injection"],
                    "severity": "high",
                },
            },
        }
    ]
}


def test_semgrep_normalizer_basic():
    normalizer = SemgrepNormalizer()
    findings = normalizer.normalize(SAMPLE_SEMGREP_OUTPUT)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "SEMGREP"
    assert f.severity == "HIGH"
    assert f.file_path == "app/db.py"
    assert f.line_start == 42
    assert "CWE-89" in f.cwe_ids
    assert f.code_snippet is not None


def test_semgrep_normalizer_empty():
    normalizer = SemgrepNormalizer()
    findings = normalizer.normalize({"results": []})
    assert findings == []


def test_semgrep_fingerprint():
    normalizer = SemgrepNormalizer()
    findings = normalizer.normalize(SAMPLE_SEMGREP_OUTPUT)
    fp1 = findings[0].fingerprint("repo-123")
    fp2 = findings[0].fingerprint("repo-123")
    fp3 = findings[0].fingerprint("repo-456")
    assert fp1 == fp2  # Deterministic
    assert fp1 != fp3  # Different repo = different fingerprint
