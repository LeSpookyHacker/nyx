"""Tests for Bandit normalizer."""
from app.services.normalization.bandit import BanditNormalizer

SAMPLE_BANDIT_OUTPUT = {
    "results": [
        {
            "filename": "app/auth.py",
            "test_id": "B303",
            "test_name": "blacklist",
            "issue_text": "Use of MD5 or SHA1 hash function.",
            "issue_severity": "MEDIUM",
            "issue_confidence": "HIGH",
            "line_number": 15,
            "line_range": [15, 15],
            "code": "    hashed = hashlib.md5(password).hexdigest()",
            "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
        }
    ]
}


def test_bandit_normalizer_basic():
    normalizer = BanditNormalizer()
    findings = normalizer.normalize(SAMPLE_BANDIT_OUTPUT)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "BANDIT"
    assert f.severity == "MEDIUM"
    assert f.file_path == "app/auth.py"
    assert f.line_start == 15
    assert "CWE-327" in f.cwe_ids


def test_bandit_exploitability():
    """HIGH severity + HIGH confidence = exploitable."""
    data = {
        "results": [{
            "filename": "app/cmd.py",
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "issue_text": "subprocess call with shell=True identified",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "line_number": 5,
            "code": "subprocess.Popen(cmd, shell=True)",
            "issue_cwe": {},
        }]
    }
    normalizer = BanditNormalizer()
    findings = normalizer.normalize(data)
    assert findings[0].is_exploitable is True
