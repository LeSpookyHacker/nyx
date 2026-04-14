# Adding a Scanner

Nyx's normalization layer is deliberately small — adding a new scanner is a single file plus a registry entry.

---

## The `AbstractNormalizer` interface

Every scanner normalizer lives in `backend/app/services/normalization/` and implements:

```python
class AbstractNormalizer(Protocol):
    scanner_name: ClassVar[str]           # e.g. "SEMGREP"

    def normalize(
        self,
        raw: dict,
        repo: Repository,
        scan_meta: ScanMeta,
    ) -> list[NormalizedFinding]: ...
```

`NormalizedFinding` is a dataclass with the unified shape Nyx persists. See `normalization/schemas.py` for the full definition.

---

## Walkthrough — adding Gitleaks

Suppose you want to add Gitleaks (secrets scanning). Three steps:

### 1. Write the normalizer

`backend/app/services/normalization/gitleaks.py`:

```python
from typing import ClassVar
from app.services.normalization.schemas import NormalizedFinding, Severity
from app.models.repository import Repository
from app.services.normalization.base import ScanMeta

class GitleaksNormalizer:
    scanner_name: ClassVar[str] = "GITLEAKS"

    def normalize(
        self,
        raw: list[dict],
        repo: Repository,
        scan_meta: ScanMeta,
    ) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for item in raw:
            findings.append(
                NormalizedFinding(
                    scanner="GITLEAKS",
                    rule_id=item["RuleID"],
                    severity=Severity.HIGH,  # Gitleaks does not grade
                    title=f"Secret detected: {item['Description']}",
                    description=item.get("Match", "")[:500],
                    file_path=item["File"],
                    line_start=item["StartLine"],
                    line_end=item["EndLine"],
                    cwe=798,  # Hard-coded credentials
                    raw=item,
                )
            )
        return findings
```

### 2. Register it

`backend/app/services/normalization/__init__.py`:

```python
from .gitleaks import GitleaksNormalizer

NORMALIZERS = {
    # ...existing entries...
    "GITLEAKS": GitleaksNormalizer(),
}
```

### 3. Test it

`backend/tests/services/normalization/test_gitleaks.py`:

```python
def test_gitleaks_normalizes_basic_output():
    raw = [{
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "Match": "AKIA...",
        "File": "src/config.py",
        "StartLine": 42,
        "EndLine": 42,
    }]
    findings = GitleaksNormalizer().normalize(raw, fake_repo(), fake_meta())
    assert len(findings) == 1
    assert findings[0].cwe == 798
    assert findings[0].scanner == "GITLEAKS"
```

Run it:

```bash
cd backend
pytest tests/services/normalization/test_gitleaks.py -xvs
```

Done. The scanner is now a first-class citizen — `POST /scans/import-json` with `scanner: "GITLEAKS"` will route to your normalizer, dedup, score, and surface the findings like any other.

---

## Design notes

### Fingerprinting

Deduplication uses `(repository, file, line_start, rule_id, content_hash)` by default. If your scanner's rule IDs are unstable (e.g., hash-based), override `fingerprint()` on your normalizer to produce a stable identifier.

### Severity mapping

Normalize scanner-specific severity strings to the `Severity` enum: `CRITICAL | HIGH | MEDIUM | LOW | INFO`. When the scanner doesn't provide severity, pick a conservative default (HIGH for secrets, MEDIUM for style).

### CWE mapping

CWE is how Nyx maps findings to compliance controls. If your scanner doesn't emit CWE, maintain a `RULE_ID → CWE` lookup in the normalizer.

### CVE / EPSS enrichment

Dependency scanners (SCA) should emit CVE IDs. Nyx enriches those with EPSS scores automatically via the `enrichment_service` — you don't need to do it in the normalizer.

---

## Adding the scanner to auto-detection

Optional but nice: teach the scanner detection service which files imply your scanner is useful.

`backend/app/services/scanner_detection_service.py`:

```python
SCANNER_HEURISTICS = {
    # ...existing...
    "GITLEAKS": [
        # Git repos with any code benefit from secrets scanning
        FileExists(".git"),
    ],
}
```

---

## Adding the scanner to the CI workflow template

Optional: if you want **Push Workflow** to include your scanner, update `templates/nyx-scan.yml.j2` to add a job that runs it and pushes results.

---

## What next

- **Run your new scanner in CI →** [CI/CD Integration](CICD-Integration.md)
- **See other normalizers for reference →** `backend/app/services/normalization/*.py`
