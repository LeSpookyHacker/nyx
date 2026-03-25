"""Scanner normalizer registry."""
from __future__ import annotations

from typing import Dict, Type

from app.services.normalization.bandit import BanditNormalizer
from app.services.normalization.base import AbstractNormalizer
from app.services.normalization.checkov import CheckovNormalizer
from app.services.normalization.code_scanning import CodeScanningNormalizer
from app.services.normalization.dependabot import DependabotNormalizer
from app.services.normalization.gitleaks import GitleaksNormalizer
from app.services.normalization.grype import GrypeNormalizer
from app.services.normalization.hadolint import HadolintNormalizer
from app.services.normalization.semgrep import SemgrepNormalizer
from app.services.normalization.snyk import SnykNormalizer
from app.services.normalization.trivy import TrivyNormalizer
from app.services.normalization.zap import ZapNormalizer

NORMALIZER_REGISTRY: Dict[str, Type[AbstractNormalizer]] = {
    "SEMGREP": SemgrepNormalizer,
    "ZAP": ZapNormalizer,
    "SNYK": SnykNormalizer,
    "TRIVY": TrivyNormalizer,
    "BANDIT": BanditNormalizer,
    "GRYPE": GrypeNormalizer,
    "CHECKOV": CheckovNormalizer,
    "CODE_SCANNING": CodeScanningNormalizer,
    "HADOLINT": HadolintNormalizer,
    "GITLEAKS": GitleaksNormalizer,
    "DEPENDABOT": DependabotNormalizer,
}


def get_normalizer(scanner: str) -> AbstractNormalizer:
    cls = NORMALIZER_REGISTRY.get(scanner.upper())
    if not cls:
        raise ValueError(f"No normalizer registered for scanner '{scanner}'")
    return cls()
