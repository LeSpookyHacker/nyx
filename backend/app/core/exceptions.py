"""Custom exception hierarchy for Nyx."""
from __future__ import annotations


class NyxError(Exception):
    """Base exception for all Nyx errors."""


class RepositoryNotFound(NyxError):
    pass


class FindingNotFound(NyxError):
    pass


class ScanNotFound(NyxError):
    pass


class RemediationNotFound(NyxError):
    pass


class GitHubError(NyxError):
    """Wraps errors from the GitHub API."""


class AIServiceError(NyxError):
    """Error from the Claude AI service."""


class NormalizationError(NyxError):
    """Failed to parse scanner output."""


class DuplicateSuppression(NyxError):
    pass
