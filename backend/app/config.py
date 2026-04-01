"""
Nyx Configuration
All settings are driven by environment variables (12-factor app style).
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


def _parse_str_list(v: str, upper: bool = False) -> List[str]:
    """Parse a comma-separated or JSON list string."""
    v = v.strip()
    if v.startswith("["):
        import json
        items = json.loads(v)
    else:
        items = [i.strip() for i in v.split(",") if i.strip()]
    return [i.upper() if upper else i for i in items]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ─── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "Nyx"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    ENVIRONMENT: str = "development"  # Set to "production" to enable strict security checks
    HTTPS_ONLY: bool = False          # Reject non-HTTPS requests when True

    # ─── Database ────────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/nyx.db"

    # ─── GitHub ──────────────────────────────────────────────────────────────────
    GITHUB_TOKEN: str = ""
    GITHUB_WEBHOOK_ENDPOINT: str = ""
    GITHUB_APP_ID: str = ""
    GITHUB_PRIVATE_KEY_PATH: str = ""
    # When true, validate that GitHub webhook requests originate from GitHub's published IP ranges.
    GITHUB_WEBHOOK_IP_ALLOWLIST_ENABLED: bool = False

    # ─── Anthropic / AI ──────────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"
    # Maximum output tokens for AI fix generation (the Claude API max_tokens param is output-only).
    AI_MAX_OUTPUT_TOKENS: int = 8192
    AI_MAX_FILE_LINES: int = 500
    AI_MAX_RETRIES: int = 2
    # Per-call timeout (seconds) for Anthropic API requests.
    ANTHROPIC_TIMEOUT: float = 90.0
    # Minimum AI confidence score (0.0–1.0) for a fix to be auto-promoted to REVIEW.
    # Fixes below this threshold are placed in REVIEW_LOW_CONFIDENCE status.
    AI_MIN_CONFIDENCE_THRESHOLD: float = 0.4

    # ─── Nyx API Auth ────────────────────────────────────────────────────────────
    NYX_API_KEY: str = ""

    # ─── Secret key for at-rest encryption and audit HMAC chain ────────────────
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    NYX_SECRET_KEY: str = ""

    # ─── API key lifetime ─────────────────────────────────────────────────────
    # Maximum lifetime for API keys in days. 0 = no limit.
    API_KEY_MAX_LIFETIME_DAYS: int = 0

    # ─── Trusted Reverse Proxy CIDRs ─────────────────────────────────────────────
    # Comma-separated CIDR ranges of trusted reverse proxies (nginx, Cloudflare, ALB, etc.).
    # ONLY when a request arrives from one of these IPs will X-Forwarded-For be trusted
    # for IP extraction. Leaving this blank means X-Forwarded-For is NEVER trusted —
    # the raw TCP peer address is used instead, preventing IP spoofing in lockout logic.
    #
    # Examples:
    #   TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
    #   TRUSTED_PROXY_CIDRS=10.0.1.15/32
    TRUSTED_PROXY_CIDRS: str = ""

    # ─── Scan Submission Integrity ────────────────────────────────────────────────
    # When true, scan imports that omit the X-Nyx-Submission-HMAC header are rejected.
    # Set to false (default) for backward compatibility — the header is validated when
    # present but not required.
    REQUIRE_SUBMISSION_HMAC: bool = False

    # ─── CORS — stored as plain string, parsed via property ──────────────────────
    CORS_ORIGINS_STR: str = "http://localhost:5173,http://localhost:3000"

    @property
    def CORS_ORIGINS(self) -> List[str]:
        return _parse_str_list(self.CORS_ORIGINS_STR)

    # ─── Scanner Defaults ────────────────────────────────────────────────────────
    DEFAULT_ENABLED_SCANNERS_STR: str = "SEMGREP,BANDIT,TRIVY,GRYPE,CHECKOV"

    @property
    def DEFAULT_ENABLED_SCANNERS(self) -> List[str]:
        return _parse_str_list(self.DEFAULT_ENABLED_SCANNERS_STR, upper=True)

    # ─── EPSS API ────────────────────────────────────────────────────────────────
    EPSS_API_ENABLED: bool = True
    EPSS_API_BASE_URL: str = "https://api.first.org/data/v1/epss"

    # ─── SLA Targets (days) ──────────────────────────────────────────────────────
    SLA_CRITICAL_DAYS: int = 7
    SLA_HIGH_DAYS: int = 30
    SLA_MEDIUM_DAYS: int = 90
    SLA_LOW_DAYS: int = 180

    # ─── GitHub Code Scanning ────────────────────────────────────────────────────
    CODE_SCANNING_SYNC_ENABLED: bool = False   # Auto-poll GitHub Code Scanning API
    CODE_SCANNING_POLL_INTERVAL: int = 3600    # Seconds between polls (default: 1 hour)

    # ─── Jira ────────────────────────────────────────────────────────────────────
    JIRA_URL: str = ""                      # e.g. https://mycompany.atlassian.net
    JIRA_USER_EMAIL: str = ""               # Atlassian account email
    JIRA_API_TOKEN: str = ""                # Atlassian API token
    JIRA_DEFAULT_PROJECT_KEY: str = "SEC"   # Default project key for new tickets
    JIRA_ISSUE_TYPE: str = "Bug"            # Issue type: Bug, Task, Story, etc.
    JIRA_MOCK_MODE: bool = False            # Return mock responses (no real Jira needed)

    # ─── Snyk ────────────────────────────────────────────────────────────────────
    SNYK_WEBHOOK_SECRET: str = ""  # Set in Snyk dashboard → Integrations → Webhooks

    # ─── Global Webhook Signing ───────────────────────────────────────────────────
    # Optional global HMAC secret used as a pre-auth check before per-repo lookup.
    # Set this to any random string to prevent unauthenticated DB enumeration.
    NYX_WEBHOOK_SECRET: str = ""

    # ─── Notifications ───────────────────────────────────────────────────────────
    NOTIFICATION_WEBHOOK_URL: str = ""  # Outbound webhook (Slack-compatible)
    NOTIFY_ON_CRITICAL: bool = True

    # ─── Scan Schedules ──────────────────────────────────────────────────────────
    SCAN_SCHEDULES_ENABLED: bool = True   # Enable periodic scheduled scans

    # ─── SLA Policy Engine ───────────────────────────────────────────────────────
    SLA_CHECK_ENABLED: bool = True        # Enable hourly SLA breach escalation

    # ─── GitHub Check Runs ───────────────────────────────────────────────────────
    GITHUB_CHECK_RUNS_ENABLED: bool = True  # Post Check Run results on PRs


@lru_cache
def get_settings() -> Settings:
    return Settings()
