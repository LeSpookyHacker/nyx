"""Shared pytest fixtures.

Sets a fresh in-memory SQLite DB + deterministic secrets before the app
(and its settings cache) is imported, so tests run in full isolation from
whatever `.env` the developer has locally.
"""
from __future__ import annotations

import os
import tempfile

# Must be set before any `app.*` import so the settings cache picks them up.
_tmp = tempfile.NamedTemporaryFile(prefix="nyx-test-", suffix=".db", delete=False)
_tmp.close()
# Force-override any values coming from a developer .env — tests must be hermetic.
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp.name}"
os.environ["NYX_API_KEY"] = "nyx-test-bootstrap-key"
os.environ["NYX_SECRET_KEY"] = "a" * 64
os.environ["NYX_WEBHOOK_SECRET"] = "b" * 64
os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["GITHUB_TOKEN"] = ""
os.environ["GITHUB_WEBHOOK_ENDPOINT"] = ""
os.environ["ENVIRONMENT"] = "development"
os.environ["HTTPS_ONLY"] = "false"
