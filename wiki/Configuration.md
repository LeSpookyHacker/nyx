# Configuration Reference

> **The canonical list of every environment variable Nyx reads is the `Settings` class in [`backend/app/config.py`](../backend/app/config.py).** Every variable Nyx reads is declared there with its default, type, and validation. This page redirects to the right sources rather than duplicating the table, which drifted badly when it lived here.

---

## Where to look

| You want to… | Go to |
|---|---|
| See every env var grouped by subsystem (required, database, GitHub, JIRA, AI, security, notifications, logging) | **[`backend/app/config.py`](../backend/app/config.py)** — the `Settings` Pydantic model is the authoritative list |
| Understand how secrets are generated and validated on first run | **[Installation → Option A](Installation.md#option-a--one-command-setup-recommended)** |
| Know which variables are mandatory before Nyx will run at all | **[Installation → Option B (Manual setup)](Installation.md#option-b--manual-setup)** |
| Harden an instance before pointing the internet at it | **[Security Hardening](Security.md)** |
| Move from SQLite to PostgreSQL | **[Production Deployment → Switch to PostgreSQL](Deployment.md#1-switch-to-postgresql)** |

---

## Source of truth

- **`backend/app/config.py`** — the `Settings` Pydantic model. Every variable Nyx reads is declared here with its default. If the README disagrees with this file, the file wins.
- **`.env.example`** — the starter template `setup.sh` copies to `.env` on first run.
- **`docker-compose.yml`** / **`docker-compose.postgres.yml`** — the variables actually injected into the backend container.

---

## Adding a new variable

1. Declare it on `Settings` in `backend/app/config.py` with a sensible default.
2. Add it to `.env.example` with an explanatory comment.
3. Add a row to the relevant `<details>` block in the README's Configuration Reference section.
4. If it changes how a user *sets up* Nyx, also mention it in [Installation](Installation.md).
