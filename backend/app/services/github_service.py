"""
GitHub Service — wraps PyGithub for all GitHub API interactions.

Responsibilities:
  - Registering/removing webhooks on repositories
  - Fetching file content for AI fix context
  - Creating branches and pull requests with AI-generated fixes
  - Polling PR status and deployment environments
  - Creating Check Runs for PR security annotations

Note: PyGithub is a synchronous library. All blocking calls are wrapped with
asyncio.to_thread() to avoid blocking the FastAPI event loop.
"""
from __future__ import annotations

import asyncio
import ast
import base64
import difflib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from github import Github, GithubException
from github.Repository import Repository as GHRepo

from app.config import get_settings
from app.core.exceptions import GitHubError
from app.core.security import generate_webhook_secret

settings = get_settings()

# ── Pinned versions ───────────────────────────────────────────────────────────
# Single source of truth for everything pinned in the generated workflow.
# The background loop in main.py refreshes these weekly and re-pushes the
# workflow to all onboarded repos when a newer release is found.

# GitHub Actions pins — referenced by commit SHA for supply-chain safety.
PINNED_ACTIONS: dict[str, dict[str, str]] = {
    "zaproxy/action-baseline": {
        "sha": "de8ad967d3548d44ef623df22cf95c3b0baf8b25",
        "tag": "v0.15.0",
    },
    "aquasecurity/trivy-action": {
        "sha": "57a97c7e7821a5776cebc9bb87c984fa69cba8f1",
        "tag": "v0.35.0",
    },
}

# Binary tool pins — downloaded directly in shell steps by version tag.
PINNED_TOOLS: dict[str, str] = {
    "gitleaks/gitleaks": "v8.30.1",
    "hadolint/hadolint": "v2.14.0",
}


async def _resolve_tag_sha(client: httpx.AsyncClient, repo: str, tag: str) -> str | None:
    """Return the commit SHA for a tag, dereferencing annotated tag objects."""
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    ref_resp = await client.get(
        f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}",
        headers=headers, timeout=10,
    )
    if ref_resp.status_code != 200:
        return None
    obj = ref_resp.json()["object"]
    if obj["type"] == "commit":
        return obj["sha"]
    # Annotated tag — dereference to the commit
    tag_resp = await client.get(
        f"https://api.github.com/repos/{repo}/git/tags/{obj['sha']}",
        headers=headers, timeout=10,
    )
    if tag_resp.status_code != 200:
        return None
    return tag_resp.json()["object"]["sha"]


async def refresh_pinned_actions() -> list[str]:
    """
    Check GitHub for newer releases of every pinned action and binary tool.
    Updates PINNED_ACTIONS and PINNED_TOOLS in place.
    Returns the names of everything that changed so the caller can re-push workflows.
    """
    if not settings.GITHUB_TOKEN:
        return []

    updated: list[str] = []
    log = __import__("logging").getLogger("nyx.github")
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient() as client:
        # ── GitHub Actions (SHA-pinned) ───────────────────────────────────────
        for action, pin in PINNED_ACTIONS.items():
            try:
                rel_resp = await client.get(
                    f"https://api.github.com/repos/{action}/releases/latest",
                    headers=headers, timeout=10,
                )
                if rel_resp.status_code != 200:
                    continue
                latest_tag = rel_resp.json().get("tag_name", "")
                if not latest_tag or latest_tag == pin["tag"]:
                    continue
                sha = await _resolve_tag_sha(client, action, latest_tag)
                if not sha:
                    continue
                log.info("Pinned action update: %s %s → %s (%s)", action, pin["tag"], latest_tag, sha[:12])
                PINNED_ACTIONS[action]["sha"] = sha
                PINNED_ACTIONS[action]["tag"] = latest_tag
                updated.append(action)
            except Exception:
                log.debug("Failed to check latest release for %s", action, exc_info=True)

        # ── Binary tools (version-pinned) ─────────────────────────────────────
        for repo, current_tag in PINNED_TOOLS.items():
            try:
                rel_resp = await client.get(
                    f"https://api.github.com/repos/{repo}/releases/latest",
                    headers=headers, timeout=10,
                )
                if rel_resp.status_code != 200:
                    continue
                latest_tag = rel_resp.json().get("tag_name", "")
                if not latest_tag or latest_tag == current_tag:
                    continue
                log.info("Pinned tool update: %s %s → %s", repo, current_tag, latest_tag)
                PINNED_TOOLS[repo] = latest_tag
                updated.append(repo)
            except Exception:
                log.debug("Failed to check latest release for %s", repo, exc_info=True)

    return updated


async def push_workflow_to_all_repos(db) -> int:
    """
    Re-push the generated nyx-scan.yml to every active repo.
    Called after pinned actions are updated. Returns the count of repos updated.
    """
    from sqlalchemy import select
    from app.models.repository import Repository

    result = await db.execute(
        select(Repository).where(Repository.webhook_active.is_(True))
    )
    repos = result.scalars().all()

    count = 0
    for repo in repos:
        try:
            await push_nyx_workflow(repo.github_full_name, str(repo.id), repo.default_branch)
            count += 1
        except Exception:
            import logging
            logging.getLogger("nyx.github").warning(
                "Failed to update workflow for %s", repo.github_full_name, exc_info=True,
            )
    return count


def _get_client() -> Github:
    """Return a synchronous PyGithub client. Callers must use asyncio.to_thread()."""
    if not settings.GITHUB_TOKEN:
        raise GitHubError("GITHUB_TOKEN is not configured")
    return Github(settings.GITHUB_TOKEN)


def generate_nyx_workflow(repo_id: str) -> str:
    """
    Generate the canonical nyx-scan.yml workflow content for a repository.

    The workflow is self-detecting: most scanner steps include hashFiles()
    or env-var conditions so they activate automatically when relevant files
    appear — no re-push needed.

    Required GitHub settings:
      vars.NYX_URL        — Nyx public URL (no trailing slash)
      secrets.NYX_API_KEY — Nyx API key

    Optional:
      vars.NYX_ZAP_TARGET  — full URL for DAST scan (e.g. https://myapp.com)
      secrets.SNYK_TOKEN   — enables Snyk SCA step
    """
    return f"""\
name: Nyx Security Scan

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  nyx-scan:
    name: Nyx Security Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Gitleaks needs full history to scan all commits

      # ── Semgrep (SAST) ────────────────────────────────────────────────────────
      - name: Run Semgrep
        run: |
          pip install semgrep --quiet
          semgrep --config=p/javascript --config=p/secrets --config=p/security-audit \\
            --json --output semgrep.json . || true

      - name: Report Semgrep → Nyx
        if: hashFiles('semgrep.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
          NYX_WEBHOOK_SECRET: ${{{{ secrets.NYX_WEBHOOK_SECRET }}}}
        run: |
          NYX_URL="${{NYX_URL// /}}"
          jq -cn \\
            --arg repo    "{repo_id}" \\
            --arg scanner "SEMGREP" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d semgrep.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
            > /tmp/nyx_payload.json
          HMAC=$(openssl dgst -sha256 -hmac "${{NYX_WEBHOOK_SECRET}}" /tmp/nyx_payload.json \\
            | awk '{{print $NF}}')
          curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
              -H "ngrok-skip-browser-warning: true" \\
              --data-binary @/tmp/nyx_payload.json
          echo "✓ Semgrep results sent to Nyx"

      # ── Gitleaks (Secrets) — always runs ─────────────────────────────────────
      - name: Run Gitleaks
        run: |
          GITLEAKS_VERSION="{PINNED_TOOLS["gitleaks/gitleaks"]}"
          GITLEAKS_ARCHIVE="gitleaks_${{GITLEAKS_VERSION#v}}_linux_x64.tar.gz"
          BASE_URL="https://github.com/gitleaks/gitleaks/releases/download/$GITLEAKS_VERSION"
          curl -sSfL "$BASE_URL/$GITLEAKS_ARCHIVE" -o "$GITLEAKS_ARCHIVE"
          curl -sSfL "$BASE_URL/gitleaks_${{GITLEAKS_VERSION#v}}_checksums.txt" -o gitleaks_checksums.txt
          grep "$GITLEAKS_ARCHIVE" gitleaks_checksums.txt | sha256sum --check --status || \\
            {{ echo "::error::Gitleaks checksum verification FAILED"; exit 1; }}
          tar -xz -f "$GITLEAKS_ARCHIVE" gitleaks
          ./gitleaks detect --source . --report-format json \\
            --report-path gitleaks.json --exit-code 0 || true

      - name: Report Gitleaks → Nyx
        if: hashFiles('gitleaks.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
          NYX_WEBHOOK_SECRET: ${{{{ secrets.NYX_WEBHOOK_SECRET }}}}
        run: |
          COUNT=$(jq 'if type == "array" then length else 0 end' gitleaks.json 2>/dev/null || echo 0)
          if [ "$COUNT" -eq 0 ]; then echo "✓ Gitleaks: no secrets found"; exit 0; fi
          NYX_URL="${{NYX_URL// /}}"
          jq -cn \\
            --arg repo    "{repo_id}" \\
            --arg scanner "GITLEAKS" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d gitleaks.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
            > /tmp/nyx_payload.json
          HMAC=$(openssl dgst -sha256 -hmac "${{NYX_WEBHOOK_SECRET}}" /tmp/nyx_payload.json \\
            | awk '{{print $NF}}')
          curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
              -H "ngrok-skip-browser-warning: true" \\
              --data-binary @/tmp/nyx_payload.json
          echo "✓ Gitleaks: $COUNT secret(s) sent to Nyx"

      # ── Hadolint (Dockerfile linting) — auto-activates when Dockerfile exists ─
      - name: Run Hadolint
        if: hashFiles('**/Dockerfile', '**/Dockerfile.*') != ''
        run: |
          HADOLINT_VERSION="{PINNED_TOOLS["hadolint/hadolint"]}"
          HADOLINT_BIN="hadolint-Linux-x86_64"
          BASE_URL="https://github.com/hadolint/hadolint/releases/download/$HADOLINT_VERSION"
          wget -qO /usr/local/bin/hadolint "$BASE_URL/$HADOLINT_BIN"
          wget -qO /tmp/hadolint.sha256 "$BASE_URL/$HADOLINT_BIN.sha256"
          EXPECTED=$(cat /tmp/hadolint.sha256 | awk '{{print $1}}')
          ACTUAL=$(sha256sum /usr/local/bin/hadolint | awk '{{print $1}}')
          [ "$EXPECTED" = "$ACTUAL" ] || \\
            {{ echo "::error::Hadolint checksum verification FAILED"; exit 1; }}
          chmod +x /usr/local/bin/hadolint
          find . \\( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.dockerfile' \\) \\
            | head -20 | xargs hadolint --format json 2>/dev/null > hadolint.json || true

      - name: Report Hadolint → Nyx
        if: hashFiles('hadolint.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
          NYX_WEBHOOK_SECRET: ${{{{ secrets.NYX_WEBHOOK_SECRET }}}}
        run: |
          COUNT=$(jq 'if type == "array" then length else 0 end' hadolint.json 2>/dev/null || echo 0)
          if [ "$COUNT" -eq 0 ]; then echo "✓ Hadolint: no issues found"; exit 0; fi
          NYX_URL="${{NYX_URL// /}}"
          jq -cn \\
            --arg repo    "{repo_id}" \\
            --arg scanner "HADOLINT" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d hadolint.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
            > /tmp/nyx_payload.json
          HMAC=$(openssl dgst -sha256 -hmac "${{NYX_WEBHOOK_SECRET}}" /tmp/nyx_payload.json \\
            | awk '{{print $NF}}')
          curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
              -H "ngrok-skip-browser-warning: true" \\
              --data-binary @/tmp/nyx_payload.json
          echo "✓ Hadolint: $COUNT issue(s) sent to Nyx"

      # ── Snyk (SCA) — activates when SNYK_TOKEN secret is set ─────────────────
      - name: Run Snyk
        env:
          SNYK_TOKEN: ${{{{ secrets.SNYK_TOKEN }}}}
        run: |
          if [ -z "$SNYK_TOKEN" ]; then
            echo "⏭ SNYK_TOKEN not set — skipping Snyk (add it to repo secrets to enable)"
            exit 0
          fi
          npm install -g snyk --quiet
          snyk test --json --all-projects > snyk.json 2>/dev/null || true
          echo "Snyk scan complete"

      - name: Report Snyk → Nyx
        if: hashFiles('snyk.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
          NYX_WEBHOOK_SECRET: ${{{{ secrets.NYX_WEBHOOK_SECRET }}}}
          SNYK_TOKEN: ${{{{ secrets.SNYK_TOKEN }}}}
        run: |
          if [ -z "$SNYK_TOKEN" ]; then exit 0; fi
          NYX_URL="${{NYX_URL// /}}"
          jq -cn \\
            --arg repo    "{repo_id}" \\
            --arg scanner "SNYK" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d snyk.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
            > /tmp/nyx_payload.json
          HMAC=$(openssl dgst -sha256 -hmac "${{NYX_WEBHOOK_SECRET}}" /tmp/nyx_payload.json \\
            | awk '{{print $NF}}')
          curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
              -H "ngrok-skip-browser-warning: true" \\
              --data-binary @/tmp/nyx_payload.json
          echo "✓ Snyk results sent to Nyx"

      # ── Trivy (SCA + IaC + Container) ────────────────────────────────────────
      - name: Run Trivy
        if: always()  # Run even if ZAP failed
        uses: aquasecurity/trivy-action@{PINNED_ACTIONS["aquasecurity/trivy-action"]["sha"]}  # {PINNED_ACTIONS["aquasecurity/trivy-action"]["tag"]}
        with:
          scan-type: "fs"
          format: "json"
          output: "trivy.json"
          exit-code: "0"

      - name: Report Trivy → Nyx
        if: always() && hashFiles('trivy.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
          NYX_WEBHOOK_SECRET: ${{{{ secrets.NYX_WEBHOOK_SECRET }}}}
        run: |
          NYX_URL="${{NYX_URL// /}}"
          jq -cn \\
            --arg repo    "{repo_id}" \\
            --arg scanner "TRIVY" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d trivy.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
            > /tmp/nyx_payload.json
          HMAC=$(openssl dgst -sha256 -hmac "${{NYX_WEBHOOK_SECRET}}" /tmp/nyx_payload.json \\
            | awk '{{print $NF}}')
          curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
              -H "ngrok-skip-browser-warning: true" \\
              --data-binary @/tmp/nyx_payload.json
          echo "✓ Trivy results sent to Nyx"

      # ── SBOM (CycloneDX via Trivy) ────────────────────────────────────────────
      - name: Generate SBOM (CycloneDX)
        if: always()
        run: trivy fs --format cyclonedx --output sbom-cdx.json . || true

      - name: Submit SBOM → Nyx
        if: always() && hashFiles('sbom-cdx.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
        run: |
          NYX_URL="${{NYX_URL// /}}"
          jq -cn \\
            --arg ref "$GITHUB_REF_NAME" \\
            --slurpfile s sbom-cdx.json \\
            '{{"git_ref":$ref,"sbom":$s[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/sbom/repositories/{repo_id}/submit" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
          echo "✓ SBOM submitted to Nyx"

  # ── ZAP (DAST — optional, isolated job) ────────────────────────────────────
  # Runs in its own job so a ZAP action version problem or scan failure can
  # never prevent Semgrep, Gitleaks, Trivy, or SBOM from reporting to Nyx.
  # Enable by setting vars.NYX_ZAP_TARGET to your deployed app URL.
  nyx-zap:
    name: Nyx ZAP DAST Scan
    runs-on: ubuntu-latest
    if: vars.NYX_ZAP_TARGET != ''
    permissions:
      contents: read
    continue-on-error: true  # job-level: ZAP never marks the overall workflow as failed

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Fix workspace permissions for ZAP container
        run: |
          mkdir -p zap-wrk
          chmod -R 777 zap-wrk

      - name: Run ZAP Baseline Scan
        continue-on-error: true
        uses: zaproxy/action-baseline@{PINNED_ACTIONS["zaproxy/action-baseline"]["sha"]}  # {PINNED_ACTIONS["zaproxy/action-baseline"]["tag"]}
        with:
          target: ${{{{ vars.NYX_ZAP_TARGET }}}}
          cmd_options: '-m 3 -a -J zap.json'
          allow_issue_writing: false
          fail_action: false

      - name: Report ZAP → Nyx
        if: always() && hashFiles('zap.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
          NYX_WEBHOOK_SECRET: ${{{{ secrets.NYX_WEBHOOK_SECRET }}}}
        run: |
          NYX_URL="${{NYX_URL// /}}"
          SITE_COUNT=$(jq '.site | length' zap.json 2>/dev/null || echo 0)
          if [ "$SITE_COUNT" -eq 0 ]; then
            echo "⚠ ZAP returned no site data — skipping submission"
            exit 0
          fi
          jq -cn \\
            --arg repo    "{repo_id}" \\
            --arg scanner "ZAP" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d zap.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
            > /tmp/nyx_payload.json
          HMAC=$(openssl dgst -sha256 -hmac "${{NYX_WEBHOOK_SECRET}}" /tmp/nyx_payload.json \\
            | awk '{{print $NF}}')
          curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "X-Nyx-Submission-HMAC: sha256=$HMAC" \\
              -H "ngrok-skip-browser-warning: true" \\
              --data-binary @/tmp/nyx_payload.json
          echo "✓ ZAP results sent to Nyx ($SITE_COUNT site(s) scanned)"
"""


async def push_nyx_workflow(repo_full_name: str, repo_id: str, default_branch: str = "main") -> dict:
    """
    Create or update .github/workflows/nyx-scan.yml in the repository.
    Returns a dict with 'created' (bool) and 'html_url' (str).
    """
    if not settings.GITHUB_TOKEN:
        raise GitHubError("GITHUB_TOKEN is not configured")

    content = generate_nyx_workflow(repo_id)
    encoded = base64.b64encode(content.encode()).decode()
    path = ".github/workflows/nyx-scan.yml"
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient() as client:
        # Check if the file already exists (need its SHA to update)
        get_resp = await client.get(url, headers=headers, timeout=10)
        sha: Optional[str] = None
        if get_resp.status_code == 200:
            sha = get_resp.json().get("sha")

        payload: Dict[str, Any] = {
            "message": "chore: update Nyx security scan workflow",
            "content": encoded,
            "branch": default_branch,
        }
        if sha:
            payload["sha"] = sha

        put_resp = await client.put(url, json=payload, headers=headers, timeout=15)

    if put_resp.status_code not in (200, 201):
        raise GitHubError(f"Failed to push workflow: {put_resp.status_code} {put_resp.text[:200]}")

    data = put_resp.json()
    return {
        "created": put_resp.status_code == 201,
        "html_url": data.get("content", {}).get("html_url", ""),
    }


async def get_repository_info(full_name: str) -> dict:
    """Fetch basic metadata for a GitHub repository."""
    def _sync():
        g = _get_client()
        repo = g.get_repo(full_name)
        return {
            "github_repo_id": repo.id,
            "default_branch": repo.default_branch,
            "description": repo.description or "",
            "language": repo.language,
            "is_private": repo.private,
        }
    try:
        return await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to fetch repo info for {full_name}: {e}") from e


async def register_webhook(repo_full_name: str) -> Tuple[int, str]:
    """
    Register a Nyx webhook on the GitHub repository.
    Returns (webhook_id, webhook_secret).
    """
    if not settings.GITHUB_WEBHOOK_ENDPOINT:
        raise GitHubError(
            "GITHUB_WEBHOOK_ENDPOINT is not configured. Set it to your public Nyx URL."
        )
    secret = generate_webhook_secret()

    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        hook = repo.create_hook(
            name="web",
            config={
                "url": f"{settings.GITHUB_WEBHOOK_ENDPOINT}",
                "content_type": "json",
                "secret": secret,
                "insecure_ssl": "0",
            },
            events=["push", "pull_request", "check_run", "check_suite"],
            active=True,
        )
        return hook.id

    try:
        hook_id = await asyncio.to_thread(_sync)
        return hook_id, secret
    except GithubException as e:
        raise GitHubError(f"Failed to register webhook for {repo_full_name}: {e}") from e


async def remove_webhook(repo_full_name: str, webhook_id: int) -> None:
    """Remove the Nyx webhook from a repository."""
    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        hook = repo.get_hook(webhook_id)
        hook.delete()

    try:
        await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to remove webhook: {e}") from e


async def get_file_content(repo_full_name: str, file_path: str, ref: str = "") -> str:
    """Fetch the content of a file from a GitHub repository."""
    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        kwargs = {"ref": ref} if ref else {}
        contents = repo.get_contents(file_path, **kwargs)
        if isinstance(contents, list):
            raise GitHubError(f"{file_path} is a directory, not a file")
        return base64.b64decode(contents.content).decode("utf-8", errors="replace")

    try:
        return await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to fetch {file_path} from {repo_full_name}: {e}") from e


async def list_directory(repo_full_name: str, dir_path: str, ref: str = "") -> list[str]:
    """Return sorted list of entry names in a repository directory. Returns [] on any error."""
    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        kwargs = {"ref": ref} if ref else {}
        contents = repo.get_contents(dir_path or ".", **kwargs)
        if isinstance(contents, list):
            return sorted(item.name for item in contents)
        return []
    try:
        return await asyncio.to_thread(_sync)
    except Exception:
        return []


async def create_fix_pr(
    repo_full_name: str,
    file_path: str,
    original_content: str,
    fixed_content: str,
    branch_name: str,
    pr_title: str,
    pr_body: str,
    base_branch: str,
    draft: bool = False,
) -> Tuple[int, str]:
    """
    Create a branch with the fixed file and open a pull request.
    Returns (pr_number, pr_url).

    When draft=True the PR is opened as a GitHub draft — it cannot be merged
    until a human explicitly marks it ready for review. Auto PR Mode always
    uses draft=True so a human owns the merge decision.
    """
    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)

        # Get the SHA of the base branch HEAD
        base_ref = repo.get_branch(base_branch)
        base_sha = base_ref.commit.sha

        # Create the fix branch
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_sha)

        # Update the file on the fix branch
        existing = repo.get_contents(file_path, ref=base_branch)
        repo.update_file(
            path=file_path,
            message=f"fix: apply Nyx AI remediation for {file_path}",
            content=fixed_content,
            sha=existing.sha,
            branch=branch_name,
        )

        # Create the PR
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=base_branch,
            draft=draft,
        )
        labels = ["nyx-remediation", "security"]
        if draft:
            labels.append("nyx-auto-pr")
        try:
            pr.add_to_labels(*labels)
        except GithubException:
            pass  # Labels may not exist; non-fatal

        return pr.number, pr.html_url

    try:
        return await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to create fix PR for {repo_full_name}: {e}") from e


async def create_advisory_issue(
    repo_full_name: str,
    title: str,
    body: str,
    labels: Optional[List[str]] = None,
) -> Tuple[int, str]:
    """
    Create a GitHub Issue to track a security finding that cannot be auto-fixed with a code diff.
    Returns (issue_number, issue_url).

    Used by Auto PR Mode for SCA / CONTAINER / IAC findings that have no file_path.
    The issue body contains AI-generated step-by-step remediation guidance.
    """
    def _sync() -> Tuple[int, str]:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        issue_labels = labels or ["nyx-advisory", "security"]
        issue = repo.create_issue(title=title, body=body)
        try:
            issue.add_to_labels(*issue_labels)
        except GithubException:
            pass  # Labels may not exist — non-fatal
        return issue.number, issue.html_url

    try:
        return await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to create advisory issue for {repo_full_name}: {e}") from e


async def get_branch_head_sha(repo_full_name: str, branch_name: str) -> Optional[str]:
    """
    Return the HEAD commit SHA of a branch, sourced from the GitHub API.

    The Auto PR worker uses this (not any finding-supplied value) as the SHA it
    polls check-runs against, so the polling target is always a commit Nyx created.
    """
    def _sync() -> Optional[str]:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        return repo.get_branch(branch_name).commit.sha

    try:
        return await asyncio.to_thread(_sync)
    except GithubException:
        return None


async def wait_for_check_run(
    repo_full_name: str,
    sha: str,
    timeout_seconds: int = 600,
    poll_interval_seconds: int = 15,
) -> dict:
    """
    Poll the target repository's own CI check-runs for a commit SHA.

    Returns a dict: {
        "found": bool,             # any check runs exist for the SHA
        "completed": bool,         # all runs completed before the deadline
        "conclusion": str | None,  # overall conclusion ("success" if all succeeded, else first non-success)
        "check_run_id": int | None,
        "details": str | None,     # names/conclusions of failing runs, for annotation
    }
    """
    def _poll() -> dict:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        commit = repo.get_commit(sha)
        runs = list(commit.get_check_runs())
        if not runs:
            return {"found": False, "completed": False, "conclusion": None,
                    "check_run_id": None, "details": None}
        all_completed = all(r.status == "completed" for r in runs)
        first_id = runs[0].id
        if not all_completed:
            return {"found": True, "completed": False, "conclusion": None,
                    "check_run_id": first_id, "details": None}
        failing = [r for r in runs if r.conclusion not in ("success", "neutral", "skipped")]
        if failing:
            details = "; ".join(f"{r.name}: {r.conclusion}" for r in failing)[:1000]
            return {"found": True, "completed": True, "conclusion": failing[0].conclusion,
                    "check_run_id": first_id, "details": details}
        return {"found": True, "completed": True, "conclusion": "success",
                "check_run_id": first_id, "details": None}

    deadline = asyncio.get_event_loop().time() + timeout_seconds
    last: dict = {"found": False, "completed": False, "conclusion": None,
                  "check_run_id": None, "details": None}
    while True:
        try:
            last = await asyncio.to_thread(_poll)
        except GithubException as e:
            import logging
            logging.getLogger("nyx.github").debug("check-run poll failed: %s", e)
        if last["completed"]:
            return last
        if asyncio.get_event_loop().time() >= deadline:
            return last  # timed out — caller decides whether to block (AUTO_PR_BLOCK_ON_TIMEOUT)
        await asyncio.sleep(poll_interval_seconds)


async def add_pr_comment(repo_full_name: str, pr_number: int, body: str) -> bool:
    """Post an issue comment on a PR (best-effort). Used for the Auto PR test-results annotation."""
    def _sync() -> bool:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        repo.get_pull(pr_number).create_issue_comment(body)
        return True

    try:
        return await asyncio.to_thread(_sync)
    except GithubException:
        return False


async def trigger_workflow_dispatch(repo_full_name: str, workflow_file: str = "nyx-scan.yml", ref: str = "main") -> bool:
    """
    Trigger a workflow_dispatch event on a GitHub Actions workflow.
    Returns True on success, raises GitHubError on failure.
    """
    if not settings.GITHUB_TOKEN:
        raise GitHubError("GITHUB_TOKEN is not configured")
    url = f"https://api.github.com/repos/{repo_full_name}/actions/workflows/{workflow_file}/dispatches"
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            json={"ref": ref},
            headers={
                "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15,
        )
    if resp.status_code == 204:
        return True
    raise GitHubError(f"workflow_dispatch failed: {resp.status_code} {resp.text}")


async def merge_pr(repo_full_name: str, pr_number: int, branch_name: str) -> bool:
    """
    Merge a pull request and delete the source branch.
    Returns True on success, raises GitHubError on failure.
    """
    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        result = pr.merge(merge_method="squash")
        if result.merged:
            try:
                ref = repo.get_git_ref(f"heads/{branch_name}")
                ref.delete()
            except GithubException:
                pass  # Branch cleanup is best-effort
        return result.merged

    try:
        return await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to merge PR #{pr_number}: {e}") from e


async def get_pr_status(repo_full_name: str, pr_number: int) -> dict:
    """Return current PR state and merged status."""
    def _sync():
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        return {
            "state": pr.state,
            "merged": pr.merged,
            "merged_at": pr.merged_at,
            "deployment_url": None,
        }

    try:
        return await asyncio.to_thread(_sync)
    except GithubException as e:
        raise GitHubError(f"Failed to get PR status: {e}") from e


async def create_check_run(repo_full_name: str, head_sha: str, name: str = "Nyx Security") -> Optional[int]:
    """Create a pending GitHub Check Run. Returns check_run_id or None on failure."""
    if not settings.GITHUB_TOKEN:
        return None
    try:
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"token {settings.GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10.0,
        ) as c:
            resp = await c.post(f"/repos/{repo_full_name}/check-runs", json={
                "name": name,
                "head_sha": head_sha,
                "status": "in_progress",
                "started_at": datetime.now(timezone.utc).isoformat(),
            })
            if resp.status_code in (200, 201):
                return resp.json().get("id")
    except (httpx.HTTPError, KeyError) as exc:
        import logging
        logging.getLogger("nyx.github").debug("Check run creation failed: %s", exc)
    return None


async def complete_check_run(
    repo_full_name: str,
    check_run_id: int,
    conclusion: str,
    summary: str,
    annotations: List[Dict[str, Any]],
) -> None:
    """Update a GitHub Check Run with results and inline annotations."""
    if not settings.GITHUB_TOKEN or not check_run_id:
        return
    try:
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"token {settings.GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10.0,
        ) as c:
            await c.patch(f"/repos/{repo_full_name}/check-runs/{check_run_id}", json={
                "status": "completed",
                "conclusion": conclusion,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "output": {
                    "title": "Nyx Security Scan Results",
                    "summary": summary,
                    # GitHub allows max 50 annotations per request
                    "annotations": annotations[:50],
                },
            })
    except (httpx.HTTPError, KeyError) as exc:
        import logging
        logging.getLogger("nyx.github").debug("Check run completion failed: %s", exc)


def _fix_hunk_headers(diff: str) -> str:
    """
    Recount actual source/target lines in each hunk and rewrite the @@ header.
    Claude occasionally emits wrong line counts which cause unidiff to reject
    an otherwise valid diff.
    """
    import re
    result: list[str] = []
    i = 0
    lines = diff.split("\n")
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$", line)
        if m:
            src_start, tgt_start, rest = m.group(1), m.group(2), m.group(3)
            i += 1
            hunk: list[str] = []
            while i < len(lines) and not re.match(r"^(@@|--- |\+\+\+ )", lines[i]):
                hunk.append(lines[i])
                i += 1
            src_count = sum(1 for l in hunk if l.startswith(" ") or l.startswith("-"))
            tgt_count = sum(1 for l in hunk if l.startswith(" ") or l.startswith("+"))
            result.append(f"@@ -{src_start},{src_count} +{tgt_start},{tgt_count} @@{rest}")
            result.extend(hunk)
        else:
            result.append(line)
            i += 1
    return "\n".join(result)


def apply_unified_diff(original: str, diff: str) -> Optional[str]:
    """
    Apply a unified diff string to original file content.
    Returns the modified content, or None if patch cannot be applied cleanly.

    Uses fuzzy line matching (±FUZZ lines) so minor offsets between the diff
    and the actual file do not cause a hard failure.
    """
    FUZZ = 10  # lines of tolerance around the expected hunk position

    try:
        import unidiff
        patch = unidiff.PatchSet(_fix_hunk_headers(diff))
        lines = original.splitlines(keepends=True)
        result_lines = list(lines)  # safe default: empty/unparseable patch returns original

        for patched_file in patch:
            result_lines = list(lines)
            offset = 0
            for hunk in patched_file:
                # Context lines at the start of the hunk used to locate position
                context_lines = [
                    line.value for line in hunk if line.line_type == " "
                ]
                source_lines = [
                    line.value for line in hunk if line.line_type in (" ", "-")
                ]

                expected_start = hunk.source_start - 1 + offset
                actual_start = expected_start  # default: trust the diff

                # Fuzzy search: look for the source lines near the expected position
                if context_lines:
                    search_start = max(0, expected_start - FUZZ)
                    search_end = min(len(result_lines), expected_start + FUZZ + len(source_lines))
                    for candidate in range(search_start, search_end):
                        window = [
                            l for l in result_lines[candidate: candidate + len(source_lines)]
                        ]
                        if window == source_lines:
                            actual_start = candidate
                            break

                new_lines = []
                for line in hunk:
                    if line.line_type == "+":
                        new_lines.append(line.value)
                    elif line.line_type == " ":
                        new_lines.append(line.value)
                    # "-" lines are dropped

                result_lines[actual_start: actual_start + len(source_lines)] = new_lines
                offset += len(new_lines) - len(source_lines)

        return "".join(result_lines)
    except (unidiff.errors.UnidiffParseError, IndexError, ValueError) as exc:
        import logging
        logging.getLogger("nyx.github").debug("Diff application failed: %s", exc)
        return None
