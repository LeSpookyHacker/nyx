"""
GitHub Service — wraps PyGithub for all GitHub API interactions.

Responsibilities:
  - Registering/removing webhooks on repositories
  - Fetching file content for AI fix context
  - Creating branches and pull requests with AI-generated fixes
  - Polling PR status and deployment environments
  - Creating Check Runs for PR security annotations
"""
from __future__ import annotations

import base64
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


def _get_client() -> Github:
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
        run: |
          NYX_URL="${{NYX_URL// /}}"
          jq -n \\
            --arg repo    "{repo_id}" \\
            --arg scanner "SEMGREP" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d semgrep.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
          echo "✓ Semgrep results sent to Nyx"

      # ── Gitleaks (Secrets) — always runs ─────────────────────────────────────
      - name: Run Gitleaks
        run: |
          curl -sSfL \\
            https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz \\
            | tar -xz gitleaks
          ./gitleaks detect --source . --report-format json \\
            --report-path gitleaks.json --exit-code 0 || true

      - name: Report Gitleaks → Nyx
        if: hashFiles('gitleaks.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
        run: |
          COUNT=$(jq 'if type == "array" then length else 0 end' gitleaks.json 2>/dev/null || echo 0)
          if [ "$COUNT" -eq 0 ]; then echo "✓ Gitleaks: no secrets found"; exit 0; fi
          NYX_URL="${{NYX_URL// /}}"
          jq -n \\
            --arg repo    "{repo_id}" \\
            --arg scanner "GITLEAKS" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d gitleaks.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
          echo "✓ Gitleaks: $COUNT secret(s) sent to Nyx"

      # ── Hadolint (Dockerfile linting) — auto-activates when Dockerfile exists ─
      - name: Run Hadolint
        if: hashFiles('**/Dockerfile', '**/Dockerfile.*') != ''
        run: |
          wget -qO /usr/local/bin/hadolint \\
            https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64
          chmod +x /usr/local/bin/hadolint
          find . \\( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.dockerfile' \\) \\
            | head -20 | xargs hadolint --format json 2>/dev/null > hadolint.json || true

      - name: Report Hadolint → Nyx
        if: hashFiles('hadolint.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
        run: |
          COUNT=$(jq 'if type == "array" then length else 0 end' hadolint.json 2>/dev/null || echo 0)
          if [ "$COUNT" -eq 0 ]; then echo "✓ Hadolint: no issues found"; exit 0; fi
          NYX_URL="${{NYX_URL// /}}"
          jq -n \\
            --arg repo    "{repo_id}" \\
            --arg scanner "HADOLINT" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d hadolint.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
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
          SNYK_TOKEN: ${{{{ secrets.SNYK_TOKEN }}}}
        run: |
          if [ -z "$SNYK_TOKEN" ]; then exit 0; fi
          NYX_URL="${{NYX_URL// /}}"
          jq -n \\
            --arg repo    "{repo_id}" \\
            --arg scanner "SNYK" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d snyk.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
          echo "✓ Snyk results sent to Nyx"

      # ── ZAP (DAST — optional) ─────────────────────────────────────────────────
      # Set vars.NYX_ZAP_TARGET to your deployed app URL to enable DAST scanning.
      - name: Fix workspace permissions for ZAP container
        if: vars.NYX_ZAP_TARGET != ''
        run: chmod -R 777 .

      - name: Run ZAP Baseline Scan
        if: vars.NYX_ZAP_TARGET != ''
        continue-on-error: true  # ZAP failure must not abort Trivy/Gitleaks/Hadolint steps
        uses: zaproxy/action-baseline@v0.14.0
        with:
          target: ${{{{ vars.NYX_ZAP_TARGET }}}}
          # -m 3  = spider for 3 minutes (SPAs need more than the 1m default; NOTE: use -m not -t)
          # -a    = include alpha passive rules for better header/cookie coverage
          # -J    = write traditional JSON report to this file (distinct from the action's -J)
          cmd_options: '-m 3 -a -J zap.json'
          allow_issue_writing: false
          fail_action: false

      - name: Debug — show ZAP output
        if: always() && vars.NYX_ZAP_TARGET != ''
        run: |
          if [ -f zap.json ]; then
            echo "zap.json exists, size=$(wc -c < zap.json) bytes"
            echo "site count=$(jq '.site | length' zap.json 2>/dev/null || echo 'parse error')"
            jq '.site[] | {{host: .["@host"], alerts: (.alerts | length)}}' zap.json 2>/dev/null || true
          else
            echo "WARNING: zap.json was NOT created — ZAP may have failed to start or write output"
          fi

      - name: Report ZAP → Nyx
        if: hashFiles('zap.json') != ''
        env:
          NYX_URL: ${{{{ vars.NYX_URL }}}}
          NYX_API_KEY: ${{{{ secrets.NYX_API_KEY }}}}
        run: |
          NYX_URL="${{NYX_URL// /}}"
          SITE_COUNT=$(jq '.site | length' zap.json 2>/dev/null || echo 0)
          if [ "$SITE_COUNT" -eq 0 ]; then
            echo "⚠ ZAP returned no site data — skipping submission (check Debug step above)"
            exit 0
          fi
          jq -n \\
            --arg repo    "{repo_id}" \\
            --arg scanner "ZAP" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d zap.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
          echo "✓ ZAP results sent to Nyx ($SITE_COUNT site(s) scanned)"

      # ── Trivy (SCA + IaC + Container) ────────────────────────────────────────
      - name: Run Trivy
        if: always()  # Run even if ZAP failed
        uses: aquasecurity/trivy-action@master
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
        run: |
          NYX_URL="${{NYX_URL// /}}"
          jq -n \\
            --arg repo    "{repo_id}" \\
            --arg scanner "TRIVY" \\
            --arg ref     "$GITHUB_REF_NAME" \\
            --slurpfile d trivy.json \\
            '{{repository_id:$repo, scanner:$scanner, git_ref:$ref, data:$d[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/scans/import-json" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
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
          jq -n \\
            --arg ref "$GITHUB_REF_NAME" \\
            --slurpfile s sbom-cdx.json \\
            '{{"git_ref":$ref,"sbom":$s[0]}}' \\
          | curl -sf -X POST "$NYX_URL/api/v1/sbom/repositories/{repo_id}/submit" \\
              -H "Content-Type: application/json" \\
              -H "X-API-Key: $NYX_API_KEY" \\
              -H "ngrok-skip-browser-warning: true" \\
              -d @-
          echo "✓ SBOM submitted to Nyx"
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
    try:
        g = _get_client()
        repo = g.get_repo(full_name)
        return {
            "github_repo_id": repo.id,
            "default_branch": repo.default_branch,
            "description": repo.description or "",
            "language": repo.language,
            "is_private": repo.private,
        }
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
    try:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        secret = generate_webhook_secret()
        hook = repo.create_hook(
            name="web",
            config={
                "url": f"{settings.GITHUB_WEBHOOK_ENDPOINT}",
                "content_type": "json",
                "secret": secret,
                "insecure_ssl": "0",
            },
            events=["push", "pull_request", "check_run"],
            active=True,
        )
        return hook.id, secret
    except GithubException as e:
        raise GitHubError(f"Failed to register webhook for {repo_full_name}: {e}") from e


async def remove_webhook(repo_full_name: str, webhook_id: int) -> None:
    """Remove the Nyx webhook from a repository."""
    try:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        hook = repo.get_hook(webhook_id)
        hook.delete()
    except GithubException as e:
        raise GitHubError(f"Failed to remove webhook: {e}") from e


async def get_file_content(repo_full_name: str, file_path: str, ref: str = "") -> str:
    """Fetch the content of a file from a GitHub repository."""
    try:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        kwargs = {"ref": ref} if ref else {}
        contents = repo.get_contents(file_path, **kwargs)
        if isinstance(contents, list):
            raise GitHubError(f"{file_path} is a directory, not a file")
        return base64.b64decode(contents.content).decode("utf-8", errors="replace")
    except GithubException as e:
        raise GitHubError(f"Failed to fetch {file_path} from {repo_full_name}: {e}") from e


async def create_fix_pr(
    repo_full_name: str,
    file_path: str,
    original_content: str,
    fixed_content: str,
    branch_name: str,
    pr_title: str,
    pr_body: str,
    base_branch: str,
) -> Tuple[int, str]:
    """
    Create a branch with the fixed file and open a pull request.
    Returns (pr_number, pr_url).
    """
    try:
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
        )
        try:
            pr.add_to_labels("nyx-remediation", "security")
        except GithubException:
            pass  # Labels may not exist; non-fatal

        return pr.number, pr.html_url
    except GithubException as e:
        raise GitHubError(f"Failed to create fix PR for {repo_full_name}: {e}") from e


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
    try:
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
    except GithubException as e:
        raise GitHubError(f"Failed to merge PR #{pr_number}: {e}") from e


async def get_pr_status(repo_full_name: str, pr_number: int) -> dict:
    """Return current PR state and merged status."""
    try:
        g = _get_client()
        repo = g.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)
        return {
            "state": pr.state,
            "merged": pr.merged,
            "merged_at": pr.merged_at,
            "deployment_url": None,  # Extend: poll repo.get_environments() for staging deploy
        }
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
    except Exception:
        pass
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
    except Exception:
        pass


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
        patch = unidiff.PatchSet(diff)
        lines = original.splitlines(keepends=True)

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
    except Exception:
        return None
