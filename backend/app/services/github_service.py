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

    Uses a pure-Python implementation to avoid shell injection risks.
    """
    try:
        import unidiff
        patch = unidiff.PatchSet(diff)
        lines = original.splitlines(keepends=True)

        for patched_file in patch:
            result_lines = list(lines)
            offset = 0
            for hunk in patched_file:
                source_start = hunk.source_start - 1 + offset
                source_length = hunk.source_length

                new_lines = []
                for line in hunk:
                    if line.line_type == "+":
                        new_lines.append(line.value)
                    elif line.line_type == " ":
                        new_lines.append(line.value)
                    # "-" lines are removed (not added to new_lines)

                result_lines[source_start : source_start + source_length] = new_lines
                offset += len(new_lines) - source_length

        return "".join(result_lines)
    except Exception:
        return None
