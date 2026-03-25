"""
Scanner auto-detection service.

Analyses a repository's file tree (via GitHub API) and the files in push
payloads to determine which scanners are applicable.  The canonical
nyx-scan.yml uses hashFiles() conditions so it self-activates — this
service keeps the DB's enabled_scanners in sync so Nyx's UI and scan
records stay accurate.
"""
from __future__ import annotations

import fnmatch
import logging
from typing import Any, Dict, List, Optional, Set

import httpx

from app.config import get_settings

logger = logging.getLogger("nyx.scanner_detection")

_GITHUB_API = "https://api.github.com"

# ── Trigger rules ──────────────────────────────────────────────────────────────
# Each entry maps a scanner name to:
#   always        — always recommend regardless of files
#   file_patterns — fnmatch patterns; scanner is triggered if any match
#   note          — shown to the user

SCANNER_TRIGGERS: Dict[str, Dict[str, Any]] = {
    "GITLEAKS": {
        "always": True,
        "note": "Scans git history for leaked secrets and credentials.",
    },
    "HADOLINT": {
        "file_patterns": ["Dockerfile", "Dockerfile.*", "*.dockerfile", "**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"],
        "note": "Dockerfile(s) detected — lints for best-practice violations.",
    },
    "SNYK": {
        "file_patterns": [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "requirements*.txt", "Pipfile", "pyproject.toml",
            "Gemfile", "Gemfile.lock",
            "go.mod", "go.sum",
            "pom.xml", "build.gradle", "build.gradle.kts",
            "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock",
            "**/package.json", "**/requirements.txt", "**/go.mod",
        ],
        "note": "Package manager files detected. Requires SNYK_TOKEN secret in GitHub.",
    },
    "DEPENDABOT": {
        "file_patterns": [
            "package.json", "package-lock.json", "yarn.lock",
            "requirements.txt", "requirements*.txt", "Pipfile", "pyproject.toml",
            "Gemfile", "Gemfile.lock",
            "go.mod", "go.sum",
            "pom.xml", "build.gradle", "build.gradle.kts",
            "Cargo.toml", "Cargo.lock",
            "composer.json", "composer.lock",
            "**/package.json", "**/requirements.txt", "**/go.mod",
        ],
        "note": "GitHub Dependabot alert sync. Enable Dependabot in repository Security settings.",
    },
}

# Scanners that are always included in the canonical workflow regardless of detection
BASELINE_SCANNERS = {"SEMGREP", "TRIVY"}


def detect_from_file_list(file_paths: List[str]) -> Dict[str, str]:
    """
    Given a list of file paths, return a dict of {scanner: reason} for each
    scanner that should be activated based on those files.
    """
    detected: Dict[str, str] = {}

    for scanner, rule in SCANNER_TRIGGERS.items():
        if rule.get("always"):
            detected[scanner] = "Always recommended"
            continue

        patterns = rule.get("file_patterns", [])
        for path in file_paths:
            filename = path.split("/")[-1]  # basename
            for pattern in patterns:
                # Match against full path and basename
                if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(filename, pattern.lstrip("**/").lstrip("**/")):
                    detected[scanner] = f"{path} detected"
                    break
            if scanner in detected:
                break

    return detected


def detect_from_push_payload(payload: dict) -> Dict[str, str]:
    """
    Extract all added/modified files from a GitHub push webhook payload
    and run detection against them.
    """
    file_paths: Set[str] = set()
    for commit in payload.get("commits", []):
        file_paths.update(commit.get("added", []))
        file_paths.update(commit.get("modified", []))
    return detect_from_file_list(list(file_paths))


async def detect_from_github_tree(github_full_name: str) -> Dict[str, str]:
    """
    Fetch the full file tree from GitHub and run detection.
    Returns {scanner: reason} for each recommended scanner.
    """
    settings = get_settings()
    if not settings.GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set — cannot fetch repo tree for scanner detection")
        return {}

    headers = {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(base_url=_GITHUB_API, headers=headers, timeout=20.0) as client:
            # Get default branch
            repo_resp = await client.get(f"/repos/{github_full_name}")
            if repo_resp.status_code != 200:
                return {}
            default_branch = repo_resp.json().get("default_branch", "main")

            # Get recursive tree
            tree_resp = await client.get(
                f"/repos/{github_full_name}/git/trees/{default_branch}",
                params={"recursive": "1"},
            )
            if tree_resp.status_code != 200:
                return {}

            tree = tree_resp.json()
            file_paths = [
                item["path"]
                for item in tree.get("tree", [])
                if item.get("type") == "blob"
            ]

    except Exception as e:
        logger.warning(f"Failed to fetch tree for {github_full_name}: {e}")
        return {}

    return detect_from_file_list(file_paths)


def merge_scanners(current: List[str], new_detections: Dict[str, str]) -> tuple[List[str], List[str]]:
    """
    Merge newly detected scanners into the current list.

    Returns (updated_list, added_list) where added_list contains only the
    scanners that were not already present.
    """
    current_set = set(s.upper() for s in current)
    added = [s for s in new_detections if s not in current_set]
    updated = list(current_set | set(new_detections.keys()))
    return updated, added
