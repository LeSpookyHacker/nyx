"""
Deduplication Service

Determines whether an incoming NormalizedFinding matches an existing Finding
in the database. Returns (existing_finding, is_new) tuples.

Strategy:
  1. Exact fingerprint match — same scanner, rule, repo, file/location
  2. Cross-scanner dedup — same CWE + file_path within 3 lines proximity
     (for SAST tools that both catch the same bug)
"""
from __future__ import annotations

from typing import Optional, Tuple

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.services.normalization.base import NormalizedFinding


async def find_existing(
    db: AsyncSession,
    normalized: NormalizedFinding,
    repo_id: str,
) -> Tuple[Optional[Finding], bool]:
    """
    Returns (existing_finding, is_new).
    If is_new is True, the caller should INSERT a new Finding.
    If is_new is False, the caller should UPDATE last_seen_at on the existing one.
    """
    fingerprint = normalized.fingerprint(repo_id)

    # Strategy 1: exact fingerprint
    result = await db.execute(
        select(Finding).where(
            and_(
                Finding.fingerprint == fingerprint,
                Finding.repository_id == repo_id,
            )
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        return existing, False

    # Strategy 2: Cross-scanner dedup for SAST findings with the same CWE+file+line proximity.
    # Only applies across different scanners — same-scanner findings on adjacent lines are
    # distinct hits and must not be collapsed into one.
    if normalized.file_path and normalized.cwe_ids and normalized.line_start:
        for cwe in normalized.cwe_ids:
            nearby = await _find_nearby_sast(
                db, repo_id, cwe, normalized.file_path, normalized.line_start,
                exclude_scanner=normalized.scanner,
            )
            if nearby:
                return nearby, False

    return None, True


async def _find_nearby_sast(
    db: AsyncSession,
    repo_id: str,
    cwe: str,
    file_path: str,
    line_start: int,
    proximity: int = 3,
    exclude_scanner: Optional[str] = None,
) -> Optional[Finding]:
    """Find an existing finding within `proximity` lines and same CWE in same file.

    exclude_scanner: skip findings from this scanner so same-scanner adjacent hits
    are never collapsed — only cross-scanner duplicates are merged.
    """
    conditions = [
        Finding.repository_id == repo_id,
        Finding.file_path == file_path,
        Finding.cwe_ids.contains(cwe),
        Finding.line_start >= line_start - proximity,
        Finding.line_start <= line_start + proximity,
    ]
    if exclude_scanner:
        conditions.append(Finding.scanner != exclude_scanner)
    result = await db.execute(select(Finding).where(and_(*conditions)))
    return result.scalar_one_or_none()
