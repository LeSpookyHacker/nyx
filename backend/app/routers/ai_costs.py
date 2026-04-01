"""
AI cost dashboard — aggregate token usage and estimated spend.

Tracks Claude API token consumption per remediation and surfaces:
  - Daily / weekly / monthly totals
  - Per-finding average cost
  - Cost by severity (highest-cost findings)
  - Cumulative spend estimate
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_api_key
from app.database import get_db
from app.models.remediation import Remediation
from app.models.finding import Finding

router = APIRouter(prefix="/dashboard/ai-costs", tags=["analytics"])

# Claude pricing (USD per million tokens) — update when Anthropic changes pricing.
# These are approximate defaults; actual billing may differ.
_INPUT_PRICE_PER_MILLION = 3.00   # claude-sonnet-4-x input
_OUTPUT_PRICE_PER_MILLION = 15.00  # claude-sonnet-4-x output


def _estimate_cost(prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate USD cost from token counts."""
    return (
        (prompt_tokens / 1_000_000) * _INPUT_PRICE_PER_MILLION
        + (completion_tokens / 1_000_000) * _OUTPUT_PRICE_PER_MILLION
    )


@router.get("")
async def get_ai_costs(
    days: int = Query(30, ge=1, le=365),
    repository_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """
    AI token usage and estimated cost summary for the specified period.

    Returns totals, daily averages, per-finding breakdown, and daily time series.
    Costs are estimates based on public Claude pricing — check your Anthropic invoice for actuals.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)

    base_filters = [
        Remediation.created_at >= since,
        Remediation.prompt_tokens.isnot(None),
    ]

    # Join with Finding for repository filtering and severity breakdown
    if repository_id:
        base_filters.extend([
            Remediation.finding_id == Finding.id,
            Finding.repository_id == repository_id,
        ])
        stmt = select(
            func.sum(Remediation.prompt_tokens).label("total_input"),
            func.sum(Remediation.completion_tokens).label("total_output"),
            func.count().label("total_remediations"),
            func.avg(Remediation.prompt_tokens).label("avg_input"),
            func.avg(Remediation.completion_tokens).label("avg_output"),
        ).join(Finding, Remediation.finding_id == Finding.id).where(*base_filters)
    else:
        stmt = select(
            func.sum(Remediation.prompt_tokens).label("total_input"),
            func.sum(Remediation.completion_tokens).label("total_output"),
            func.count().label("total_remediations"),
            func.avg(Remediation.prompt_tokens).label("avg_input"),
            func.avg(Remediation.completion_tokens).label("avg_output"),
        ).where(*base_filters)

    totals_row = (await db.execute(stmt)).one()

    total_input = int(totals_row.total_input or 0)
    total_output = int(totals_row.total_output or 0)
    total_remediations = int(totals_row.total_remediations or 0)
    avg_input = round(float(totals_row.avg_input or 0))
    avg_output = round(float(totals_row.avg_output or 0))

    total_cost = _estimate_cost(total_input, total_output)
    avg_cost_per_fix = _estimate_cost(avg_input, avg_output)

    # Daily time series
    daily_stmt = select(
        func.date(Remediation.created_at).label("date"),
        func.sum(Remediation.prompt_tokens).label("input_tokens"),
        func.sum(Remediation.completion_tokens).label("output_tokens"),
        func.count().label("fixes"),
    ).where(*base_filters).group_by(func.date(Remediation.created_at)).order_by("date")

    if repository_id:
        daily_stmt = daily_stmt.join(Finding, Remediation.finding_id == Finding.id)

    daily_rows = (await db.execute(daily_stmt)).all()
    daily = []
    for row in daily_rows:
        inp = int(row.input_tokens or 0)
        out = int(row.output_tokens or 0)
        daily.append({
            "date": str(row.date),
            "input_tokens": inp,
            "output_tokens": out,
            "total_tokens": inp + out,
            "fixes": row.fixes,
            "estimated_cost_usd": round(_estimate_cost(inp, out), 4),
        })

    # Top 10 most expensive individual remediations
    top_stmt = (
        select(Remediation, Finding.severity, Finding.title)
        .join(Finding, Remediation.finding_id == Finding.id)
        .where(*base_filters)
        .order_by((Remediation.prompt_tokens + Remediation.completion_tokens).desc())
        .limit(10)
    )
    if not repository_id:
        # Remove the extra Finding filters added above for the no-repo case
        top_stmt = (
            select(Remediation, Finding.severity, Finding.title)
            .join(Finding, Remediation.finding_id == Finding.id)
            .where(
                Remediation.created_at >= since,
                Remediation.prompt_tokens.isnot(None),
            )
            .order_by((Remediation.prompt_tokens + Remediation.completion_tokens).desc())
            .limit(10)
        )

    top_rows = (await db.execute(top_stmt)).all()
    top_remediations = []
    for rem, severity, title in top_rows:
        inp = rem.prompt_tokens or 0
        out = rem.completion_tokens or 0
        top_remediations.append({
            "remediation_id": rem.id,
            "finding_title": title,
            "severity": severity,
            "status": rem.status,
            "confidence": rem.ai_confidence,
            "confidence_flagged": rem.confidence_flagged,
            "input_tokens": inp,
            "output_tokens": out,
            "total_tokens": inp + out,
            "estimated_cost_usd": round(_estimate_cost(inp, out), 4),
        })

    return {
        "period_days": days,
        "total_remediations": total_remediations,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_tokens": total_input + total_output,
        "estimated_total_cost_usd": round(total_cost, 4),
        "avg_tokens_per_fix": avg_input + avg_output,
        "avg_cost_per_fix_usd": round(avg_cost_per_fix, 4),
        "pricing_note": "Estimates based on published Claude Sonnet pricing. Check your Anthropic invoice for actuals.",
        "daily": daily,
        "top_remediations_by_cost": top_remediations,
    }
