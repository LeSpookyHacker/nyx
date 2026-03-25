"""Executive Report router — generates print-friendly HTML security reports."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import FindingStatus, Severity
from app.core.security import require_api_key
from app.database import get_db
from app.models.finding import Finding
from app.models.repository import Repository
from app.services.compliance_service import FRAMEWORK_META, FRAMEWORKS, get_compliance_report

router = APIRouter(prefix="/reports", tags=["reports"])

_SEVERITY_COLORS = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM": "#eab308", "LOW": "#22c55e", "INFO": "#64748b",
}


@router.get("/executive")
async def executive_report(
    days: int = Query(30, ge=7, le=365),
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(require_api_key),
):
    """Generate a print-friendly HTML executive security report."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    date_range = f"{since.strftime('%b %d, %Y')} – {now.strftime('%b %d, %Y')}"

    # ── KPIs ──────────────────────────────────────────────────────────────────
    total_open = (await db.execute(
        select(func.count()).where(Finding.status == FindingStatus.OPEN.value)
    )).scalar_one()
    total_critical = (await db.execute(
        select(func.count()).where(Finding.status == FindingStatus.OPEN.value, Finding.severity == "CRITICAL")
    )).scalar_one()
    sla_breached = (await db.execute(
        select(func.count()).where(
            Finding.status == FindingStatus.OPEN.value,
            Finding.sla_breach_at <= now,
            Finding.sla_breach_at.isnot(None),
        )
    )).scalar_one()
    total_fixed = (await db.execute(
        select(func.count()).where(Finding.status == FindingStatus.FIXED.value)
    )).scalar_one()
    regressions = (await db.execute(
        select(func.count()).where(Finding.is_regression == True, Finding.regression_detected_at >= since)  # noqa: E712
    )).scalar_one()
    total_repos = (await db.execute(select(func.count()).select_from(Repository))).scalar_one()

    # ── MTTR ──────────────────────────────────────────────────────────────────
    mttr_rows = {}
    for sev in Severity:
        avg = (await db.execute(
            select(func.avg(func.julianday(Finding.resolved_at) - func.julianday(Finding.first_seen_at)))
            .where(Finding.severity == sev.value, Finding.status == FindingStatus.FIXED.value,
                   Finding.resolved_at.isnot(None))
        )).scalar_one()
        mttr_rows[sev.value] = f"{round(float(avg), 1)}d" if avg else "N/A"

    # ── Trends (weekly) ────────────────────────────────────────────────────────
    weekly_result = await db.execute(
        select(
            func.strftime("%Y-%W", Finding.first_seen_at).label("week"),
            func.count().label("new"),
        )
        .where(Finding.first_seen_at >= since)
        .group_by("week").order_by("week")
    )
    weekly_new = {str(r.week): r.new for r in weekly_result}

    weekly_fixed_result = await db.execute(
        select(
            func.strftime("%Y-%W", Finding.resolved_at).label("week"),
            func.count().label("fixed"),
        )
        .where(Finding.resolved_at >= since, Finding.status == FindingStatus.FIXED.value)
        .group_by("week").order_by("week")
    )
    weekly_fixed = {str(r.week): r.fixed for r in weekly_fixed_result}
    all_weeks = sorted(set(list(weekly_new.keys()) + list(weekly_fixed.keys())))

    # ── Top vulnerabilities ────────────────────────────────────────────────────
    top_vulns_result = await db.execute(
        select(Finding.rule_id, Finding.title, Finding.scanner, func.count().label("cnt"))
        .where(Finding.status == FindingStatus.OPEN.value)
        .group_by(Finding.rule_id, Finding.title, Finding.scanner)
        .order_by(desc("cnt")).limit(10)
    )
    top_vulns = top_vulns_result.all()

    # ── Repo risk table ────────────────────────────────────────────────────────
    repos_result = await db.execute(
        select(Repository).order_by(desc(Repository.risk_score)).limit(20)
    )
    repos = repos_result.scalars().all()

    # ── Scanner breakdown ──────────────────────────────────────────────────────
    scanner_result = await db.execute(
        select(Finding.scanner, Finding.severity, func.count().label("cnt"))
        .where(Finding.status == FindingStatus.OPEN.value)
        .group_by(Finding.scanner, Finding.severity)
        .order_by(Finding.scanner)
    )
    scanner_rows = scanner_result.all()
    scanner_map: dict = {}
    for row in scanner_rows:
        if row.scanner not in scanner_map:
            scanner_map[row.scanner] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
        scanner_map[row.scanner][row.severity] = row.cnt
        scanner_map[row.scanner]["total"] += row.cnt

    # ── Per-repo findings breakdown ────────────────────────────────────────────
    repo_findings_result = await db.execute(
        select(
            Repository.github_full_name,
            Finding.severity,
            Finding.scanner,
            Finding.category,
            func.count().label("cnt"),
        )
        .join(Repository, Finding.repository_id == Repository.id)
        .where(Finding.status == FindingStatus.OPEN.value)
        .group_by(Repository.github_full_name, Finding.severity, Finding.scanner, Finding.category)
        .order_by(Repository.github_full_name, Finding.severity)
    )
    repo_findings_rows = repo_findings_result.all()
    repo_findings_map: dict = {}
    for row in repo_findings_rows:
        if row.github_full_name not in repo_findings_map:
            repo_findings_map[row.github_full_name] = []
        repo_findings_map[row.github_full_name].append(row)

    # ── SLA status breakdown ───────────────────────────────────────────────────
    overdue_7 = (await db.execute(
        select(func.count()).where(
            Finding.status == FindingStatus.OPEN.value,
            Finding.sla_breach_at <= now,
        )
    )).scalar_one()
    due_in_7 = (await db.execute(
        select(func.count()).where(
            Finding.status == FindingStatus.OPEN.value,
            Finding.sla_breach_at > now,
            Finding.sla_breach_at <= now + timedelta(days=7),
        )
    )).scalar_one()
    on_track = (await db.execute(
        select(func.count()).where(
            Finding.status == FindingStatus.OPEN.value,
            Finding.sla_breach_at > now + timedelta(days=7),
        )
    )).scalar_one()

    # ── Compliance ────────────────────────────────────────────────────────────
    compliance_summary = []
    for fid, meta in FRAMEWORK_META.items():
        try:
            report = await get_compliance_report(db, fid)
            total_controls = len(report)
            passing = sum(1 for ctrl in report if ctrl.open_findings == 0)
            pct = round(passing / total_controls * 100) if total_controls else 0
            compliance_summary.append({"name": meta["name"], "pct": pct, "passing": passing, "total": total_controls})
        except Exception:
            pass

    # ── Build HTML ─────────────────────────────────────────────────────────────
    kpi_row = _kpi(total_open, total_critical, sla_breached, total_fixed, regressions, total_repos)
    mttr_html = "".join(f"<tr><td>{s}</td><td>{d}</td></tr>" for s, d in mttr_rows.items())
    trend_html = "".join(
        f"<tr><td>{w}</td><td>{weekly_new.get(w, 0)}</td><td>{weekly_fixed.get(w, 0)}</td></tr>"
        for w in all_weeks
    )
    vuln_html = "".join(
        f"<tr><td>{v.title}</td><td>{v.scanner}</td><td><code>{v.rule_id}</code></td><td>{v.cnt}</td></tr>"
        for v in top_vulns
    )
    repo_html = "".join(
        f"<tr><td>{r.github_full_name}</td>"
        f"<td class='score' style='color:{'#ef4444' if r.risk_score>=70 else '#f97316' if r.risk_score>=40 else '#22c55e'}'>{round(r.risk_score)}</td>"
        f"<td style='color:#ef4444'>{r.open_critical}</td>"
        f"<td style='color:#f97316'>{r.open_high}</td>"
        f"<td style='color:#eab308'>{r.open_medium}</td>"
        f"<td>{r.open_low}</td>"
        f"<td>{r.open_critical + r.open_high + r.open_medium + r.open_low + r.open_info}</td></tr>"
        for r in repos
    )

    # Scanner breakdown table
    scanner_html = "".join(
        f"<tr><td><strong>{s}</strong></td>"
        f"<td style='color:#ef4444'>{d['CRITICAL']}</td>"
        f"<td style='color:#f97316'>{d['HIGH']}</td>"
        f"<td style='color:#eab308'>{d['MEDIUM']}</td>"
        f"<td style='color:#22c55e'>{d['LOW']}</td>"
        f"<td>{d['INFO']}</td>"
        f"<td><strong>{d['total']}</strong></td></tr>"
        for s, d in sorted(scanner_map.items(), key=lambda x: -x[1]["total"])
    ) if scanner_map else "<tr><td colspan='7' style='color:#9ca3af'>No open findings</td></tr>"

    # SLA status bar
    sla_total = overdue_7 + due_in_7 + on_track
    sla_html = f"""
    <div class='sla-bar'>
      <div style='background:#ef4444;width:{round(overdue_7/sla_total*100) if sla_total else 0}%'
           title='Overdue: {overdue_7}'></div>
      <div style='background:#f97316;width:{round(due_in_7/sla_total*100) if sla_total else 0}%'
           title='Due in 7d: {due_in_7}'></div>
      <div style='background:#22c55e;width:{round(on_track/sla_total*100) if sla_total else 0}%'
           title='On track: {on_track}'></div>
    </div>
    <div class='sla-legend'>
      <span style='color:#ef4444'>&#9632; Overdue: {overdue_7}</span>
      <span style='color:#f97316'>&#9632; Due within 7d: {due_in_7}</span>
      <span style='color:#22c55e'>&#9632; On track: {on_track}</span>
    </div>"""

    # Per-repo findings breakdown
    repo_detail_html = ""
    for repo_name, rows in repo_findings_map.items():
        scanner_totals: dict = {}
        sev_totals: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for row in rows:
            scanner_totals[row.scanner] = scanner_totals.get(row.scanner, 0) + row.cnt
            sev_totals[row.severity] = sev_totals.get(row.severity, 0) + row.cnt
        total_repo = sum(sev_totals.values())
        _sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        row_html = "".join(
            "<tr><td>{}</td><td>{}</td><td style='color:{}'>{}</td><td>{}</td></tr>".format(
                row.scanner, row.category or "—",
                _SEVERITY_COLORS.get(row.severity, "#000"), row.severity, row.cnt
            )
            for row in sorted(rows, key=lambda r: (_sev_order.index(r.severity) if r.severity in _sev_order else 99, r.scanner))
        )
        repo_detail_html += f"""
        <div class='repo-section'>
          <div class='repo-header'>
            <strong>{repo_name}</strong>
            <span class='repo-badge'>{total_repo} open findings</span>
            <span style='color:#ef4444'>{sev_totals['CRITICAL']}C</span>
            <span style='color:#f97316'>{sev_totals['HIGH']}H</span>
            <span style='color:#eab308'>{sev_totals['MEDIUM']}M</span>
            <span style='color:#22c55e'>{sev_totals['LOW']}L</span>
          </div>
          <table><thead><tr><th>Scanner</th><th>Category</th><th>Severity</th><th>Count</th></tr></thead>
          <tbody>{row_html}</tbody></table>
        </div>"""

    comp_html = "".join(
        f"<tr><td>{c['name']}</td><td>{c['pct']}%</td>"
        f"<td>{c['passing']}/{c['total']} controls</td></tr>"
        for c in compliance_summary
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Nyx Executive Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #111; margin: 0; padding: 24px; background: #fff; }}
  h1 {{ color: #1e1b4b; margin-bottom: 4px; }}
  .subtitle {{ color: #6b7280; margin-bottom: 32px; font-size: 14px; }}
  h2 {{ color: #1e1b4b; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; margin-top: 36px; }}
  h3 {{ color: #374151; margin: 0 0 8px; font-size: 14px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 16px; margin-bottom: 32px; }}
  .kpi {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }}
  .kpi .num {{ font-size: 32px; font-weight: 700; }}
  .kpi .label {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 13px; }}
  th {{ background: #f3f4f6; text-align: left; padding: 8px 12px; font-size: 12px; color: #374151; }}
  td {{ padding: 7px 12px; border-bottom: 1px solid #f3f4f6; }}
  .score {{ font-weight: 700; }}
  code {{ background: #f3f4f6; padding: 2px 5px; border-radius: 3px; font-size: 11px; }}
  .sla-bar {{ display: flex; height: 20px; border-radius: 4px; overflow: hidden; margin: 12px 0 4px; background: #f3f4f6; }}
  .sla-bar div {{ transition: width 0.3s; }}
  .sla-legend {{ display: flex; gap: 20px; font-size: 12px; color: #374151; margin-bottom: 16px; }}
  .repo-section {{ border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
  .repo-header {{ background: #f9fafb; padding: 10px 14px; display: flex; align-items: center; gap: 12px; font-size: 13px; }}
  .repo-badge {{ background: #e5e7eb; border-radius: 4px; padding: 2px 8px; font-size: 11px; color: #374151; }}
  .repo-section table {{ margin: 0; }}
  .repo-section td, .repo-section th {{ padding: 6px 14px; }}
  .footer {{ margin-top: 40px; color: #9ca3af; font-size: 12px; border-top: 1px solid #e5e7eb; padding-top: 16px; }}
  @media print {{
    body {{ padding: 0; }}
    .kpi-grid {{ grid-template-columns: repeat(3, 1fr); }}
    h2 {{ break-before: auto; }}
    table {{ break-inside: avoid; }}
    .repo-section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<h1>Nyx Executive Security Report</h1>
<div class="subtitle">Period: {date_range} &nbsp;·&nbsp; Generated: {now.strftime("%Y-%m-%d %H:%M UTC")}</div>

<h2>Security KPIs</h2>
{kpi_row}

<h2>SLA Status</h2>
{sla_html}

<h2>Scanner Coverage</h2>
<table>
  <thead><tr><th>Scanner</th><th style='color:#ef4444'>Critical</th><th style='color:#f97316'>High</th><th style='color:#eab308'>Medium</th><th style='color:#22c55e'>Low</th><th>Info</th><th>Total Open</th></tr></thead>
  <tbody>{scanner_html}</tbody>
</table>

<h2>Repository Risk Summary</h2>
<table>
  <thead><tr><th>Repository</th><th>Risk Score</th><th style='color:#ef4444'>Critical</th><th style='color:#f97316'>High</th><th style='color:#eab308'>Medium</th><th>Low</th><th>Total</th></tr></thead>
  <tbody>{repo_html}</tbody>
</table>

<h2>Per-Repository Findings Breakdown</h2>
{repo_detail_html if repo_detail_html else "<p style='color:#9ca3af'>No open findings.</p>"}

<h2>Mean Time to Remediate (MTTR)</h2>
<table><thead><tr><th>Severity</th><th>Avg Days to Fix</th></tr></thead><tbody>{mttr_html}</tbody></table>

<h2>Weekly Finding Trends</h2>
<table><thead><tr><th>Week</th><th>New</th><th>Fixed</th></tr></thead><tbody>{trend_html}</tbody></table>

<h2>Top 10 Vulnerability Types</h2>
<table><thead><tr><th>Title</th><th>Scanner</th><th>Rule</th><th>Count</th></tr></thead><tbody>{vuln_html}</tbody></table>

<h2>Compliance Coverage</h2>
<table><thead><tr><th>Framework</th><th>Coverage</th><th>Controls Passing</th></tr></thead><tbody>{comp_html}</tbody></table>

<div class="footer">
  Generated by Nyx Security Dashboard &nbsp;·&nbsp; Print this page (Cmd+P / Ctrl+P) to save as PDF
</div>
</body>
</html>"""

    return Response(content=html, media_type="text/html")


def _kpi(total_open, total_critical, sla_breached, total_fixed, regressions, total_repos) -> str:
    items = [
        ("Total Open", total_open, "#1e1b4b"),
        ("Critical", total_critical, "#ef4444"),
        ("SLA Breached", sla_breached, "#f97316"),
        ("Fixed", total_fixed, "#22c55e"),
        ("Regressions", regressions, "#8b5cf6"),
        ("Repositories", total_repos, "#6366f1"),
    ]
    cards = "".join(
        f'<div class="kpi"><div class="num" style="color:{color}">{val}</div>'
        f'<div class="label">{label}</div></div>'
        for label, val, color in items
    )
    return f'<div class="kpi-grid">{cards}</div>'
