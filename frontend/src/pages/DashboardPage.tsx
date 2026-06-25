import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { dashboardApi } from '../api/dashboard'
import {
  AreaChart, Area, BarChart, Bar, Cell, PieChart, Pie,
  ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid
} from 'recharts'
import { AlertOctagon, Clock, Shield, TrendingUp, Flame, RotateCcw, AlertTriangle, GitBranch, Plus } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { SEVERITY_COLORS, SCANNER_COLORS } from '../constants/theme'
import LoadingSkeleton from '../components/ui/LoadingSkeleton'
import AutoPrActivityCard from '../components/dashboard/AutoPrActivityCard'

function KpiCard({ label, value, icon: Icon, color, onClick }: {
  label: string; value: string | number; icon: React.ElementType; color: string; onClick?: () => void
}) {
  return (
    <div
      className={`nyx-card p-5 transition-colors ${onClick ? 'cursor-pointer hover:border-nyx-amethyst/50 hover:bg-nyx-twilight/20' : ''}`}
      onClick={onClick}
    >
      <div className="flex items-center justify-between mb-3">
        <p className="text-nyx-mist text-sm">{label}</p>
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
          <Icon size={16} className="text-white" />
        </div>
      </div>
      <p className="text-3xl font-bold text-nyx-moonbeam">{value}</p>
      {onClick && <p className="text-nyx-mist/50 text-[10px] mt-2 uppercase tracking-wide">Click to explore →</p>}
    </div>
  )
}

/** Executive security dashboard with KPIs, severity breakdown, trends, and risk insights. */
export default function DashboardPage() {
  const navigate = useNavigate()
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => dashboardApi.getSummary(),
    refetchInterval: 60_000,
  })

  const { data: trends } = useQuery({
    queryKey: ['dashboard-trends', 30],
    queryFn: () => dashboardApi.getTrends(30),
  })

  const { data: topVulns } = useQuery({
    queryKey: ['dashboard-top-vulns'],
    queryFn: () => dashboardApi.getTopVulnerabilities(8),
  })

  const { data: repoRisk } = useQuery({
    queryKey: ['dashboard-repo-risk'],
    queryFn: () => dashboardApi.getRepoRisk(),
  })

  const { data: mttr } = useQuery({
    queryKey: ['dashboard-mttr'],
    queryFn: () => dashboardApi.getMttr(),
  })

  const { data: hotRepos } = useQuery({
    queryKey: ['dashboard-hot-repos'],
    queryFn: () => dashboardApi.getHotRepos(7, 5),
  })

  const { data: coverageGaps } = useQuery({
    queryKey: ['dashboard-coverage-gaps'],
    queryFn: () => dashboardApi.getCoverageGaps(),
  })

  const { data: regressions } = useQuery({
    queryKey: ['dashboard-regressions'],
    queryFn: () => dashboardApi.getRegressions(7, 5),
  })

  const { data: orgRiskHistory } = useQuery({
    queryKey: ['dashboard-org-risk-history'],
    queryFn: () => dashboardApi.getOrgRiskHistory(30),
  })

  const severityDonutData = useMemo(() => summary
    ? Object.entries(summary.open_by_severity)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: k.toUpperCase(), value: v, color: SEVERITY_COLORS[k as keyof typeof SEVERITY_COLORS] }))
    : [], [summary])

  const totalOpen = useMemo(() => summary
    ? Object.values(summary.open_by_severity).reduce((a, b) => a + b, 0)
    : 0, [summary])

  if (summaryLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSkeleton lines={5} />
      </div>
    )
  }

  // Empty state — no repositories registered yet (fresh install onboarding)
  if (summary && (summary.total_repositories || 0) === 0) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="nyx-card p-10 max-w-xl text-center space-y-5">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-nyx-iris/20 flex items-center justify-center">
            <GitBranch size={32} className="text-nyx-amethyst" />
          </div>
          <div className="space-y-2">
            <h2 className="text-2xl font-semibold text-nyx-moonbeam">Welcome to Nyx</h2>
            <p className="text-nyx-mist text-sm leading-relaxed">
              You haven't registered any repositories yet. Add your first repo to start ingesting
              scan results, prioritizing findings, and opening AI-generated remediation PRs.
            </p>
          </div>
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={() => navigate('/repositories')}
              className="nyx-btn-primary gap-2"
            >
              <Plus size={16} />
              Add your first repository
            </button>
          </div>
          <p className="text-nyx-mist/60 text-xs">
            Or load demo data from the CLI:{' '}
            <code className="text-nyx-lavender font-mono">
              docker compose exec backend python scripts/seed_demo_data.py
            </code>
          </p>
        </div>
      </div>
    )
  }

  const regressionCount = (regressions || []).length

  return (
    <div className="space-y-6">
      {/* Regression alert banner */}
      {regressionCount > 0 && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-orange-900/20 border border-orange-500/30">
          <RotateCcw size={16} className="text-orange-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <span className="text-orange-300 font-medium text-sm">{regressionCount} regression{regressionCount !== 1 ? 's' : ''} detected</span>
            <span className="text-orange-400/70 text-sm"> — previously fixed findings have re-appeared in the last 7 days</span>
          </div>
          <button onClick={() => navigate('/findings?is_regression=true')} className="text-orange-300 text-xs hover:text-orange-200 shrink-0 underline">
            View →
          </button>
        </div>
      )}

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard
          label="Total Open Findings"
          value={totalOpen.toLocaleString()}
          icon={Shield}
          color="bg-nyx-iris"
          onClick={() => navigate('/findings')}
        />
        <KpiCard
          label="Critical"
          value={summary?.open_by_severity.critical || 0}
          icon={AlertOctagon}
          color="bg-red-600"
          onClick={() => navigate('/findings?severity=CRITICAL')}
        />
        <KpiCard
          label="SLA Breached"
          value={summary?.sla_breached || 0}
          icon={Clock}
          color="bg-orange-600"
          onClick={() => navigate('/findings')}
        />
        <KpiCard
          label="Repositories"
          value={summary?.total_repositories || 0}
          icon={TrendingUp}
          color="bg-nyx-stardust"
          onClick={() => navigate('/repositories')}
        />
        <KpiCard
          label="Regressions (7d)"
          value={regressionCount}
          icon={RotateCcw}
          color="bg-orange-700"
          onClick={() => navigate('/findings?is_regression=true')}
        />
      </div>

      {/* Auto PR Mode activity — only renders if a repo has Auto PR Mode enabled */}
      <AutoPrActivityCard />

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity Donut */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Open by Severity</h3>
          <div className="flex items-center gap-4">
            <ResponsiveContainer width={140} height={140}>
              <PieChart>
                <Pie
                  data={severityDonutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={65}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityDonutData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
                  labelStyle={{ color: '#ede9fe' }}
                  itemStyle={{ color: '#c4b5fd' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-1.5 text-sm flex-1">
              {severityDonutData.map((entry) => (
                <button
                  key={entry.name}
                  className="w-full flex items-center justify-between rounded px-1 py-0.5 hover:bg-nyx-twilight/40 transition-colors cursor-pointer group"
                  onClick={() => navigate(`/findings?severity=${entry.name}`)}
                >
                  <span className="flex items-center gap-1.5 text-nyx-mist group-hover:text-nyx-moonbeam transition-colors">
                    <span className="w-2 h-2 rounded-full" style={{ background: entry.color }} />
                    {entry.name}
                  </span>
                  <span className="text-nyx-moonbeam font-semibold">{entry.value}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Scanner Breakdown */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Findings by Scanner</h3>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={summary?.by_scanner || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" />
              <XAxis dataKey="scanner" tick={{ fill: '#a78bfa', fontSize: 10 }} />
              <YAxis tick={{ fill: '#a78bfa', fontSize: 10 }} width={30} />
              <Tooltip
                contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
                labelStyle={{ color: '#ede9fe' }}
                itemStyle={{ color: '#c4b5fd' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {(summary?.by_scanner || []).map((_, i) => (
                  <Cell key={i} fill={SCANNER_COLORS[i % SCANNER_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* MTTR */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Mean Time to Remediate</h3>
          <div className="space-y-3">
            {mttr?.mttr_days && Object.entries(mttr.mttr_days).map(([sev, days]) => (
              <div key={sev} className="flex items-center justify-between">
                <span className="text-nyx-mist text-sm capitalize">{sev}</span>
                <span className="text-nyx-moonbeam font-semibold text-sm">
                  {days !== null ? `${days}d` : 'N/A'}
                </span>
              </div>
            ))}
            {!mttr?.mttr_days && (
              <p className="text-nyx-mist text-sm">No resolved findings yet.</p>
            )}
          </div>
        </div>
      </div>

      {/* Trend Chart */}
      <div className="nyx-card p-5">
        <h3 className="text-nyx-moonbeam font-semibold mb-4">Finding Trends (30 days)</h3>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={trends?.data || []}>
            <defs>
              <linearGradient id="newGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#7c3aed" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="fixedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" />
            <XAxis dataKey="date" tick={{ fill: '#a78bfa', fontSize: 10 }} />
            <YAxis tick={{ fill: '#a78bfa', fontSize: 10 }} width={30} />
            <Tooltip
              contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
              labelStyle={{ color: '#ede9fe' }}
              itemStyle={{ color: '#c4b5fd' }}
            />
            <Area type="monotone" dataKey="new_findings" stroke="#7c3aed" fill="url(#newGrad)" name="New" strokeWidth={2} />
            <Area type="monotone" dataKey="fixed_findings" stroke="#22c55e" fill="url(#fixedGrad)" name="Fixed" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Vulnerabilities */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Top Vulnerability Types</h3>
          <div className="space-y-2">
            {(topVulns || []).map((v: { rule_id: string; title: string; scanner: string; count: number }, i: number) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-nyx-iris/10 last:border-0">
                <div className="min-w-0 flex-1">
                  <p className="text-nyx-moonbeam text-sm font-medium truncate">{v.title}</p>
                  <p className="text-nyx-mist text-xs">{v.scanner} · {v.rule_id}</p>
                </div>
                <span className="text-nyx-amethyst font-bold text-sm ml-3 shrink-0">{v.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Repo Risk */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Repository Risk</h3>
          <div className="space-y-2">
            {(repoRisk || []).slice(0, 8).map((r: {
              id: string; name: string; risk_score: number
              open_critical: number; open_high: number; last_scan_at: string | null
            }) => (
              <div
                key={r.id}
                className="flex items-center gap-3 py-1.5 border-b border-nyx-iris/10 last:border-0 cursor-pointer hover:bg-nyx-twilight/20 rounded px-1 -mx-1 transition-colors group"
                onClick={() => navigate(`/repositories/${r.id}`)}
              >
                <div className="flex-1 min-w-0">
                  <p className="text-nyx-moonbeam text-sm font-medium truncate group-hover:text-nyx-amethyst transition-colors">{r.name}</p>
                  <p className="text-nyx-mist text-xs">
                    {r.open_critical > 0 && (
                      <button
                        className="text-red-400 hover:text-red-300 transition-colors"
                        onClick={e => { e.stopPropagation(); navigate(`/findings?severity=CRITICAL&repository_id=${r.id}&repo_name=${encodeURIComponent(r.name)}`) }}
                      >
                        {r.open_critical} critical ·{' '}
                      </button>
                    )}
                    {r.open_high > 0 && (
                      <button
                        className="text-orange-400 hover:text-orange-300 transition-colors"
                        onClick={e => { e.stopPropagation(); navigate(`/findings?severity=HIGH&repository_id=${r.id}&repo_name=${encodeURIComponent(r.name)}`) }}
                      >
                        {r.open_high} high
                      </button>
                    )}
                    {r.last_scan_at && (
                      <span> · {formatDistanceToNow(new Date(r.last_scan_at))} ago</span>
                    )}
                  </p>
                </div>
                <div className="shrink-0 text-right">
                  <p className="text-nyx-amethyst font-bold text-sm">{Math.round(r.risk_score)}</p>
                  <p className="text-nyx-mist text-[10px]">risk</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Org Risk History + Hot Repos Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Org Risk Over Time */}
        <div className="nyx-card p-5">
          <h3 className="text-nyx-moonbeam font-semibold mb-4">Org Risk Score (30 days)</h3>
          {(orgRiskHistory?.data || []).length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={orgRiskHistory?.data || []}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" />
                <XAxis dataKey="date" tick={{ fill: '#a78bfa', fontSize: 10 }} />
                <YAxis domain={[0, 100]} tick={{ fill: '#a78bfa', fontSize: 10 }} width={30} />
                <Tooltip
                  contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
                  labelStyle={{ color: '#ede9fe' }}
                  itemStyle={{ color: '#c4b5fd' }}
                />
                <Area type="monotone" dataKey="avg_risk_score" stroke="#f97316" fill="url(#riskGrad)" name="Avg Risk" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-nyx-mist text-sm">No risk history yet — data accumulates daily.</p>
          )}
        </div>

        {/* Hot Repos */}
        <div className="nyx-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Flame size={16} className="text-orange-400" />
            <h3 className="text-nyx-moonbeam font-semibold">Hot Repos (last 7 days)</h3>
          </div>
          {(hotRepos || []).length === 0 ? (
            <p className="text-nyx-mist text-sm">No new findings in the last 7 days.</p>
          ) : (
            <div className="space-y-2">
              {(hotRepos || []).map((r: { id: string; name: string; new_findings: number; open_critical: number }) => (
                <div
                  key={r.id}
                  className="flex items-center justify-between py-1.5 border-b border-nyx-iris/10 last:border-0 cursor-pointer hover:bg-nyx-twilight/20 rounded px-1 -mx-1 transition-colors"
                  onClick={() => navigate(`/repositories/${r.id}`)}
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-nyx-moonbeam text-sm truncate">{r.name}</p>
                    {r.open_critical > 0 && <p className="text-red-400 text-xs">{r.open_critical} critical open</p>}
                  </div>
                  <span className="text-orange-400 font-bold text-sm shrink-0">+{r.new_findings}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Coverage Gaps */}
      {coverageGaps && (
        (coverageGaps.stale_repos?.length > 0 || coverageGaps.no_scanner_repos?.length > 0 || coverageGaps.partial_repos?.length > 0) && (
          <div className="nyx-card p-5 border border-yellow-500/20">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle size={16} className="text-yellow-400" />
              <h3 className="text-nyx-moonbeam font-semibold">Scanner Coverage Gaps</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {coverageGaps.stale_repos?.length > 0 && (
                <div>
                  <p className="text-yellow-400 text-xs font-medium mb-1.5 uppercase tracking-wide">Stale (&gt;7 days)</p>
                  {coverageGaps.stale_repos.map((r: { id: string; name: string; last_scan_at: string }) => (
                    <button key={r.id} onClick={() => navigate(`/repositories/${r.id}`)}
                      className="block text-nyx-mist text-xs hover:text-nyx-moonbeam transition-colors mb-1">
                      {r.name} · {formatDistanceToNow(new Date(r.last_scan_at))} ago
                    </button>
                  ))}
                </div>
              )}
              {coverageGaps.no_scanner_repos?.length > 0 && (
                <div>
                  <p className="text-red-400 text-xs font-medium mb-1.5 uppercase tracking-wide">No Scanners</p>
                  {coverageGaps.no_scanner_repos.map((r: { id: string; name: string }) => (
                    <button key={r.id} onClick={() => navigate(`/repositories/${r.id}`)}
                      className="block text-nyx-mist text-xs hover:text-nyx-moonbeam transition-colors mb-1">
                      {r.name}
                    </button>
                  ))}
                </div>
              )}
              {coverageGaps.partial_repos?.length > 0 && (
                <div>
                  <p className="text-nyx-mist text-xs font-medium mb-1.5 uppercase tracking-wide">Partial Coverage</p>
                  {coverageGaps.partial_repos.map((r: { id: string; name: string; scanner_count: number }) => (
                    <button key={r.id} onClick={() => navigate(`/repositories/${r.id}`)}
                      className="block text-nyx-mist text-xs hover:text-nyx-moonbeam transition-colors mb-1">
                      {r.name} · {r.scanner_count} scanner{r.scanner_count !== 1 ? 's' : ''}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )
      )}
    </div>
  )
}
