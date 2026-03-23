/**
 * Per-repository trend charts.
 * Used inside RepositoryDetailPage's "Trends" tab.
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { dashboardApi } from '../../api/dashboard'
import { repositoriesApi } from '../../api/repositories'
import type { Scan } from '../../types'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import { clsx } from 'clsx'

// ── Palette ───────────────────────────────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#6b7280',
}

const SCANNER_PALETTE = [
  '#8b5cf6', '#6366f1', '#0ea5e9', '#10b981', '#f59e0b', '#ef4444', '#ec4899',
]

const CHART_GRID = '#2d2447'
const CHART_TICK = '#7c6fa0'
const TOOLTIP_BG = '#1a1330'
const TOOLTIP_BORDER = '#3d2f6b'

// ── Custom Tooltip ─────────────────────────────────────────────────────────────
function NyxTooltip({ active, payload, label }: {
  active?: boolean
  payload?: { name: string; value: number; color: string }[]
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border text-xs p-2.5 shadow-xl min-w-[120px]"
      style={{ background: TOOLTIP_BG, borderColor: TOOLTIP_BORDER }}>
      {label && <p className="text-[#a89cc8] mb-1.5 font-medium">{label}</p>}
      {payload.map(p => (
        <div key={p.name} className="flex items-center justify-between gap-3">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-full" style={{ background: p.color }} />
            <span style={{ color: '#c4b5e8' }}>{p.name}</span>
          </span>
          <span className="font-semibold" style={{ color: '#e8deff' }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────
function ChartCard({ title, children, className }: {
  title: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={clsx('nyx-card p-5', className)}>
      <h3 className="text-nyx-mist text-xs uppercase tracking-wider font-semibold mb-4">{title}</h3>
      {children}
    </div>
  )
}

// ── Day range picker ──────────────────────────────────────────────────────────
const DAY_OPTIONS = [30, 60, 90] as const
type DayRange = typeof DAY_OPTIONS[number]

// ── Main component ────────────────────────────────────────────────────────────
export default function RepoTrends({ repoId }: { repoId: string }) {
  const [days, setDays] = useState<DayRange>(30)

  const { data: trends } = useQuery({
    queryKey: ['repo-trends', repoId, days],
    queryFn: () => dashboardApi.getTrends(days, repoId),
  })

  const { data: summary } = useQuery({
    queryKey: ['repo-summary', repoId],
    queryFn: () => dashboardApi.getSummary(repoId),
  })

  const { data: sevTrend } = useQuery({
    queryKey: ['repo-sev-trend', repoId, days],
    queryFn: () => dashboardApi.getSeverityTrend(days, repoId),
  })

  const { data: mttr } = useQuery({
    queryKey: ['repo-mttr', repoId],
    queryFn: () => dashboardApi.getMttr(repoId),
  })

  const { data: scans = [] } = useQuery({
    queryKey: ['repo-scans', repoId],
    queryFn: () => repositoriesApi.getScans(repoId),
  })

  // ── Data derivation ───────────────────────────────────────────────────────

  // New vs Fixed over time (fill gaps so every day has a value)
  const trendPoints = (trends?.data ?? []).map((d: { date: string; new_findings: number; fixed_findings: number }) => ({
    date: d.date.slice(5), // "MM-DD"
    New: d.new_findings,
    Fixed: d.fixed_findings,
  }))

  // Severity donut
  const sevSummary: Record<string, number> = summary?.open_by_severity ?? {}
  const sevDonut = Object.entries(SEV_COLORS)
    .map(([k, color]) => ({ name: k, value: sevSummary[k.toLowerCase()] ?? 0, color }))
    .filter(d => d.value > 0)

  // Scanner donut
  const scannerDonut = (summary?.by_scanner ?? []).map(
    (s: { scanner: string; count: number }, i: number) => ({
      name: s.scanner,
      value: s.count,
      color: SCANNER_PALETTE[i % SCANNER_PALETTE.length],
    })
  )

  // Severity stacked bars per week
  const sevWeekly = (sevTrend?.data ?? []).map((d: Record<string, number | string>) => ({
    week: String(d.week).replace(/^\d{4}-/, 'W'),
    Critical: d.CRITICAL as number,
    High: d.HIGH as number,
    Medium: d.MEDIUM as number,
    Low: d.LOW as number,
    Info: d.INFO as number,
  }))

  // Findings per scan (last 20, oldest first)
  const scanBars = [...(scans as Scan[])]
    .filter(s => s.status === 'COMPLETED')
    .slice(0, 20)
    .reverse()
    .map((s, i) => ({
      label: `#${i + 1}`,
      scanner: s.scanner,
      Total: s.finding_count,
      New: s.new_finding_count,
      Fixed: s.fixed_finding_count,
    }))

  // MTTR bar
  const mttrBars = Object.entries(mttr?.mttr_days ?? {})
    .filter(([, v]) => v !== null)
    .map(([sev, days]) => ({
      severity: sev.charAt(0).toUpperCase() + sev.slice(1),
      Days: days as number,
      fill: SEV_COLORS[sev.toUpperCase()] ?? '#6b7280',
    }))

  // Quick KPIs
  const totalOpen = Object.values(sevSummary).reduce((a: number, b) => a + (b as number), 0)
  const totalFixed = summary?.by_status?.fixed ?? 0
  const fixRate = totalOpen + totalFixed > 0
    ? Math.round((totalFixed / (totalOpen + totalFixed)) * 100)
    : 0

  return (
    <div className="space-y-4">
      {/* KPI strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Open', value: totalOpen, color: 'text-nyx-moonbeam' },
          { label: 'Fixed', value: totalFixed, color: 'text-green-400' },
          { label: 'Fix Rate', value: `${fixRate}%`, color: fixRate >= 50 ? 'text-green-400' : 'text-orange-400' },
          { label: 'SLA Breached', value: summary?.sla_breached ?? 0, color: (summary?.sla_breached ?? 0) > 0 ? 'text-red-400' : 'text-nyx-mist' },
        ].map(({ label, value, color }) => (
          <div key={label} className="nyx-card p-4 text-center">
            <p className={clsx('text-2xl font-bold', color)}>{value}</p>
            <p className="text-nyx-mist text-xs mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* Day range toggle */}
      <div className="flex items-center gap-1">
        <span className="text-nyx-mist/60 text-xs mr-1">Period:</span>
        {DAY_OPTIONS.map(d => (
          <button
            key={d}
            onClick={() => setDays(d)}
            className={clsx('px-3 py-1 rounded text-xs font-medium transition-colors',
              days === d
                ? 'bg-nyx-eclipse text-nyx-lavender border border-nyx-iris/40'
                : 'text-nyx-mist hover:text-nyx-moonbeam')}
          >
            {d}d
          </button>
        ))}
      </div>

      {/* Row 1: New vs Fixed over time */}
      <ChartCard title={`New vs Fixed Findings — Last ${days} Days`}>
        {trendPoints.length === 0 ? (
          <p className="text-nyx-mist/50 text-sm text-center py-8">No findings recorded in this period.</p>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={trendPoints} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gradNew" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradFixed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
              <XAxis dataKey="date" tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} />
              <YAxis tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip content={<NyxTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: CHART_TICK }} />
              <Area type="monotone" dataKey="New" stroke="#8b5cf6" fill="url(#gradNew)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="Fixed" stroke="#10b981" fill="url(#gradFixed)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* Row 2: Severity breakdown by week */}
      <ChartCard title={`Weekly Severity Breakdown — Last ${days} Days`}>
        {sevWeekly.length === 0 ? (
          <p className="text-nyx-mist/50 text-sm text-center py-8">No findings recorded in this period.</p>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={sevWeekly} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} vertical={false} />
              <XAxis dataKey="week" tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} />
              <YAxis tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip content={<NyxTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: CHART_TICK }} />
              <Bar dataKey="Critical" stackId="a" fill={SEV_COLORS.CRITICAL} radius={[0, 0, 0, 0]} />
              <Bar dataKey="High" stackId="a" fill={SEV_COLORS.HIGH} />
              <Bar dataKey="Medium" stackId="a" fill={SEV_COLORS.MEDIUM} />
              <Bar dataKey="Low" stackId="a" fill={SEV_COLORS.LOW} />
              <Bar dataKey="Info" stackId="a" fill={SEV_COLORS.INFO} radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* Row 3: Donut charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ChartCard title="Open Findings by Severity">
          {sevDonut.length === 0 ? (
            <p className="text-nyx-mist/50 text-sm text-center py-8">No open findings.</p>
          ) : (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={180}>
                <PieChart>
                  <Pie data={sevDonut} cx="50%" cy="50%" innerRadius={50} outerRadius={75}
                    dataKey="value" paddingAngle={2} strokeWidth={0}>
                    {sevDonut.map(entry => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<NyxTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5">
                {sevDonut.map(d => (
                  <div key={d.name} className="flex items-center gap-2 text-xs">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: d.color }} />
                    <span className="text-nyx-mist w-16">{d.name}</span>
                    <span className="font-semibold text-nyx-moonbeam">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </ChartCard>

        <ChartCard title="Open Findings by Scanner">
          {scannerDonut.length === 0 ? (
            <p className="text-nyx-mist/50 text-sm text-center py-8">No open findings.</p>
          ) : (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={180}>
                <PieChart>
                  <Pie data={scannerDonut} cx="50%" cy="50%" innerRadius={50} outerRadius={75}
                    dataKey="value" paddingAngle={2} strokeWidth={0}>
                    {scannerDonut.map((entry: { name: string; color: string }) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<NyxTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5">
                {scannerDonut.map((d: { name: string; color: string; value: number }) => (
                  <div key={d.name} className="flex items-center gap-2 text-xs">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: d.color }} />
                    <span className="text-nyx-mist w-20 truncate">{d.name}</span>
                    <span className="font-semibold text-nyx-moonbeam">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </ChartCard>
      </div>

      {/* Row 4: Findings per scan */}
      <ChartCard title="Findings per Scan Run (last 20 completed)">
        {scanBars.length === 0 ? (
          <p className="text-nyx-mist/50 text-sm text-center py-8">No completed scans yet.</p>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={scanBars} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} vertical={false} />
              <XAxis dataKey="label" tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} />
              <YAxis tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip content={<NyxTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: CHART_TICK }} />
              <Bar dataKey="Total" fill="#6366f1" radius={[3, 3, 0, 0]} />
              <Bar dataKey="New" fill="#ef4444" radius={[3, 3, 0, 0]} />
              <Bar dataKey="Fixed" fill="#10b981" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </ChartCard>

      {/* Row 5: MTTR by severity */}
      <ChartCard title="Mean Time to Remediate by Severity (days)">
        {mttrBars.length === 0 ? (
          <p className="text-nyx-mist/50 text-sm text-center py-8">No resolved findings yet — MTTR will appear once findings are fixed.</p>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <BarChart
              data={mttrBars}
              layout="vertical"
              margin={{ top: 4, right: 24, left: 16, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} horizontal={false} />
              <XAxis type="number" tick={{ fill: CHART_TICK, fontSize: 10 }} tickLine={false} axisLine={false}
                label={{ value: 'days', position: 'insideRight', offset: 8, fill: CHART_TICK, fontSize: 10 }} />
              <YAxis type="category" dataKey="severity" tick={{ fill: CHART_TICK, fontSize: 11 }} tickLine={false} axisLine={false} width={60} />
              <Tooltip content={<NyxTooltip />} />
              <Bar dataKey="Days" radius={[0, 4, 4, 0]}>
                {mttrBars.map((entry) => (
                  <Cell key={entry.severity} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </ChartCard>
    </div>
  )
}
