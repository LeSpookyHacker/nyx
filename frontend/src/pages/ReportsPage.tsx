import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { reportsApi } from '../api/reports'
import { dashboardApi } from '../api/dashboard'
import { Download, FileText, TrendingUp, Loader2, Newspaper, Calendar, ExternalLink, AlertTriangle } from 'lucide-react'
import type { AutoPrDigest, DigestItem } from '../types'

const COMPLIANCE_FRAMEWORKS = [
  { id: 'pci-dss', name: 'PCI DSS' },
  { id: 'nist-800-53', name: 'NIST 800-53' },
  { id: 'cis-controls', name: 'CIS Controls' },
  { id: 'owasp-top-10', name: 'OWASP Top 10' },
  { id: 'soc-2', name: 'SOC 2' },
]

/** Report generation page for executive summaries and compliance exports. */
export default function ReportsPage() {
  const [execDays, setExecDays] = useState(30)
  const [compFramework, setCompFramework] = useState('pci-dss')
  const [compDays, setCompDays] = useState(30)
  const [generating, setGenerating] = useState(false)

  const { data: summary } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => dashboardApi.getSummary(),
  })

  const { data: trends } = useQuery({
    queryKey: ['dashboard-trends', execDays],
    queryFn: () => dashboardApi.getTrends(execDays),
  })

  const handleExecutiveReport = async () => {
    setGenerating(true)
    try {
      await reportsApi.downloadExecutiveReport(execDays)
    } finally {
      setGenerating(false)
    }
  }

  const totalOpen = summary ? Object.values(summary.open_by_severity).reduce((a, b) => a + b, 0) : 0
  const fixedFindings = trends?.data.reduce((a: number, d: { fixed_findings: number }) => a + d.fixed_findings, 0) || 0

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-2">
        <FileText size={18} className="text-nyx-amethyst" />
        <h1 className="text-nyx-moonbeam font-bold text-lg">Reports</h1>
      </div>

      {/* Auto PR Daily Digest */}
      <DailyDigestSection />

      {/* Executive Report */}
      <div className="nyx-card p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-nyx-moonbeam font-semibold text-base mb-1">Executive Security Report</h2>
            <p className="text-nyx-mist text-sm">
              Comprehensive overview of your security posture including trends, SLA performance, top vulnerabilities, repository risk, and compliance coverage.
            </p>
          </div>
          <FileText size={32} className="text-nyx-iris/40 shrink-0 ml-4" />
        </div>

        {/* Preview stats */}
        {summary && (
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-nyx-dusk rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-nyx-moonbeam">{totalOpen.toLocaleString()}</p>
              <p className="text-nyx-mist text-xs mt-0.5">Open Findings</p>
            </div>
            <div className="bg-nyx-dusk rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{fixedFindings}</p>
              <p className="text-nyx-mist text-xs mt-0.5">Fixed (period)</p>
            </div>
            <div className="bg-nyx-dusk rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{summary.open_by_severity.critical}</p>
              <p className="text-nyx-mist text-xs mt-0.5">Critical Open</p>
            </div>
          </div>
        )}

        <div className="flex items-center gap-3">
          <div>
            <label className="text-nyx-mist text-sm mb-1 block">Date Range</label>
            <select className="nyx-input" value={execDays} onChange={e => setExecDays(Number(e.target.value))}>
              <option value={30}>Last 30 days</option>
              <option value={60}>Last 60 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>
          <button
            onClick={handleExecutiveReport}
            disabled={generating}
            className="nyx-btn-primary mt-5"
          >
            {generating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>

        <p className="text-nyx-mist/50 text-xs flex items-center gap-1">
          <FileText size={11} />
          Report opens in a new tab. Use Cmd+P / Ctrl+P to save as PDF.
        </p>
      </div>

      {/* Compliance Trend Report */}
      <div className="nyx-card p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-nyx-moonbeam font-semibold text-base mb-1">Compliance Trend Analysis</h2>
            <p className="text-nyx-mist text-sm">
              Track how your compliance coverage changes over time for specific frameworks.
            </p>
          </div>
          <TrendingUp size={32} className="text-nyx-iris/40 shrink-0 ml-4" />
        </div>

        <div className="flex items-center gap-3">
          <div>
            <label className="text-nyx-mist text-sm mb-1 block">Framework</label>
            <select className="nyx-input" value={compFramework} onChange={e => setCompFramework(e.target.value)}>
              {COMPLIANCE_FRAMEWORKS.map(f => (
                <option key={f.id} value={f.id}>{f.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-nyx-mist text-sm mb-1 block">Period</label>
            <select className="nyx-input" value={compDays} onChange={e => setCompDays(Number(e.target.value))}>
              <option value={30}>Last 30 days</option>
              <option value={60}>Last 60 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>
        </div>

        <ComplianceTrendPreview frameworkId={compFramework} days={compDays} />
      </div>

      {/* Info card */}
      <div className="nyx-card p-4 border border-nyx-iris/20">
        <h3 className="text-nyx-moonbeam font-semibold text-sm mb-2">About Reports</h3>
        <ul className="text-nyx-mist text-sm space-y-1">
          <li>• Executive reports are generated server-side from live data</li>
          <li>• Reports include KPIs, trends, top vulnerabilities, repo risk, and compliance</li>
          <li>• Use browser Print (Cmd+P / Ctrl+P) → "Save as PDF" to export</li>
          <li>• Compliance trends are approximated from finding open/close timestamps</li>
        </ul>
      </div>
    </div>
  )
}

// ── Daily Digest ──────────────────────────────────────────────────────────────

const SEVERITY_PILL_CLASSES: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
  HIGH:     'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  MEDIUM:   'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  LOW:      'bg-green-500/20 text-green-400 border border-green-500/30',
  INFO:     'bg-slate-500/20 text-slate-400 border border-slate-500/30',
}

function DailyDigestSection() {
  const [generating, setGenerating] = useState(false)

  const { data, isLoading, isError } = useQuery<AutoPrDigest>({
    queryKey: ['auto-pr-digest'],
    queryFn: () => reportsApi.getDailyDigest(),
    refetchInterval: 5 * 60 * 1000, // refresh every 5 min so digest stays live
  })

  const handleDigestReport = async () => {
    setGenerating(true)
    try {
      await reportsApi.downloadDailyDigestReport()
    } finally {
      setGenerating(false)
    }
  }

  const today = new Date().toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
  })

  return (
    <div className="nyx-card p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-nyx-moonbeam font-semibold text-base mb-1">Auto PR Daily Digest</h2>
          <p className="text-nyx-mist text-sm flex items-center gap-1.5">
            <Calendar size={13} className="shrink-0" />
            {today}
          </p>
        </div>
        <Newspaper size={32} className="text-nyx-iris/40 shrink-0 ml-4" />
      </div>

      {isLoading && (
        <p className="text-nyx-mist text-sm animate-pulse">Loading digest...</p>
      )}
      {isError && (
        <p className="text-red-400 text-sm flex items-center gap-1.5">
          <AlertTriangle size={14} /> Failed to load digest data.
        </p>
      )}

      {data && (
        <>
          {/* KPI strip */}
          <div className="grid grid-cols-5 gap-3">
            {([
              { label: 'Processed Today', value: data.totals.processed,   color: 'text-nyx-moonbeam' },
              { label: 'PRs Created',     value: data.totals.prs_created,  color: 'text-nyx-amethyst' },
              { label: 'Advisories',      value: data.totals.advisories,   color: 'text-yellow-400' },
              { label: 'Skipped',         value: data.totals.skipped,       color: 'text-nyx-mist' },
              { label: 'Failed',          value: data.totals.failed,        color: 'text-red-400' },
            ] as const).map(({ label, value, color }) => (
              <div key={label} className="bg-nyx-dusk rounded-lg p-3 text-center">
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
                <p className="text-nyx-mist text-xs mt-0.5">{label}</p>
              </div>
            ))}
          </div>

          {/* Severity pills — only rendered when there's activity */}
          {Object.keys(data.by_severity).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {(Object.entries(data.by_severity) as [string, { processed: number }][]).map(
                ([sev, bucket]) => (
                  <span
                    key={sev}
                    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${SEVERITY_PILL_CLASSES[sev] ?? ''}`}
                  >
                    {sev} · {bucket.processed}
                  </span>
                )
              )}
            </div>
          )}

          {/* Repo breakdown table */}
          {data.by_repo.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-nyx-mist text-xs border-b border-white/10">
                    <th className="text-left pb-2 font-medium">Repository</th>
                    <th className="text-right pb-2 font-medium">PRs</th>
                    <th className="text-right pb-2 font-medium">Advisories</th>
                    <th className="text-right pb-2 font-medium">Skipped</th>
                    <th className="text-right pb-2 font-medium">Failed</th>
                    <th className="text-right pb-2 font-medium">Total</th>
                  </tr>
                </thead>
                <tbody>
                  {data.by_repo.map(row => (
                    <tr key={row.repo} className="border-b border-white/5 last:border-0">
                      <td className="py-1.5 text-nyx-moonbeam font-mono text-xs">{row.repo}</td>
                      <td className="py-1.5 text-right text-nyx-amethyst">{row.prs}</td>
                      <td className="py-1.5 text-right text-yellow-400">{row.advisories}</td>
                      <td className="py-1.5 text-right text-nyx-mist">{row.skipped}</td>
                      <td className="py-1.5 text-right text-red-400">{row.failed}</td>
                      <td className="py-1.5 text-right text-nyx-mist/60">{row.total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Activity feed */}
          {data.items.length === 0 ? (
            <p className="text-nyx-mist/60 text-sm text-center py-4">No Auto PR activity today.</p>
          ) : (
            <div className="space-y-1 max-h-[200px] overflow-y-auto pr-1">
              {data.total_count > data.items.length && (
                <p className="text-nyx-mist/60 text-xs mb-2">
                  Showing {data.items.length} of {data.total_count} items
                </p>
              )}
              {data.items.map(item => (
                <DigestFeedItem key={`${item.finding_id}-${item.status}`} item={item} />
              ))}
            </div>
          )}
        </>
      )}

      {/* Export */}
      <div className="pt-2 border-t border-nyx-iris/10 space-y-2">
        <button
          onClick={handleDigestReport}
          disabled={generating}
          className="nyx-btn-primary"
        >
          {generating ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
          {generating ? 'Generating...' : 'Export as PDF'}
        </button>
        <p className="text-nyx-mist/50 text-xs flex items-center gap-1">
          <FileText size={11} />
          Report opens in a new tab. Use Cmd+P / Ctrl+P to save as PDF.
        </p>
      </div>
    </div>
  )
}

function DigestFeedItem({ item }: { item: DigestItem }) {
  const typeChip =
    item.type === 'pr'          ? 'bg-nyx-amethyst/20 text-nyx-amethyst' :
    item.type === 'advisory'    ? 'bg-yellow-500/20 text-yellow-400' :
    item.type === 'skipped'     ? 'bg-nyx-dusk text-nyx-mist' :
    item.type === 'in_progress' ? 'bg-blue-500/20 text-blue-400' :
                                  'bg-red-500/20 text-red-400'

  const typeLabel =
    item.type === 'pr'          ? 'PR' :
    item.type === 'advisory'    ? 'ADVISORY' :
    item.type === 'skipped'     ? 'SKIPPED' :
    item.type === 'in_progress' ? 'IN PROGRESS' :
                                  'FAILED'

  return (
    <div className="flex items-center gap-2 py-1 text-sm">
      <span className={`nyx-badge severity-${item.severity.toLowerCase()} shrink-0`}>
        {item.severity[0]}
      </span>
      <span className="text-nyx-moonbeam truncate flex-1 min-w-0" title={item.title}>
        {item.title}
      </span>
      <span className="text-nyx-mist/60 text-xs font-mono shrink-0">
        {item.repo.split('/')[1]}
      </span>
      <span className={`text-xs px-1.5 py-0.5 rounded font-medium shrink-0 ${typeChip}`}>
        {typeLabel}
      </span>
      {item.url ? (
        <a
          href={item.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-nyx-iris hover:text-nyx-amethyst shrink-0"
          title="Open in GitHub"
        >
          <ExternalLink size={13} />
        </a>
      ) : (
        <span className="w-[13px] shrink-0" />
      )}
    </div>
  )
}

// ── Compliance Trend Preview ──────────────────────────────────────────────────

function ComplianceTrendPreview({ frameworkId, days }: { frameworkId: string; days: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ['compliance-trends', frameworkId, days],
    queryFn: () => dashboardApi.getComplianceTrends(frameworkId, days),
  })

  if (isLoading) return <p className="text-nyx-mist text-sm animate-pulse">Loading trend data...</p>
  if (!data?.data?.length) return <p className="text-nyx-mist text-sm">No trend data available yet.</p>

  const latest = data.data[data.data.length - 1]
  const earliest = data.data[0]
  const delta = latest.coverage_pct - earliest.coverage_pct

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-nyx-dusk rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-nyx-amethyst">{latest.coverage_pct}%</p>
          <p className="text-nyx-mist text-xs mt-0.5">Current Coverage</p>
        </div>
        <div className="bg-nyx-dusk rounded-lg p-3 text-center">
          <p className={`text-2xl font-bold ${delta >= 0 ? 'text-green-400' : 'text-red-400'}`}>
            {delta >= 0 ? '+' : ''}{delta.toFixed(1)}%
          </p>
          <p className="text-nyx-mist text-xs mt-0.5">Change ({days}d)</p>
        </div>
        <div className="bg-nyx-dusk rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-orange-400">{latest.open_findings}</p>
          <p className="text-nyx-mist text-xs mt-0.5">Open Findings</p>
        </div>
      </div>
    </div>
  )
}
