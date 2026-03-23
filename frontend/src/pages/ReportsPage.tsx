import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { reportsApi } from '../api/reports'
import { dashboardApi } from '../api/dashboard'
import { Download, FileText, TrendingUp } from 'lucide-react'

const COMPLIANCE_FRAMEWORKS = [
  { id: 'pci-dss', name: 'PCI DSS' },
  { id: 'nist-800-53', name: 'NIST 800-53' },
  { id: 'cis-controls', name: 'CIS Controls' },
  { id: 'owasp-top-10', name: 'OWASP Top 10' },
  { id: 'soc-2', name: 'SOC 2' },
]

export default function ReportsPage() {
  const [execDays, setExecDays] = useState(30)
  const [compFramework, setCompFramework] = useState('pci-dss')
  const [compDays, setCompDays] = useState(30)

  const { data: summary } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: () => dashboardApi.getSummary(),
  })

  const { data: trends } = useQuery({
    queryKey: ['dashboard-trends', execDays],
    queryFn: () => dashboardApi.getTrends(execDays),
  })

  const handleExecutiveReport = () => {
    reportsApi.downloadExecutiveReport(execDays)
  }

  const totalOpen = summary ? Object.values(summary.open_by_severity).reduce((a, b) => a + b, 0) : 0
  const fixedFindings = trends?.data.reduce((a: number, d: { fixed_findings: number }) => a + d.fixed_findings, 0) || 0

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-2">
        <FileText size={18} className="text-nyx-amethyst" />
        <h1 className="text-nyx-moonbeam font-bold text-lg">Reports</h1>
      </div>

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
            className="nyx-btn-primary mt-5"
          >
            <Download size={14} />
            Generate Report
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
