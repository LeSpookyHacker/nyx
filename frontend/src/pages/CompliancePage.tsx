import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { complianceApi, ControlReport } from '../api/compliance'
import { CheckCircle2, XCircle, AlertCircle, ChevronDown, ChevronRight, GitBranch } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { clsx } from 'clsx'

const FRAMEWORK_COLORS: Record<string, string> = {
  'pci-dss': 'text-blue-400 border-blue-400/30 bg-blue-400/5',
  'soc2': 'text-purple-400 border-purple-400/30 bg-purple-400/5',
  'hipaa': 'text-green-400 border-green-400/30 bg-green-400/5',
  'nist-csf': 'text-orange-400 border-orange-400/30 bg-orange-400/5',
  'iso27001': 'text-pink-400 border-pink-400/30 bg-pink-400/5',
}

function GaugeRing({ pct, size = 80 }: { pct: number; size?: number }) {
  const r = (size - 8) / 2
  const circumference = 2 * Math.PI * r
  const offset = circumference - (pct / 100) * circumference
  const color = pct >= 80 ? '#22c55e' : pct >= 50 ? '#eab308' : '#ef4444'

  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1a1a35" strokeWidth={7} />
      <circle
        cx={size / 2} cy={size / 2} r={r}
        fill="none" stroke={color} strokeWidth={7}
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.6s ease' }}
      />
      <text
        x={size / 2} y={size / 2}
        textAnchor="middle" dominantBaseline="central"
        style={{ transform: `rotate(90deg)`, transformOrigin: `${size / 2}px ${size / 2}px` }}
        fill={color} fontSize={size / 4.5} fontWeight="bold"
      >
        {Math.round(pct)}%
      </text>
    </svg>
  )
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-green-400',
  INFO: 'text-slate-400',
}

function ControlCard({ control, frameworkId }: { control: ControlReport; frameworkId: string }) {
  const [open, setOpen] = useState(false)

  const fixed = control.total_findings - control.open_findings
  const fixedPct = control.total_findings > 0 ? (fixed / control.total_findings) * 100 : 0

  // Only fetch findings when expanded and there are open findings
  const { data: controlFindings, isLoading: findingsLoading } = useQuery({
    queryKey: ['control-findings', frameworkId, control.id],
    queryFn: () => complianceApi.getControlFindings(frameworkId, control.id),
    enabled: open && control.open_findings > 0,
    staleTime: 60_000,
  })

  return (
    <div className={clsx(
      'border rounded-lg overflow-hidden transition-colors',
      control.is_compliant ? 'border-green-500/20' : 'border-red-500/20'
    )}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-nyx-twilight/50 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        {control.is_compliant
          ? <CheckCircle2 size={16} className="text-green-400 shrink-0" />
          : control.open_findings > 0
            ? <XCircle size={16} className="text-red-400 shrink-0" />
            : <AlertCircle size={16} className="text-yellow-400 shrink-0" />
        }
        <div className="flex-1 min-w-0">
          <p className="text-nyx-moonbeam text-sm font-medium truncate">{control.title}</p>
          {!control.is_compliant && control.open_findings > 0 && (
            <p className="text-red-400 text-xs">{control.open_findings} open finding{control.open_findings !== 1 ? 's' : ''}</p>
          )}
        </div>
        <div className="shrink-0 flex items-center gap-3">
          {control.total_findings > 0 && (
            <div className="text-right">
              <p className={clsx('text-xs font-semibold', control.is_compliant ? 'text-green-400' : 'text-red-400')}>
                {control.coverage_pct}%
              </p>
              <p className="text-nyx-mist text-[10px]">fixed</p>
            </div>
          )}
          {open ? <ChevronDown size={14} className="text-nyx-mist" /> : <ChevronRight size={14} className="text-nyx-mist" />}
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-2 border-t border-nyx-iris/10 space-y-4">
          <p className="text-nyx-mist text-xs leading-relaxed">{control.description}</p>

          {/* Finding breakdown bar */}
          {control.total_findings > 0 && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-nyx-mist">Coverage</span>
                <span className="text-nyx-mist">{control.total_findings} total findings</span>
              </div>
              <div className="w-full h-2 bg-nyx-dusk rounded-full overflow-hidden flex">
                <div className="h-full bg-green-500 transition-all" style={{ width: `${fixedPct}%` }} />
                <div className="h-full bg-red-500 transition-all" style={{ width: `${100 - fixedPct}%` }} />
              </div>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1 text-green-400">
                  <span className="w-2 h-2 rounded-full bg-green-500 inline-block" />{fixed} fixed
                </span>
                <span className="flex items-center gap-1 text-red-400">
                  <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />{control.open_findings} open
                </span>
              </div>
            </div>
          )}

          {/* Open findings grouped by repository */}
          {control.open_findings > 0 && (
            <div className="space-y-3">
              <p className="text-nyx-moonbeam text-xs font-semibold uppercase tracking-wide">
                Open Findings by Repository
              </p>
              {findingsLoading && (
                <p className="text-nyx-mist text-xs animate-pulse">Loading findings...</p>
              )}
              {controlFindings?.repositories.map(repo => (
                <div key={repo.repository_id} className="rounded-lg border border-nyx-iris/15 overflow-hidden">
                  {/* Repo header */}
                  <div className="flex items-center gap-2 px-3 py-2 bg-nyx-dusk/60">
                    <GitBranch size={12} className="text-nyx-iris/60 shrink-0" />
                    <Link
                      to={`/repositories/${repo.repository_id}`}
                      className="text-nyx-lavender text-xs font-semibold hover:text-nyx-moonbeam transition-colors"
                      onClick={e => e.stopPropagation()}
                    >
                      {repo.repository_full_name}
                    </Link>
                    <span className="ml-auto text-nyx-mist/50 text-[10px]">
                      {repo.findings.length} finding{repo.findings.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  {/* Finding rows */}
                  <div className="divide-y divide-nyx-iris/5">
                    {repo.findings.map(f => (
                      <Link
                        key={f.id}
                        to={`/findings/${f.id}`}
                        className="flex items-start gap-3 px-3 py-2.5 hover:bg-nyx-twilight/30 transition-colors group block"
                        onClick={e => e.stopPropagation()}
                      >
                        <span className={clsx('text-[10px] font-bold shrink-0 mt-0.5 w-14', SEV_COLORS[f.severity])}>
                          {f.severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-nyx-moonbeam text-xs font-medium truncate group-hover:text-nyx-amethyst transition-colors">
                            {f.title}
                          </p>
                          <p className="text-nyx-mist/60 text-[10px] mt-0.5 flex items-center gap-2">
                            <span>{f.scanner}</span>
                            {f.file_path && (
                              <span className="font-mono truncate max-w-[200px]">
                                {f.file_path}{f.line_start ? `:${f.line_start}` : ''}
                              </span>
                            )}
                            {f.cve_id && <span className="text-nyx-amethyst/70">{f.cve_id}</span>}
                          </p>
                        </div>
                        <div className="shrink-0 text-right">
                          <p className="text-nyx-amethyst text-[10px] font-bold">{f.priority_score}</p>
                          {f.first_seen_at && (
                            <p className="text-nyx-mist/40 text-[10px]">
                              {formatDistanceToNow(new Date(f.first_seen_at))} ago
                            </p>
                          )}
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Mapped CWEs and OWASP categories */}
          <div className="flex flex-wrap gap-2 pt-1">
            {control.cwe_ids.map(cwe => (
              <span key={cwe} className="text-[10px] px-1.5 py-0.5 rounded bg-nyx-eclipse text-nyx-amethyst border border-nyx-iris/20">
                {cwe}
              </span>
            ))}
            {control.owasp_categories.map(cat => (
              <span key={cat} className="text-[10px] px-1.5 py-0.5 rounded bg-orange-900/20 text-orange-400 border border-orange-500/20">
                OWASP {cat}
              </span>
            ))}
          </div>

          {control.total_findings === 0 && (
            <p className="text-nyx-mist/50 text-xs italic">No findings in scope — import scan results to assess this control.</p>
          )}
        </div>
      )}
    </div>
  )
}

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState('pci-dss')

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['compliance-summary'],
    queryFn: () => complianceApi.getSummary(),
  })

  const { data: report, isLoading: reportLoading } = useQuery({
    queryKey: ['compliance-report', selectedFramework],
    queryFn: () => complianceApi.getReport(selectedFramework),
  })

  const failingControls = report?.controls.filter(c => !c.is_compliant) ?? []
  const passingControls = report?.controls.filter(c => c.is_compliant) ?? []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-nyx-moonbeam text-xl font-bold">Compliance</h1>
        <p className="text-nyx-mist text-sm mt-1">
          Map security findings to regulatory and industry frameworks.
        </p>
      </div>

      {/* Summary cards */}
      {summaryLoading ? (
        <div className="text-nyx-mist text-sm animate-pulse">Loading frameworks...</div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          {(summary ?? []).map(f => (
            <button
              key={f.framework_id}
              onClick={() => setSelectedFramework(f.framework_id)}
              className={clsx(
                'nyx-card p-4 text-left border transition-all',
                selectedFramework === f.framework_id
                  ? 'border-nyx-iris/60 bg-nyx-eclipse/60'
                  : 'border-transparent hover:border-nyx-iris/30',
              )}
            >
              <div className="flex items-start justify-between gap-2 mb-3">
                <p className={clsx('text-xs font-semibold leading-tight', FRAMEWORK_COLORS[f.framework_id]?.split(' ')[0])}>
                  {f.name}
                </p>
                <GaugeRing pct={f.compliance_pct} size={52} />
              </div>
              <p className="text-nyx-mist text-xs">
                {f.compliant_controls}/{f.total_controls} controls
              </p>
              {f.open_findings > 0 && (
                <p className="text-red-400 text-xs mt-0.5">{f.open_findings} open</p>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Detail panel */}
      {reportLoading ? (
        <div className="text-nyx-mist text-sm animate-pulse">Loading report...</div>
      ) : report && (
        <div className="nyx-card p-5 space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-nyx-moonbeam font-semibold">{report.framework.name}</h2>
              <p className="text-nyx-mist text-xs mt-0.5">{report.framework.description}</p>
            </div>
            <div className="text-right">
              <GaugeRing pct={report.overall_compliance_pct} size={72} />
              <p className="text-nyx-mist text-xs mt-1">
                {report.compliant_controls}/{report.total_controls} compliant
              </p>
            </div>
          </div>

          {failingControls.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-red-400 text-sm font-medium flex items-center gap-2">
                <XCircle size={14} />
                Failing Controls ({failingControls.length})
              </h3>
              <div className="space-y-2">
                {failingControls.map(c => <ControlCard key={c.id} control={c} frameworkId={selectedFramework} />)}
              </div>
            </div>
          )}

          {passingControls.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-green-400 text-sm font-medium flex items-center gap-2">
                <CheckCircle2 size={14} />
                Passing Controls ({passingControls.length})
              </h3>
              <div className="space-y-2">
                {passingControls.map(c => <ControlCard key={c.id} control={c} frameworkId={selectedFramework} />)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
