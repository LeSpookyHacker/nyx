import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { repositoriesApi } from '../api/repositories'
import { findingsApi } from '../api/findings'
import { jiraApi } from '../api/jira'
import { remediationApi } from '../api/remediation'
import {
  AreaChart, Area, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid
} from 'recharts'
import type { Finding, Scan } from '../types'
import SeverityBadge from '../components/findings/SeverityBadge'
import ScannerBadge from '../components/findings/ScannerBadge'
import StatusBadge from '../components/findings/StatusBadge'
import { formatDistanceToNow } from 'date-fns'
import {
  ArrowLeft, Check, CheckCircle, ChevronDown, ChevronUp, ClipboardCopy, ExternalLink, Globe, Lock,
  RefreshCw, ShieldAlert, Ticket, TrendingUp, Wand2, Webhook, X,
} from 'lucide-react'
import RepoTrends from '../components/charts/RepoTrends'
import { clsx } from 'clsx'

import { SEVERITIES, STATUSES, SEV_COLORS } from '../constants/theme'

const SCAN_STATUS_COLORS: Record<string, string> = {
  COMPLETED: 'text-green-400',
  PENDING: 'text-yellow-400',
  PROCESSING: 'text-blue-400',
  FAILED: 'text-red-400',
}

const JIRA_STATUS_COLORS: Record<string, string> = {
  'To Do': 'bg-gray-700 text-gray-300',
  'In Progress': 'bg-blue-900/40 text-blue-300',
  Done: 'bg-green-900/40 text-green-300',
  Closed: 'bg-green-900/40 text-green-300',
  Resolved: 'bg-green-900/40 text-green-300',
}

type Tab = 'findings' | 'scans' | 'jira' | 'trends' | 'risk'

// ── Findings Tab ───────────────────────────────────────────────────────────────

function FindingsTab({ repoId }: { repoId: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [severity, setSeverity] = useState<string[]>([])
  const [status, setStatus] = useState<string[]>(['OPEN'])
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState('priority_score')
  const [sortDesc, setSortDesc] = useState(true)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [claudePrompt, setClaudePrompt] = useState<string | null>(null)
  const [promptCopied, setPromptCopied] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['findings', repoId, { severity, status, search, page, sortBy, sortDesc }],
    queryFn: () => findingsApi.list({
      repository_id: repoId,
      severity, status, search,
      page, page_size: 50,
      sort_by: sortBy, sort_desc: sortDesc,
    }),
  })

  const requestFix = useMutation({
    mutationFn: (id: string) => remediationApi.request(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['findings', repoId] }),
  })

  const generatePrompt = useMutation({
    mutationFn: () => findingsApi.generateClaudePrompt(Array.from(selectedIds)),
    onSuccess: (data) => {
      setClaudePrompt(data.prompt)
      queryClient.invalidateQueries({ queryKey: ['findings', repoId] })
    },
  })

  const bulkUpdateStatus = useMutation({
    mutationFn: (status: string) =>
      findingsApi.bulkUpdateStatus(Array.from(selectedIds), status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings', repoId] })
      setSelectedIds(new Set())
    },
  })

  const copyPrompt = async () => {
    if (!claudePrompt) return
    try {
      await navigator.clipboard.writeText(claudePrompt)
      setPromptCopied(true)
      setTimeout(() => setPromptCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy prompt to clipboard:', err)
    }
  }

  const findings = data?.items || []
  const total = data?.total || 0

  const toggle = (arr: string[], set: (v: string[]) => void, val: string) => {
    set(arr.includes(val) ? arr.filter(v => v !== val) : [...arr, val])
    setPage(1)
  }

  const toggleSort = (col: string) => {
    if (sortBy === col) setSortDesc(d => !d)
    else { setSortBy(col); setSortDesc(true) }
    setPage(1)
  }

  const SortIcon = ({ col }: { col: string }) =>
    sortBy !== col ? null : sortDesc ? <ChevronDown size={12} /> : <ChevronUp size={12} />

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }}
          className="nyx-input w-56"
        />
        <div className="flex gap-1">
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => toggle(severity, setSeverity, s)}
              className={clsx('nyx-badge cursor-pointer border transition-opacity', `severity-${s.toLowerCase()}`,
                !severity.includes(s) && severity.length > 0 && 'opacity-40')}
            >
              {s}
            </button>
          ))}
        </div>
        <div className="flex gap-1 ml-auto">
          {STATUSES.map(s => (
            <button
              key={s}
              onClick={() => toggle(status, setStatus, s)}
              className={clsx('nyx-badge cursor-pointer border bg-nyx-dusk text-nyx-mist border-nyx-iris/20 transition-opacity',
                !status.includes(s) && 'opacity-40')}
            >
              {s.replace('_', ' ')}
            </button>
          ))}
        </div>
        {selectedIds.size > 0 && (
          <>
            <button
              onClick={() => bulkUpdateStatus.mutate('ACCEPTED_RISK')}
              className="nyx-btn-ghost gap-1.5 text-xs py-1.5 border border-yellow-700/40 text-yellow-400 hover:bg-yellow-900/20"
              disabled={bulkUpdateStatus.isPending}
            >
              <ShieldAlert size={13} /> Accept Risk ({selectedIds.size})
            </button>
            <button
              onClick={() => bulkUpdateStatus.mutate('FIXED')}
              className="nyx-btn-ghost gap-1.5 text-xs py-1.5 border border-green-700/40 text-green-400 hover:bg-green-900/20"
              disabled={bulkUpdateStatus.isPending}
            >
              <CheckCircle size={13} /> Mark Fixed ({selectedIds.size})
            </button>
            <button
              onClick={async () => {
                for (const id of selectedIds) await requestFix.mutateAsync(id)
                setSelectedIds(new Set())
              }}
              className="nyx-btn-primary gap-1.5 text-xs py-1.5"
              disabled={requestFix.isPending}
            >
              <Wand2 size={13} /> AI Fix ({selectedIds.size})
            </button>
            <button
              onClick={() => generatePrompt.mutate()}
              className="nyx-btn-ghost gap-1.5 text-xs py-1.5 border border-nyx-amethyst/40 text-nyx-lavender hover:bg-nyx-amethyst/10"
              disabled={generatePrompt.isPending}
            >
              <ClipboardCopy size={13} />
              {generatePrompt.isPending ? 'Generating...' : `Claude Prompt (${selectedIds.size})`}
            </button>
          </>
        )}
        <span className="text-nyx-mist text-xs">{total.toLocaleString()} findings</span>
      </div>

      {/* Table */}
      <div className="nyx-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
              <tr>
                <th className="px-4 py-3 w-8">
                  <input type="checkbox" className="rounded"
                    onChange={e => setSelectedIds(e.target.checked ? new Set(findings.map((f: Finding) => f.id)) : new Set())}
                  />
                </th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Finding</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Location</th>
                <th
                  className="px-4 py-3 text-left text-nyx-mist font-medium cursor-pointer hover:text-nyx-moonbeam"
                  onClick={() => toggleSort('priority_score')}
                >
                  <span className="flex items-center gap-1">Score <SortIcon col="priority_score" /></span>
                </th>
                <th
                  className="px-4 py-3 text-left text-nyx-mist font-medium cursor-pointer hover:text-nyx-moonbeam"
                  onClick={() => toggleSort('first_seen_at')}
                >
                  <span className="flex items-center gap-1">Age <SortIcon col="first_seen_at" /></span>
                </th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Status</th>
                <th className="px-4 py-3 w-10" />
              </tr>
            </thead>
            <tbody className="divide-y divide-nyx-iris/5">
              {isLoading && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-nyx-mist">Loading...</td></tr>
              )}
              {!isLoading && findings.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-nyx-mist">No findings match your filters.</td></tr>
              )}
              {findings.map((f: Finding) => (
                <tr
                  key={f.id}
                  className={clsx('hover:bg-nyx-twilight/30 cursor-pointer transition-colors',
                    selectedIds.has(f.id) && 'bg-nyx-eclipse/20')}
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  <td className="px-4 py-3" onClick={e => { e.stopPropagation(); const n = new Set(selectedIds); n.has(f.id) ? n.delete(f.id) : n.add(f.id); setSelectedIds(n) }}>
                    <input type="checkbox" className="rounded" checked={selectedIds.has(f.id)} readOnly />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <ScannerBadge scanner={f.scanner} />
                    </div>
                    <p className="text-nyx-moonbeam font-medium truncate max-w-xs">{f.title}</p>
                    {f.cve_id && <p className="text-nyx-mist text-xs">{f.cve_id}</p>}
                  </td>
                  <td className="px-4 py-3">
                    {f.file_path ? (
                      <p className="text-nyx-mist text-xs font-mono truncate max-w-[180px]">
                        {f.file_path}
                        {f.line_start && <span className="text-nyx-lavender">:{f.line_start}</span>}
                      </p>
                    ) : f.url ? (
                      <p className="text-nyx-mist text-xs truncate max-w-[180px]">{f.url}</p>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('font-bold',
                      f.priority_score >= 70 ? 'text-red-400' :
                      f.priority_score >= 40 ? 'text-orange-400' : 'text-nyx-mist')}>
                      {f.priority_score.toFixed(0)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-nyx-mist text-xs whitespace-nowrap">
                    {formatDistanceToNow(new Date(f.first_seen_at))} ago
                  </td>
                  <td className="px-4 py-3"><StatusBadge status={f.status} /></td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    {(f.status === 'OPEN' || f.status === 'IN_REMEDIATION') && (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => findingsApi.updateStatus(f.id, 'FIXED').then(() => queryClient.invalidateQueries({ queryKey: ['findings', repoId] }))}
                          className="nyx-btn-ghost p-1.5 rounded"
                          title="Mark as Fixed"
                        >
                          <CheckCircle size={14} className="text-green-400" />
                        </button>
                        <button
                          onClick={() => findingsApi.updateStatus(f.id, 'ACCEPTED_RISK').then(() => queryClient.invalidateQueries({ queryKey: ['findings', repoId] }))}
                          className="nyx-btn-ghost p-1.5 rounded"
                          title="Accept Risk"
                        >
                          <ShieldAlert size={14} className="text-yellow-400" />
                        </button>
                        <button onClick={() => requestFix.mutate(f.id)} className="nyx-btn-ghost p-1.5 rounded" title="Request AI Fix">
                          <Wand2 size={14} className="text-nyx-amethyst" />
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {total > 50 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-nyx-iris/10">
            <span className="text-nyx-mist text-sm">Page {page} of {Math.ceil(total / 50)}</span>
            <div className="flex gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="nyx-btn-ghost disabled:opacity-40">Previous</button>
              <button onClick={() => setPage(p => p + 1)} disabled={page * 50 >= total} className="nyx-btn-ghost disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>

      {/* Claude Prompt Modal */}
      {claudePrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-nyx-midnight border border-nyx-iris/20 rounded-xl w-full max-w-3xl max-h-[80vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-nyx-iris/10">
              <h2 className="text-nyx-moonbeam font-semibold">Claude Code Remediation Prompt</h2>
              <div className="flex items-center gap-2">
                <button onClick={copyPrompt} className="nyx-btn-ghost gap-1.5 text-xs py-1.5 border border-nyx-amethyst/40 text-nyx-lavender hover:bg-nyx-amethyst/10">
                  {promptCopied ? <><Check size={13} className="text-green-400" /> Copied!</> : <><ClipboardCopy size={13} /> Copy</>}
                </button>
                <button onClick={() => setClaudePrompt(null)} className="nyx-btn-ghost p-1.5">
                  <X size={16} />
                </button>
              </div>
            </div>
            <pre className="overflow-y-auto p-5 text-xs text-nyx-mist font-mono whitespace-pre-wrap leading-relaxed flex-1">
              {claudePrompt}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Scans Tab ─────────────────────────────────────────────────────────────────

function ScansTab({ repoId }: { repoId: string }) {
  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['repo-scans', repoId],
    queryFn: () => repositoriesApi.getScans(repoId),
  })

  return (
    <div className="nyx-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
            <tr>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Scanner</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Trigger</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Status</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Findings</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">New</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">Branch</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium">When</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nyx-iris/5">
            {isLoading && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-nyx-mist">Loading...</td></tr>
            )}
            {!isLoading && scans.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-nyx-mist">No scans yet for this repository.</td></tr>
            )}
            {scans.map((s: Scan) => (
              <tr key={s.id} className="hover:bg-nyx-twilight/30 transition-colors">
                <td className="px-4 py-3">
                  <ScannerBadge scanner={s.scanner} />
                </td>
                <td className="px-4 py-3 text-nyx-mist text-xs">{s.trigger}</td>
                <td className="px-4 py-3">
                  <span className={clsx('text-xs font-medium', SCAN_STATUS_COLORS[s.status] ?? 'text-nyx-mist')}>
                    {s.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-nyx-moonbeam text-sm font-semibold">{s.finding_count}</td>
                <td className="px-4 py-3">
                  {s.new_finding_count > 0 && (
                    <span className="text-xs text-red-400 font-medium">+{s.new_finding_count}</span>
                  )}
                </td>
                <td className="px-4 py-3 text-nyx-mist text-xs font-mono">{s.git_ref ?? '—'}</td>
                <td className="px-4 py-3 text-nyx-mist text-xs whitespace-nowrap">
                  {s.created_at ? formatDistanceToNow(new Date(s.created_at)) + ' ago' : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── JIRA Tab ──────────────────────────────────────────────────────────────────

function JiraTab({ repoId }: { repoId: string }) {
  const queryClient = useQueryClient()
  const [bulkResult, setBulkResult] = useState<string | null>(null)
  const [isBulking, setIsBulking] = useState(false)

  const { data: tickets = [], isLoading } = useQuery({
    queryKey: ['repo-jira', repoId],
    queryFn: () => jiraApi.listRepoTickets(repoId),
  })

  const handleBulkCreate = async () => {
    setIsBulking(true)
    setBulkResult(null)
    try {
      const r = await jiraApi.bulkCreateTickets(repoId)
      setBulkResult(`Created ${r.created} ticket${r.created !== 1 ? 's' : ''} · ${r.skipped} already linked · ${r.failed} failed`)
      queryClient.invalidateQueries({ queryKey: ['repo-jira', repoId] })
    } catch {
      setBulkResult('Bulk create failed')
    } finally {
      setIsBulking(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <button
          onClick={handleBulkCreate}
          disabled={isBulking}
          className="nyx-btn-primary gap-2"
        >
          <Ticket size={14} />
          {isBulking ? 'Creating tickets...' : 'Bulk create tickets for CRITICAL & HIGH'}
        </button>
        {bulkResult && (
          <span className="text-sm text-nyx-lavender">{bulkResult}</span>
        )}
      </div>

      <div className="nyx-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
              <tr>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Ticket</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Finding</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">JIRA Status</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Priority</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Assignee</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-nyx-iris/5">
              {isLoading && (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-nyx-mist">Loading...</td></tr>
              )}
              {!isLoading && tickets.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-nyx-mist">
                    No JIRA tickets linked yet. Use "Bulk create" above or create tickets from individual findings.
                  </td>
                </tr>
              )}
              {tickets.map(t => (
                <tr key={t.jira_issue_key} className="hover:bg-nyx-twilight/30 transition-colors">
                  <td className="px-4 py-3">
                    <a
                      href={t.jira_issue_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-nyx-amethyst hover:text-nyx-lavender font-mono text-sm flex items-center gap-1"
                      onClick={e => e.stopPropagation()}
                    >
                      {t.jira_issue_key} <ExternalLink size={11} />
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/findings/${t.finding_id}`}
                      className="text-nyx-moonbeam hover:text-nyx-lavender truncate max-w-[240px] block"
                    >
                      {t.finding_title}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('text-xs font-semibold', SEV_COLORS[t.finding_severity])}>
                      {t.finding_severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {t.jira_status && (
                      <span className={clsx('nyx-badge text-xs', JIRA_STATUS_COLORS[t.jira_status] ?? 'bg-nyx-dusk text-nyx-mist')}>
                        {t.jira_status}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">{t.jira_priority ?? '—'}</td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">{t.jira_assignee ?? 'Unassigned'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

/** Repository detail view with findings, scans, JIRA tickets, trends, and risk analysis tabs. */
export default function RepositoryDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('findings')
  const [syncing, setSyncing] = useState(false)
  const [syncMsg, setSyncMsg] = useState<string | null>(null)
  const [repoPrompt, setRepoPrompt] = useState<string | null>(null)
  const [repoPromptCopied, setRepoPromptCopied] = useState(false)
  const [promptingRepo, setPromptingRepo] = useState(false)
  const queryClient = useQueryClient()

  const { data: repo, isLoading } = useQuery({
    queryKey: ['repository', id],
    queryFn: () => repositoriesApi.get(id!),
    enabled: !!id,
  })

  const handleSyncCodeScanning = async () => {
    if (!id) return
    setSyncing(true)
    setSyncMsg(null)
    try {
      const r = await repositoriesApi.syncCodeScanning(id)
      const status = r.status as string
      const alerts = r.alerts_found as number | undefined
      setSyncMsg(status === 'ok'
        ? alerts ? `Imported ${alerts} alert${alerts !== 1 ? 's' : ''}` : 'No new alerts'
        : r.reason as string || status)
      queryClient.invalidateQueries({ queryKey: ['repository', id] })
    } catch {
      setSyncMsg('Sync failed — check GITHUB_TOKEN')
    } finally {
      setSyncing(false)
    }
  }

  const handleGenerateRepoPrompt = async () => {
    if (!id) return
    setPromptingRepo(true)
    try {
      const r = await repositoriesApi.generateClaudePrompt(id)
      setRepoPrompt(r.prompt)
    } catch {
      // silent — user can retry
    } finally {
      setPromptingRepo(false)
    }
  }

  const copyRepoPrompt = async () => {
    if (!repoPrompt) return
    await navigator.clipboard.writeText(repoPrompt)
    setRepoPromptCopied(true)
    setTimeout(() => setRepoPromptCopied(false), 2000)
  }

  if (isLoading) {
    return <div className="text-nyx-mist p-8 text-center">Loading repository...</div>
  }
  if (!repo) {
    return <div className="text-nyx-mist p-8 text-center">Repository not found.</div>
  }

  const [org, repoName] = repo.github_full_name.split('/', 2)
  const totalOpen = repo.open_critical + repo.open_high + repo.open_medium + repo.open_low + repo.open_info

  const riskColor = repo.risk_score >= 70 ? 'bg-red-500' :
    repo.risk_score >= 40 ? 'bg-orange-500' :
    repo.risk_score >= 20 ? 'bg-yellow-500' : 'bg-green-500'

  const TABS: { id: Tab; label: string; icon?: React.ReactNode }[] = [
    { id: 'findings', label: `Findings (${totalOpen})` },
    { id: 'scans', label: 'Scans' },
    { id: 'jira', label: 'JIRA Tickets' },
    { id: 'trends', label: 'Trends', icon: <TrendingUp size={13} /> },
    { id: 'risk', label: 'Risk History' },
  ]

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <button onClick={() => navigate('/repositories')} className="text-nyx-mist hover:text-nyx-lavender flex items-center gap-1">
          <ArrowLeft size={14} /> Repositories
        </button>
        <span className="text-nyx-iris/40">/</span>
        <span className="text-nyx-mist/60">{org}</span>
        <span className="text-nyx-iris/40">/</span>
        <span className="text-nyx-moonbeam font-semibold">{repoName}</span>
      </div>

      {/* Header Card */}
      <div className="nyx-card p-5">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              {repo.is_private
                ? <Lock size={13} className="text-nyx-mist shrink-0" />
                : <Globe size={13} className="text-nyx-mist shrink-0" />}
              <span className="text-nyx-mist/60 text-sm">{org} /</span>
              <a
                href={`https://github.com/${repo.github_full_name}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-nyx-moonbeam font-bold text-lg hover:text-nyx-amethyst flex items-center gap-1.5"
              >
                {repoName} <ExternalLink size={13} />
              </a>
            </div>
            {repo.description && (
              <p className="text-nyx-mist text-sm mt-1">{repo.description}</p>
            )}
            <div className="flex items-center gap-3 mt-2 text-xs text-nyx-mist/60">
              {repo.language && <span>{repo.language}</span>}
              <span>Branch: <span className="font-mono text-nyx-mist">{repo.default_branch}</span></span>
              {repo.last_scan_at && (
                <span>Last scan: {formatDistanceToNow(new Date(repo.last_scan_at))} ago</span>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <span className={clsx('nyx-badge text-[10px]',
              repo.webhook_active
                ? 'bg-green-900/30 text-green-400 border border-green-800/30'
                : 'bg-red-900/30 text-red-400 border border-red-800/30')}>
              <Webhook size={9} />
              {repo.webhook_active ? 'Webhook Active' : 'Webhook Inactive'}
            </span>
            <button
              onClick={handleSyncCodeScanning}
              disabled={syncing}
              className="nyx-btn-ghost text-xs py-1 px-2 gap-1"
              title="Pull Code Scanning alerts from GitHub"
            >
              <RefreshCw size={11} className={syncing ? 'animate-spin' : ''} />
              {syncing ? 'Syncing...' : 'Code Scanning'}
            </button>
            <button
              onClick={handleGenerateRepoPrompt}
              disabled={promptingRepo}
              className="nyx-btn-ghost text-xs py-1 px-2 gap-1 border border-nyx-amethyst/40 text-nyx-lavender hover:bg-nyx-amethyst/10"
              title="Generate Claude Code prompt for all open findings"
            >
              <ClipboardCopy size={11} />
              {promptingRepo ? 'Generating...' : 'Claude Prompt'}
            </button>
          </div>
        </div>

        {syncMsg && (
          <p className="text-xs text-nyx-lavender mb-3">Code Scanning sync: {syncMsg}</p>
        )}

        {/* Risk score */}
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1">
            <span className="text-nyx-mist text-xs">Risk Score</span>
            <span className="text-nyx-moonbeam text-sm font-bold">{Math.round(repo.risk_score)}/100</span>
          </div>
          <div className="w-full h-2 bg-nyx-dusk rounded-full overflow-hidden">
            <div className={clsx('h-full rounded-full transition-all', riskColor)} style={{ width: `${Math.min(repo.risk_score, 100)}%` }} />
          </div>
        </div>

        {/* Severity stat row */}
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: 'Critical', count: repo.open_critical, color: 'text-red-400', border: 'border-red-500/20' },
            { label: 'High', count: repo.open_high, color: 'text-orange-400', border: 'border-orange-500/20' },
            { label: 'Medium', count: repo.open_medium, color: 'text-yellow-400', border: 'border-yellow-500/20' },
            { label: 'Low', count: repo.open_low, color: 'text-blue-400', border: 'border-blue-500/20' },
            { label: 'Info', count: repo.open_info, color: 'text-gray-400', border: 'border-gray-500/20' },
          ].map(({ label, count, color, border }) => (
            <button
              key={label}
              onClick={() => {
                setTab('findings')
              }}
              className={clsx('rounded-lg border p-3 text-center hover:bg-nyx-twilight/40 transition-colors', border)}
            >
              <p className={clsx('text-xl font-bold', color)}>{count}</p>
              <p className="text-nyx-mist text-xs mt-0.5">{label}</p>
            </button>
          ))}
        </div>

        {/* Scanner badges */}
        <div className="flex items-center gap-1.5 flex-wrap mt-3 pt-3 border-t border-nyx-iris/10">
          <span className="text-nyx-mist/60 text-xs mr-1">Scanners:</span>
          {repo.enabled_scanners.split(',').map(s => s.trim()).filter(Boolean).map(s => (
            <span key={s} className="nyx-badge text-[10px] bg-nyx-dusk text-nyx-mist border border-nyx-iris/10">{s}</span>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-nyx-iris/10">
        <div className="flex gap-1">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={clsx(
                'px-4 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-1.5',
                tab === t.id
                  ? 'border-nyx-amethyst text-nyx-lavender'
                  : 'border-transparent text-nyx-mist hover:text-nyx-moonbeam'
              )}
            >
              {t.icon}{t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      {tab === 'findings' && <FindingsTab repoId={id!} />}
      {tab === 'scans' && <ScansTab repoId={id!} />}
      {tab === 'jira' && <JiraTab repoId={id!} />}
      {tab === 'trends' && <RepoTrends repoId={id!} />}
      {tab === 'risk' && <RiskHistoryTab repoId={id!} />}

      {/* Repo-level Claude Prompt Modal */}
      {repoPrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-nyx-midnight border border-nyx-iris/20 rounded-xl w-full max-w-3xl max-h-[80vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-nyx-iris/10">
              <h2 className="text-nyx-moonbeam font-semibold">Claude Code Remediation Prompt — All Open Findings</h2>
              <div className="flex items-center gap-2">
                <button onClick={copyRepoPrompt} className="nyx-btn-ghost gap-1.5 text-xs py-1.5 border border-nyx-amethyst/40 text-nyx-lavender hover:bg-nyx-amethyst/10">
                  {repoPromptCopied ? <><Check size={13} className="text-green-400" /> Copied!</> : <><ClipboardCopy size={13} /> Copy</>}
                </button>
                <button onClick={() => setRepoPrompt(null)} className="nyx-btn-ghost p-1.5">
                  <X size={16} />
                </button>
              </div>
            </div>
            <pre className="overflow-y-auto p-5 text-xs text-nyx-mist font-mono whitespace-pre-wrap leading-relaxed flex-1">
              {repoPrompt}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}

function RiskHistoryTab({ repoId }: { repoId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['repo-risk-history', repoId],
    queryFn: () => repositoriesApi.getRiskHistory(repoId, 30),
  })

  if (isLoading) return <div className="text-nyx-mist text-sm animate-pulse p-4">Loading risk history...</div>
  if (!data?.data?.length) return <div className="nyx-card p-8 text-center text-nyx-mist">No risk history yet — snapshots are taken daily.</div>

  return (
    <div className="nyx-card p-5 space-y-4">
      <h3 className="text-nyx-moonbeam font-semibold">Risk Score History (30 days)</h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data.data}>
          <defs>
            <linearGradient id="repoRiskGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1a1a35" />
          <XAxis dataKey="snapshot_date" tick={{ fill: '#a78bfa', fontSize: 10 }} />
          <YAxis domain={[0, 100]} tick={{ fill: '#a78bfa', fontSize: 10 }} width={30} />
          <Tooltip
            contentStyle={{ background: '#0d0d1a', border: '1px solid #4f46e5', borderRadius: 8 }}
            labelStyle={{ color: '#ede9fe' }}
            itemStyle={{ color: '#c4b5fd' }}
          />
          <Area type="monotone" dataKey="risk_score" stroke="#f97316" fill="url(#repoRiskGrad)" name="Risk Score" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
      <div className="grid grid-cols-4 gap-3">
        {['open_critical', 'open_high', 'open_medium', 'open_low'].map(key => {
          const latest = data.data[data.data.length - 1]
          const colors: Record<string, string> = { open_critical: 'text-red-400', open_high: 'text-orange-400', open_medium: 'text-yellow-400', open_low: 'text-green-400' }
          const labels: Record<string, string> = { open_critical: 'Critical', open_high: 'High', open_medium: 'Medium', open_low: 'Low' }
          return (
            <div key={key} className="bg-nyx-dusk rounded-lg p-3 text-center">
              <p className={`text-xl font-bold ${colors[key]}`}>{latest?.[key as keyof typeof latest] ?? 0}</p>
              <p className="text-nyx-mist text-xs mt-0.5">{labels[key]}</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}
