import { useEffect, useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { findingsApi } from '../api/findings'
import { repositoriesApi } from '../api/repositories'
import { savedFiltersApi, type SavedFilter, type FindingFilterState } from '../api/savedFilters'
import type { Finding, Repository } from '../types'
import SeverityBadge from '../components/findings/SeverityBadge'
import ScannerBadge from '../components/findings/ScannerBadge'
import StatusBadge from '../components/findings/StatusBadge'
import { formatDistanceToNow } from 'date-fns'
import { Bookmark, CheckCircle, ChevronDown, ChevronUp, Check, ClipboardCopy, Download, Filter, RotateCcw, Save, ShieldAlert, Trash2, Wand2, X } from 'lucide-react'
import { clsx } from 'clsx'

import { SEVERITIES } from '../constants/theme'
const SCANNERS = ['SEMGREP', 'ZAP', 'SNYK', 'TRIVY', 'BANDIT', 'GRYPE', 'CHECKOV']

const STATUS_TABS: { label: string; value: string[]; key: string }[] = [
  { label: 'Active',        value: ['OPEN', 'IN_REMEDIATION'] },
  { label: 'Open',          value: ['OPEN'] },
  { label: 'In Remediation',value: ['IN_REMEDIATION'] },
  { label: 'Fixed',         value: ['FIXED'] },
  { label: 'Suppressed',    value: ['SUPPRESSED'] },
  { label: 'Accepted Risk', value: ['ACCEPTED_RISK'] },
  { label: 'All',           value: [] },
].map(t => ({ ...t, key: [...t.value].sort().join(',') }))

/** Security findings list with filtering, sorting, bulk actions, and Claude prompt generation. */
export default function FindingsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()

  // Initialise filters from URL search params — allows deep-linking from dashboard tiles
  // and repository severity badges (e.g. /findings?severity=CRITICAL&repository_id=<uuid>)
  const [severity, setSeverity] = useState<string[]>(
    searchParams.getAll('severity').length ? searchParams.getAll('severity') : []
  )
  const [repositoryId, setRepositoryId] = useState<string>(searchParams.get('repository_id') ?? '')
  const [scanner, setScanner] = useState<string[]>([])
  const [status, setStatus] = useState<string[]>(['OPEN', 'IN_REMEDIATION'])
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState('priority_score')
  const [sortDesc, setSortDesc] = useState(true)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showFilters, setShowFilters] = useState(severity.length > 0)
  const [isRegressionOnly, setIsRegressionOnly] = useState(searchParams.get('is_regression') === 'true')
  const [claudePrompt, setClaudePrompt] = useState<string | null>(null)
  const [promptCopied, setPromptCopied] = useState(false)
  const [savedMenuOpen, setSavedMenuOpen] = useState(false)
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [newFilterName, setNewFilterName] = useState('')
  const [newFilterDefault, setNewFilterDefault] = useState(false)

  const statusKey = useMemo(() => [...status].sort().join(','), [status])

  const { data: savedFilters = [] } = useQuery({
    queryKey: ['saved-filters', 'findings'],
    queryFn: () => savedFiltersApi.list('findings'),
  })

  // Auto-apply the default saved filter on first load — but only if the URL
  // didn't deep-link filters (deep-link takes precedence).
  const [hasAppliedDefault, setHasAppliedDefault] = useState(false)
  useEffect(() => {
    if (hasAppliedDefault || !savedFilters) return
    const deepLinked =
      searchParams.getAll('severity').length > 0 ||
      !!searchParams.get('repository_id') ||
      searchParams.get('is_regression') === 'true'
    if (deepLinked) { setHasAppliedDefault(true); return }
    const def = (savedFilters as SavedFilter[]).find(f => f.is_default)
    if (def) applySavedFilter(def)
    setHasAppliedDefault(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [savedFilters])

  function applySavedFilter(f: SavedFilter) {
    const state: FindingFilterState = f.filters || {}
    setSeverity(state.severity ?? [])
    setScanner(state.scanner ?? [])
    setStatus(state.status ?? ['OPEN', 'IN_REMEDIATION'])
    setSearch(state.search ?? '')
    setRepositoryId(state.repository_id ?? '')
    setIsRegressionOnly(!!state.is_regression)
    if (state.sort_by) setSortBy(state.sort_by)
    if (typeof state.sort_desc === 'boolean') setSortDesc(state.sort_desc)
    setPage(1)
    setSavedMenuOpen(false)
  }

  const createFilter = useMutation({
    mutationFn: () => savedFiltersApi.create(
      newFilterName.trim(),
      {
        severity, scanner, status, search,
        repository_id: repositoryId || undefined,
        is_regression: isRegressionOnly || undefined,
        sort_by: sortBy, sort_desc: sortDesc,
      },
      { isDefault: newFilterDefault },
    ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-filters', 'findings'] })
      setSaveDialogOpen(false)
      setNewFilterName('')
      setNewFilterDefault(false)
    },
  })

  const deleteFilter = useMutation({
    mutationFn: (id: string) => savedFiltersApi.remove(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['saved-filters', 'findings'] }),
  })

  const { data: reposData = [] } = useQuery({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
  })
  const repos = reposData as Repository[]

  const { data, isLoading } = useQuery({
    queryKey: ['findings', { severity, scanner, status, search, page, sortBy, sortDesc, repositoryId, isRegressionOnly }],
    queryFn: () => findingsApi.list({
      severity, scanner, status, search, page, page_size: 50,
      sort_by: sortBy, sort_desc: sortDesc,
      ...(repositoryId ? { repository_id: repositoryId } : {}),
      ...(isRegressionOnly ? { is_regression: true } : {}),
    }),
  })

  const bulkRequestFix = useMutation({
    mutationFn: (ids: string[]) => findingsApi.bulkRequestFix(ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      setSelectedIds(new Set())
    },
  })

  const generatePrompt = useMutation({
    mutationFn: (ids: string[]) => findingsApi.generateClaudePrompt(ids),
    onSuccess: (data) => {
      setClaudePrompt(data.prompt)
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      setSelectedIds(new Set())
    },
  })

  const bulkUpdateStatus = useMutation({
    mutationFn: ({ ids, status }: { ids: string[]; status: string }) =>
      findingsApi.bulkUpdateStatus(ids, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
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

  const toggleFilter = (arr: string[], setArr: (v: string[]) => void, val: string) => {
    setArr(arr.includes(val) ? arr.filter(v => v !== val) : [...arr, val])
    setPage(1)
  }

  const toggleSort = (col: string) => {
    if (sortBy === col) setSortDesc(!sortDesc)
    else { setSortBy(col); setSortDesc(true) }
    setPage(1)
  }

  const toggleSelect = (id: string) => {
    const next = new Set(selectedIds)
    next.has(id) ? next.delete(id) : next.add(id)
    setSelectedIds(next)
  }

  const SortIcon = ({ col }: { col: string }) => {
    if (sortBy !== col) return null
    return sortDesc ? <ChevronDown size={12} /> : <ChevronUp size={12} />
  }

  return (
    <div className="space-y-4">
      {/* Repository context banner — shown when deep-linked from a repo */}
      {repositoryId && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-nyx-iris/10 border border-nyx-iris/20 text-sm">
          <span className="text-nyx-mist">Showing findings for repository</span>
          <span className="text-nyx-amethyst font-medium">{searchParams.get('repo_name') ?? repositoryId}</span>
          <button
            onClick={() => navigate('/findings')}
            className="ml-auto text-nyx-mist hover:text-nyx-moonbeam transition-colors"
            title="Clear repository filter"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Severity filter banner — shown when deep-linked from a severity tile */}
      {!repositoryId && severity.length === 1 && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-nyx-iris/10 border border-nyx-iris/20 text-sm">
          <span className="text-nyx-mist">Filtered to</span>
          <span className="font-semibold" style={{ color: severity[0] === 'CRITICAL' ? '#ef4444' : severity[0] === 'HIGH' ? '#f97316' : severity[0] === 'MEDIUM' ? '#eab308' : severity[0] === 'LOW' ? '#22c55e' : '#64748b' }}>
            {severity[0]}
          </span>
          <span className="text-nyx-mist">findings</span>
          <button
            onClick={() => { setSeverity([]); setPage(1) }}
            className="ml-auto text-nyx-mist hover:text-nyx-moonbeam transition-colors"
            title="Clear severity filter"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Status tab strip */}
      <div className="flex gap-1 flex-wrap border-b border-nyx-iris/10 pb-1">
        {STATUS_TABS.map(tab => {
          const isActive = statusKey === tab.key
          return (
            <button
              key={tab.label}
              onClick={() => { setStatus(tab.value); setPage(1) }}
              className={clsx(
                'px-3 py-1.5 text-sm rounded-t transition-colors',
                isActive
                  ? 'text-nyx-moonbeam border-b-2 border-nyx-amethyst font-medium'
                  : 'text-nyx-mist hover:text-nyx-moonbeam'
              )}
            >
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3 flex-wrap">
        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }}
          className="nyx-input w-64"
        />
        <select
          value={repositoryId}
          onChange={e => { setRepositoryId(e.target.value); setPage(1) }}
          className="nyx-input text-sm"
          style={{ minWidth: '180px', maxWidth: '260px' }}
        >
          <option value="">All repositories</option>
          {repos.map((r: Repository) => (
            <option key={r.id} value={r.id}>{r.github_full_name}</option>
          ))}
        </select>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={clsx('nyx-btn-ghost gap-2', showFilters && 'bg-nyx-twilight text-nyx-moonbeam')}
        >
          <Filter size={14} />
          Filters
          {(severity.length + scanner.length) > 0 && (
            <span className="ml-1 bg-nyx-iris rounded-full px-1.5 py-0.5 text-[10px] text-white">
              {severity.length + scanner.length}
            </span>
          )}
        </button>
        <div className="relative">
          <button
            onClick={() => setSavedMenuOpen(o => !o)}
            className={clsx('nyx-btn-ghost gap-2', savedMenuOpen && 'bg-nyx-twilight text-nyx-moonbeam')}
            title="Saved filter presets"
          >
            <Bookmark size={14} />
            Views
            {savedFilters.length > 0 && (
              <span className="ml-1 bg-nyx-iris rounded-full px-1.5 py-0.5 text-[10px] text-white">
                {savedFilters.length}
              </span>
            )}
          </button>
          {savedMenuOpen && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setSavedMenuOpen(false)} />
              <div className="absolute z-20 left-0 mt-2 w-72 nyx-card p-2 shadow-xl border border-nyx-iris/20">
                {savedFilters.length === 0 && (
                  <p className="text-nyx-mist text-xs px-3 py-2">No saved views yet.</p>
                )}
                {(savedFilters as SavedFilter[]).map(f => (
                  <div key={f.id} className="flex items-center gap-1 group">
                    <button
                      onClick={() => applySavedFilter(f)}
                      className="flex-1 text-left px-3 py-2 text-sm rounded hover:bg-nyx-twilight transition-colors"
                    >
                      <span className="text-nyx-moonbeam">{f.name}</span>
                      {f.is_default && (
                        <span className="ml-2 text-[10px] text-nyx-amethyst">default</span>
                      )}
                    </button>
                    <button
                      onClick={() => deleteFilter.mutate(f.id)}
                      className="p-1.5 rounded text-nyx-mist hover:text-red-400 hover:bg-red-900/20 transition-colors opacity-0 group-hover:opacity-100"
                      title="Delete this view"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
                <div className="border-t border-nyx-iris/10 mt-1 pt-1">
                  <button
                    onClick={() => { setSavedMenuOpen(false); setSaveDialogOpen(true) }}
                    className="w-full text-left px-3 py-2 text-sm rounded hover:bg-nyx-twilight transition-colors flex items-center gap-2 text-nyx-amethyst"
                  >
                    <Save size={13} />
                    Save current as view…
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
        <button
          onClick={() => { setIsRegressionOnly(r => !r); setPage(1) }}
          className={clsx('nyx-btn-ghost gap-2', isRegressionOnly && 'bg-orange-900/30 text-orange-300 border border-orange-500/30')}
          title="Show only regressions"
        >
          <RotateCcw size={14} />
          Regressions
        </button>
        <button onClick={() => findingsApi.export('csv', { severity, scanner, status })} className="nyx-btn-ghost gap-2">
          <Download size={14} />
          Export
        </button>
        {selectedIds.size > 0 && (
          <div className="flex items-center gap-2 ml-auto flex-wrap">
            <span className="text-nyx-mist text-sm">{selectedIds.size} selected</span>
            <button
              onClick={() => bulkUpdateStatus.mutate({ ids: Array.from(selectedIds), status: 'ACCEPTED_RISK' })}
              className="nyx-btn-ghost gap-2 border border-yellow-700/40 text-yellow-400 hover:bg-yellow-900/20"
              disabled={bulkUpdateStatus.isPending}
            >
              <ShieldAlert size={14} />
              Accept Risk
            </button>
            <button
              onClick={() => bulkUpdateStatus.mutate({ ids: Array.from(selectedIds), status: 'FIXED' })}
              className="nyx-btn-ghost gap-2 border border-green-700/40 text-green-400 hover:bg-green-900/20"
              disabled={bulkUpdateStatus.isPending}
            >
              <CheckCircle size={14} />
              Mark Fixed
            </button>
            <button
              onClick={() => generatePrompt.mutate(Array.from(selectedIds))}
              className="nyx-btn-ghost gap-2 border border-nyx-amethyst/40 text-nyx-amethyst hover:bg-nyx-amethyst/10"
              disabled={generatePrompt.isPending}
              title="Generate a Claude Code prompt to remediate these findings"
            >
              <ClipboardCopy size={14} />
              {generatePrompt.isPending ? 'Generating...' : 'Claude Code Prompt'}
            </button>
            <button
              onClick={() => bulkRequestFix.mutate(Array.from(selectedIds))}
              className="nyx-btn-primary gap-2"
              disabled={bulkRequestFix.isPending}
            >
              <Wand2 size={14} />
              {bulkRequestFix.isPending ? 'Requesting...' : 'Request AI Fix'}
            </button>
          </div>
        )}
        <span className="ml-auto text-nyx-mist text-sm">{total.toLocaleString()} findings</span>
      </div>

      {/* Filter Panel — severity and scanner only */}
      {showFilters && (
        <div className="nyx-card p-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-nyx-mist text-xs uppercase tracking-wide">Severity</span>
            <div className="flex gap-1 flex-wrap">
              {SEVERITIES.map(s => (
                <button
                  key={s}
                  onClick={() => toggleFilter(severity, setSeverity, s)}
                  className={clsx(
                    'nyx-badge cursor-pointer border transition-opacity',
                    `severity-${s.toLowerCase()}`,
                    !severity.includes(s) && 'opacity-40'
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-nyx-mist text-xs uppercase tracking-wide">Scanner</span>
            <div className="flex gap-1 flex-wrap">
              {SCANNERS.map(s => (
                <button
                  key={s}
                  onClick={() => toggleFilter(scanner, setScanner, s)}
                  className={clsx('nyx-badge cursor-pointer border bg-nyx-dusk text-nyx-mist border-nyx-iris/20 transition-opacity',
                    !scanner.includes(s) && scanner.length > 0 && 'opacity-40')}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="nyx-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
              <tr>
                <th className="px-4 py-3 w-8">
                  <input type="checkbox" className="rounded"
                    onChange={e => setSelectedIds(e.target.checked ? new Set(findings.map(f => f.id)) : new Set())}
                  />
                </th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Finding</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Location</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium cursor-pointer hover:text-nyx-moonbeam"
                  onClick={() => toggleSort('priority_score')}>
                  <span className="flex items-center gap-1">Score <SortIcon col="priority_score" /></span>
                </th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium cursor-pointer hover:text-nyx-moonbeam"
                  onClick={() => toggleSort('first_seen_at')}>
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
                  className={clsx(
                    'hover:bg-nyx-twilight/30 cursor-pointer transition-colors',
                    selectedIds.has(f.id) && 'bg-nyx-eclipse/20'
                  )}
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  <td className="px-4 py-3" onClick={e => { e.stopPropagation(); toggleSelect(f.id) }}>
                    <input type="checkbox" className="rounded" checked={selectedIds.has(f.id)} readOnly />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <ScannerBadge scanner={f.scanner} />
                      {f.is_regression && (
                        <span className="nyx-badge text-[10px] bg-orange-900/30 text-orange-400 border border-orange-500/30">
                          REGRESSION
                        </span>
                      )}
                    </div>
                    <p className="text-nyx-moonbeam font-medium truncate max-w-xs">{f.title}</p>
                    {f.cve_id && <p className="text-nyx-mist text-xs">{f.cve_id}</p>}
                    {f.assigned_to && <p className="text-nyx-mist/60 text-xs">→ {f.assigned_to}</p>}
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
                    <span className={clsx(
                      'font-bold',
                      f.priority_score >= 70 ? 'text-red-400' :
                      f.priority_score >= 40 ? 'text-orange-400' : 'text-nyx-mist'
                    )}>
                      {f.priority_score.toFixed(0)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-nyx-mist text-xs whitespace-nowrap">
                    {formatDistanceToNow(new Date(f.first_seen_at))} ago
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={f.status} />
                  </td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    {(f.status === 'OPEN' || f.status === 'IN_REMEDIATION') && (
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => findingsApi.updateStatus(f.id, 'FIXED').then(() => queryClient.invalidateQueries({ queryKey: ['findings'] }))}
                          className="nyx-btn-ghost p-1.5 rounded"
                          title="Mark as Fixed"
                        >
                          <CheckCircle size={14} className="text-green-400" />
                        </button>
                        <button
                          onClick={() => findingsApi.updateStatus(f.id, 'ACCEPTED_RISK').then(() => queryClient.invalidateQueries({ queryKey: ['findings'] }))}
                          className="nyx-btn-ghost p-1.5 rounded"
                          title="Accept Risk"
                        >
                          <ShieldAlert size={14} className="text-yellow-400" />
                        </button>
                        <button
                          onClick={() => bulkRequestFix.mutate([f.id])}
                          className="nyx-btn-ghost p-1.5 rounded"
                          title="Request AI Fix"
                          disabled={bulkRequestFix.isPending}
                        >
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

        {/* Pagination */}
        {total > 50 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-nyx-iris/10">
            <span className="text-nyx-mist text-sm">
              Page {page} of {Math.ceil(total / 50)}
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="nyx-btn-ghost disabled:opacity-40"
              >
                Previous
              </button>
              <button
                onClick={() => setPage(p => p + 1)}
                disabled={page * 50 >= total}
                className="nyx-btn-ghost disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Claude Code Prompt Modal */}
      {claudePrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="nyx-card w-full max-w-4xl max-h-[90vh] flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-nyx-iris/20">
              <div>
                <h2 className="text-nyx-moonbeam font-semibold">Claude Code Remediation Prompt</h2>
                <p className="text-nyx-mist text-xs mt-0.5">
                  Findings marked as <span className="text-nyx-amethyst">In Remediation</span>.
                  Copy this prompt and paste it into Claude Code on your machine.
                </p>
              </div>
              <button onClick={() => { setClaudePrompt(null); setPromptCopied(false) }}
                className="text-nyx-mist hover:text-nyx-moonbeam transition-colors ml-4">
                <X size={18} />
              </button>
            </div>

            {/* Prompt text */}
            <div className="flex-1 overflow-y-auto p-5">
              <pre className="text-xs text-nyx-mist/90 whitespace-pre-wrap font-mono leading-relaxed bg-nyx-eclipse/40 rounded-lg p-4 border border-nyx-iris/10">
                {claudePrompt}
              </pre>
            </div>

            {/* Footer */}
            <div className="flex items-center gap-3 px-5 py-4 border-t border-nyx-iris/20">
              <button
                onClick={copyPrompt}
                className={clsx(
                  'nyx-btn-primary gap-2 flex-1',
                  promptCopied && 'bg-green-700 border-green-600'
                )}
              >
                {promptCopied ? <Check size={14} /> : <ClipboardCopy size={14} />}
                {promptCopied ? 'Copied!' : 'Copy to Clipboard'}
              </button>
              <button
                onClick={() => { setClaudePrompt(null); setPromptCopied(false) }}
                className="nyx-btn-ghost"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Save Filter Dialog */}
      {saveDialogOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="nyx-card w-full max-w-md">
            <div className="flex items-center justify-between px-5 py-4 border-b border-nyx-iris/20">
              <h2 className="text-nyx-moonbeam font-semibold">Save filter as view</h2>
              <button onClick={() => setSaveDialogOpen(false)} className="text-nyx-mist hover:text-nyx-moonbeam">
                <X size={18} />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="block text-nyx-mist text-xs uppercase tracking-wide mb-1">Name</label>
                <input
                  type="text"
                  value={newFilterName}
                  onChange={e => setNewFilterName(e.target.value)}
                  placeholder="e.g. Critical backlog"
                  className="nyx-input w-full"
                  maxLength={100}
                  autoFocus
                />
              </div>
              <label className="flex items-center gap-2 text-sm text-nyx-mist cursor-pointer">
                <input
                  type="checkbox"
                  checked={newFilterDefault}
                  onChange={e => setNewFilterDefault(e.target.checked)}
                  className="rounded"
                />
                Make this the default view on load
              </label>
              {createFilter.isError && (
                <p className="text-red-400 text-xs">Failed to save view. Please try again.</p>
              )}
            </div>
            <div className="flex items-center gap-2 px-5 py-4 border-t border-nyx-iris/20">
              <button onClick={() => setSaveDialogOpen(false)} className="nyx-btn-ghost flex-1">
                Cancel
              </button>
              <button
                onClick={() => createFilter.mutate()}
                disabled={!newFilterName.trim() || createFilter.isPending}
                className="nyx-btn-primary flex-1 gap-2 disabled:opacity-40"
              >
                <Save size={14} />
                {createFilter.isPending ? 'Saving…' : 'Save View'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
