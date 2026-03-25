import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import client from '../api/client'
import { format, formatDistanceToNow } from 'date-fns'
import { Download, Search, Filter, ChevronDown, ChevronRight, ClipboardList } from 'lucide-react'
import { clsx } from 'clsx'

interface AuditEntry {
  id: string
  actor: string
  action: string
  resource_type: string
  resource_id: string | null
  metadata: Record<string, unknown> | null
  ip_address: string | null
  created_at: string
}

interface AuditResponse {
  total: number
  page: number
  page_size: number
  items: AuditEntry[]
}

// Color code action categories
const ACTION_COLOR: Record<string, string> = {
  'finding.':       'text-blue-400',
  'remediation.':   'text-purple-400',
  'repository.':    'text-yellow-400',
  'scan.':          'text-green-400',
  'sbom.':          'text-cyan-400',
}

function actionColor(action: string): string {
  for (const [prefix, color] of Object.entries(ACTION_COLOR)) {
    if (action.startsWith(prefix)) return color
  }
  return 'text-nyx-mist'
}

// Human-readable metadata display
function MetaSummary({ action, metadata }: { action: string; metadata: Record<string, unknown> | null }) {
  if (!metadata) return null
  const parts: string[] = []

  if (action === 'finding.status_updated') {
    parts.push(`${metadata.old_status} → ${metadata.new_status}`)
  } else if (action === 'finding.suppressed') {
    parts.push(`reason: ${metadata.reason}`)
    if (metadata.expires_days) parts.push(`expires in ${metadata.expires_days}d`)
  } else if (action === 'finding.assigned') {
    parts.push(metadata.assignee ? `→ ${metadata.assignee}` : 'unassigned')
  } else if (action === 'remediation.requested') {
    parts.push(`by ${metadata.requested_by}`)
  } else if (action === 'remediation.approved') {
    if (metadata.auto_merge) parts.push('auto-merge')
    if (metadata.jira_assignee) parts.push(`jira: ${metadata.jira_assignee}`)
  } else if (action === 'remediation.rejected') {
    if (metadata.notes) parts.push(String(metadata.notes).slice(0, 60))
  } else if (action === 'remediation.regenerated') {
    if (metadata.context) parts.push(String(metadata.context).slice(0, 60))
  } else if (action === 'remediation.dismissed') {
    parts.push(`was ${metadata.status}`)
  } else if (action === 'repository.registered' || action === 'repository.deleted') {
    if (metadata.github_full_name) parts.push(String(metadata.github_full_name))
  } else if (action === 'repository.workflow_pushed') {
    if (metadata.github_full_name) parts.push(String(metadata.github_full_name))
    parts.push(metadata.created ? 'created' : 'updated')
  } else if (action === 'scan.imported') {
    parts.push(`${metadata.scanner} on ${metadata.git_ref || 'unknown ref'}`)
  } else if (action === 'sbom.generation_triggered') {
    if (metadata.github_full_name) parts.push(String(metadata.github_full_name))
  } else {
    // Fallback: first 3 key=value pairs
    Object.entries(metadata).slice(0, 3).forEach(([k, v]) => parts.push(`${k}: ${v}`))
  }

  return (
    <span className="text-nyx-mist/70 text-[10px]">{parts.join(' · ')}</span>
  )
}

function AuditRow({ log }: { log: AuditEntry }) {
  const [expanded, setExpanded] = useState(false)
  const color = actionColor(log.action)

  return (
    <>
      <tr
        className="hover:bg-nyx-twilight/20 cursor-pointer"
        onClick={() => setExpanded(e => !e)}
      >
        <td className="px-4 py-2.5 whitespace-nowrap">
          <p className="text-nyx-mist text-xs">{format(new Date(log.created_at), 'MMM d, HH:mm:ss')}</p>
          <p className="text-nyx-mist/40 text-[10px]">{formatDistanceToNow(new Date(log.created_at))} ago</p>
        </td>
        <td className="px-4 py-2.5">
          <span className="text-nyx-moonbeam text-xs font-mono">{log.actor.replace('key:', '')}</span>
        </td>
        <td className="px-4 py-2.5">
          <code className={clsx('text-xs font-semibold', color)}>{log.action}</code>
        </td>
        <td className="px-4 py-2.5">
          <span className="text-nyx-mist text-xs">{log.resource_type}</span>
          {log.resource_id && (
            <span className="text-nyx-iris/50 text-[10px] ml-1 font-mono">{log.resource_id.slice(0, 8)}</span>
          )}
        </td>
        <td className="px-4 py-2.5">
          <div className="flex items-center gap-1.5">
            <MetaSummary action={log.action} metadata={log.metadata} />
            {log.metadata && (
              <span className="text-nyx-mist/30 ml-auto">
                {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
              </span>
            )}
          </div>
        </td>
      </tr>
      {expanded && log.metadata && (
        <tr className="bg-nyx-void/40">
          <td colSpan={5} className="px-4 pb-3 pt-1">
            <pre className="text-[10px] text-nyx-lavender/80 font-mono bg-nyx-void rounded p-2 overflow-x-auto">
              {JSON.stringify(log.metadata, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}

const RESOURCE_TYPES = ['finding', 'remediation', 'repository', 'scan', 'sbom']
const ACTION_PREFIXES = [
  { label: 'All actions', value: '' },
  { label: 'Findings', value: 'finding.' },
  { label: 'Remediations', value: 'remediation.' },
  { label: 'Repositories', value: 'repository.' },
  { label: 'Scans', value: 'scan.' },
  { label: 'SBOM', value: 'sbom.' },
]

export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [downloading, setDownloading] = useState(false)

  const params = {
    page,
    page_size: 50,
    ...(search && { search }),
    ...(actionFilter && { action: actionFilter }),
    ...(resourceFilter && { resource_type: resourceFilter }),
    ...(dateFrom && { date_from: dateFrom }),
    ...(dateTo && { date_to: dateTo }),
  }

  const { data, isLoading } = useQuery<AuditResponse>({
    queryKey: ['audit', params],
    queryFn: async () => {
      const res = await client.get('/audit', { params })
      return res.data
    },
  })

  const totalPages = data ? Math.ceil(data.total / 50) : 1

  const handleDownload = async (fmt: 'json' | 'csv') => {
    setDownloading(true)
    try {
      const res = await client.get('/audit/download', {
        params: { ...params, fmt },
        responseType: 'blob',
      })
      const url = URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = `nyx_audit.${fmt}`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setDownloading(false)
    }
  }

  const resetFilters = () => {
    setSearch(''); setActionFilter(''); setResourceFilter(''); setDateFrom(''); setDateTo(''); setPage(1)
  }
  const hasFilters = search || actionFilter || resourceFilter || dateFrom || dateTo

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ClipboardList size={16} className="text-nyx-amethyst" />
          <h1 className="text-nyx-moonbeam font-bold">Audit Log</h1>
          {data && (
            <span className="text-nyx-mist/50 text-sm">{data.total.toLocaleString()} events</span>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleDownload('csv')}
            disabled={downloading}
            className="nyx-btn-ghost text-xs gap-1.5"
          >
            <Download size={12} /> CSV
          </button>
          <button
            onClick={() => handleDownload('json')}
            disabled={downloading}
            className="nyx-btn-ghost text-xs gap-1.5"
          >
            <Download size={12} /> JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="nyx-card p-3 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-48">
            <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-nyx-mist/50" />
            <input
              className="nyx-input w-full pl-8 text-xs py-1.5"
              placeholder="Search actions, metadata..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
            />
          </div>
          <select
            className="nyx-input text-xs py-1.5"
            value={actionFilter}
            onChange={e => { setActionFilter(e.target.value); setPage(1) }}
          >
            {ACTION_PREFIXES.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
          </select>
          <select
            className="nyx-input text-xs py-1.5"
            value={resourceFilter}
            onChange={e => { setResourceFilter(e.target.value); setPage(1) }}
          >
            <option value="">All resources</option>
            {RESOURCE_TYPES.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <input
            type="date"
            className="nyx-input text-xs py-1.5"
            value={dateFrom}
            onChange={e => { setDateFrom(e.target.value); setPage(1) }}
            title="From date"
          />
          <input
            type="date"
            className="nyx-input text-xs py-1.5"
            value={dateTo}
            onChange={e => { setDateTo(e.target.value); setPage(1) }}
            title="To date"
          />
          {hasFilters && (
            <button onClick={resetFilters} className="nyx-btn-ghost text-xs py-1.5 gap-1">
              <Filter size={11} /> Clear
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="nyx-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
            <tr>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium text-xs w-36">Time</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium text-xs w-28">Actor</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium text-xs">Action</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium text-xs w-32">Resource</th>
              <th className="px-4 py-3 text-left text-nyx-mist font-medium text-xs">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-nyx-iris/5">
            {isLoading && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-nyx-mist text-sm">Loading...</td></tr>
            )}
            {!isLoading && (!data?.items.length) && (
              <tr><td colSpan={5} className="px-4 py-12 text-center">
                <ClipboardList size={28} className="text-nyx-iris/30 mx-auto mb-2" />
                <p className="text-nyx-mist text-sm">No audit events{hasFilters ? ' matching filters' : ' yet'}.</p>
              </td></tr>
            )}
            {data?.items.map(log => <AuditRow key={log.id} log={log} />)}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.total > 50 && (
        <div className="flex items-center justify-between text-xs text-nyx-mist">
          <span>
            {(page - 1) * 50 + 1}–{Math.min(page * 50, data.total)} of {data.total.toLocaleString()}
          </span>
          <div className="flex gap-1">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="nyx-btn-ghost py-1 px-2 text-xs disabled:opacity-30"
            >
              ← Prev
            </button>
            <span className="px-2 py-1 text-nyx-mist/50">{page} / {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="nyx-btn-ghost py-1 px-2 text-xs disabled:opacity-30"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
