import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { repositoriesApi } from '../api/repositories'
import type { Repository } from '../types'
import { formatDistanceToNow } from 'date-fns'
import { AlertOctagon, Building2, GitBranch, Globe, Lock, Plus, RefreshCw, ScanLine, Trash2, Webhook } from 'lucide-react'
import { clsx } from 'clsx'

const ALL_SCANNERS = ['SEMGREP', 'ZAP', 'SNYK', 'TRIVY', 'BANDIT', 'GRYPE', 'CHECKOV']

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-orange-500' : score >= 20 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="w-full h-1.5 bg-nyx-dusk rounded-full overflow-hidden">
      <div className={clsx('h-full rounded-full transition-all', color)} style={{ width: `${Math.min(score, 100)}%` }} />
    </div>
  )
}

function RepoCard({ repo, onDelete, onRefreshWebhook, onSyncCodeScanning, syncingId }: {
  repo: Repository
  onDelete: (id: string) => void
  onRefreshWebhook: (id: string) => void
  onSyncCodeScanning: (id: string) => void
  syncingId: string | null
}) {
  const navigate = useNavigate()
  const repoName = repo.github_full_name.split('/')[1]
  const isStale = repo.last_scan_at
    ? (Date.now() - new Date(repo.last_scan_at).getTime()) > 7 * 24 * 60 * 60 * 1000
    : true
  const hasNoScanners = !repo.enabled_scanners || repo.enabled_scanners.trim() === ''

  return (
    <div
      className="nyx-card p-5 hover:border-nyx-amethyst/40 transition-colors cursor-pointer"
      onClick={() => navigate(`/repositories/${repo.id}`)}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2 min-w-0">
          {repo.is_private ? <Lock size={13} className="text-nyx-mist shrink-0" /> : <Globe size={13} className="text-nyx-mist shrink-0" />}
          <span className="text-nyx-moonbeam font-semibold text-sm truncate">{repoName}</span>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {hasNoScanners && (
            <span className="nyx-badge text-[10px] bg-red-900/30 text-red-400 border border-red-800/30">No Scanners</span>
          )}
          {isStale && !hasNoScanners && (
            <span className="nyx-badge text-[10px] bg-amber-900/30 text-amber-400 border border-amber-800/30">Stale</span>
          )}
          <span className={clsx('nyx-badge text-[10px]',
            repo.webhook_active
              ? 'bg-green-900/30 text-green-400 border border-green-800/30'
              : 'bg-red-900/30 text-red-400 border border-red-800/30')}>
            <Webhook size={9} />
            {repo.webhook_active ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>

      {repo.description && (
        <p className="text-nyx-mist text-xs mb-3 line-clamp-2">{repo.description}</p>
      )}

      <div className="mb-3">
        <div className="flex items-center justify-between mb-1">
          <span className="text-nyx-mist text-xs">Risk Score</span>
          <span className="text-nyx-moonbeam text-xs font-semibold">{Math.round(repo.risk_score)}/100</span>
        </div>
        <RiskBar score={repo.risk_score} />
      </div>

      <div className="flex items-center gap-3 text-xs text-nyx-mist mb-3">
        {repo.open_critical > 0 && (
          <button
            className="text-red-400 flex items-center gap-0.5 hover:text-red-300 transition-colors"
            onClick={e => { e.stopPropagation(); navigate(`/findings?severity=CRITICAL&repository_id=${repo.id}&repo_name=${encodeURIComponent(repo.github_full_name)}`) }}
            title="View critical findings"
          >
            <AlertOctagon size={10} /> {repo.open_critical} critical
          </button>
        )}
        {repo.open_high > 0 && (
          <button
            className="text-orange-400 hover:text-orange-300 transition-colors"
            onClick={e => { e.stopPropagation(); navigate(`/findings?severity=HIGH&repository_id=${repo.id}&repo_name=${encodeURIComponent(repo.github_full_name)}`) }}
            title="View high findings"
          >
            {repo.open_high} high
          </button>
        )}
        {repo.open_medium > 0 && (
          <button
            className="text-yellow-400 hover:text-yellow-300 transition-colors"
            onClick={e => { e.stopPropagation(); navigate(`/findings?severity=MEDIUM&repository_id=${repo.id}&repo_name=${encodeURIComponent(repo.github_full_name)}`) }}
            title="View medium findings"
          >
            {repo.open_medium} medium
          </button>
        )}
        {repo.language && <span className="ml-auto">{repo.language}</span>}
      </div>

      <div className="flex items-center gap-1 flex-wrap mb-3">
        {repo.enabled_scanners.split(',').map(s => s.trim()).filter(Boolean).map(s => (
          <span key={s} className="nyx-badge text-[10px] bg-nyx-dusk text-nyx-mist border border-nyx-iris/10">{s}</span>
        ))}
      </div>

      {repo.last_scan_at && (
        <p className="text-nyx-mist/50 text-xs">
          Last scanned {formatDistanceToNow(new Date(repo.last_scan_at))} ago
        </p>
      )}

      <div className="flex items-center justify-between mt-3 pt-3 border-t border-nyx-iris/10">
        <button
          className="text-nyx-amethyst text-xs hover:text-nyx-lavender transition-colors"
          onClick={e => { e.stopPropagation(); navigate(`/findings?repository_id=${repo.id}&repo_name=${encodeURIComponent(repo.github_full_name)}`) }}
        >
          View all findings →
        </button>
      </div>

      <div className="flex gap-1 flex-wrap" onClick={e => e.stopPropagation()}>
        <button
          onClick={() => onRefreshWebhook(repo.id)}
          className="nyx-btn-ghost text-xs py-1 px-2 gap-1"
          title="Refresh webhook"
        >
          <RefreshCw size={11} /> Webhook
        </button>
        <button
          onClick={() => onSyncCodeScanning(repo.id)}
          disabled={syncingId === repo.id}
          className="nyx-btn-ghost text-xs py-1 px-2 gap-1"
          title="Pull Code Scanning alerts from GitHub"
        >
          <ScanLine size={11} /> {syncingId === repo.id ? 'Syncing...' : 'Code Scanning'}
        </button>
        <button
          onClick={() => {
            if (confirm('Remove this repository from Nyx? This will delete all associated findings.')) {
              onDelete(repo.id)
            }
          }}
          className="nyx-btn-danger text-xs py-1 px-2 gap-1 ml-auto"
        >
          <Trash2 size={11} /> Remove
        </button>
      </div>
    </div>
  )
}

export default function RepositoriesPage() {
  const queryClient = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [repoName, setRepoName] = useState('')
  const [selectedScanners, setSelectedScanners] = useState(['SEMGREP', 'BANDIT', 'TRIVY'])
  const [syncingId, setSyncingId] = useState<string | null>(null)
  const [syncResult, setSyncResult] = useState<{ id: string; message: string } | null>(null)

  const { data: repos = [], isLoading } = useQuery({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
  })

  const addRepo = useMutation({
    mutationFn: () => repositoriesApi.create(repoName, selectedScanners),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      setShowAdd(false)
      setRepoName('')
    },
  })

  const deleteRepo = useMutation({
    mutationFn: (id: string) => repositoriesApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['repositories'] }),
  })

  const refreshWebhook = useMutation({
    mutationFn: (id: string) => repositoriesApi.refreshWebhook(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['repositories'] }),
  })

  const handleSyncCodeScanning = async (id: string) => {
    setSyncingId(id)
    setSyncResult(null)
    try {
      const result = await repositoriesApi.syncCodeScanning(id)
      const status = result.status as string
      const alerts = result.alerts_found as number | undefined
      const message = status === 'ok'
        ? alerts ? `Imported ${alerts} alert${alerts !== 1 ? 's' : ''}` : 'No new alerts'
        : result.reason as string || status
      setSyncResult({ id, message })
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
    } catch {
      setSyncResult({ id, message: 'Sync failed — check GITHUB_TOKEN' })
    } finally {
      setSyncingId(null)
    }
  }

  const toggleScanner = (s: string) => {
    setSelectedScanners(prev => prev.includes(s) ? prev.filter(v => v !== s) : [...prev, s])
  }

  // Group repos by organization (owner prefix before '/')
  const grouped = (repos as Repository[]).reduce<Record<string, Repository[]>>((acc, repo) => {
    const org = repo.github_full_name.split('/')[0]
    if (!acc[org]) acc[org] = []
    acc[org].push(repo)
    return acc
  }, {})
  const orgs = Object.keys(grouped).sort()

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-nyx-mist text-sm">{(repos as Repository[]).length} repositories across {orgs.length} organization{orgs.length !== 1 ? 's' : ''}</p>
        <button onClick={() => setShowAdd(!showAdd)} className="nyx-btn-primary">
          <Plus size={14} /> Add Repository
        </button>
      </div>

      {showAdd && (
        <div className="nyx-card p-5 border border-nyx-amethyst/30 space-y-4">
          <h3 className="text-nyx-moonbeam font-semibold">Add GitHub Repository</h3>
          <div>
            <label className="text-nyx-mist text-sm mb-1.5 block">Repository (owner/repo)</label>
            <input
              className="nyx-input w-full"
              placeholder="e.g. acme-corp/backend-api"
              value={repoName}
              onChange={e => setRepoName(e.target.value)}
            />
          </div>
          <div>
            <label className="text-nyx-mist text-sm mb-2 block">Enable Scanners</label>
            <div className="flex flex-wrap gap-2">
              {ALL_SCANNERS.map(s => (
                <button
                  key={s}
                  onClick={() => toggleScanner(s)}
                  className={clsx(
                    'nyx-badge border cursor-pointer transition-all',
                    selectedScanners.includes(s)
                      ? 'bg-nyx-eclipse text-nyx-lavender border-nyx-iris/50'
                      : 'bg-nyx-dusk text-nyx-mist border-nyx-iris/10 opacity-50'
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => addRepo.mutate()}
              disabled={!repoName || addRepo.isPending}
              className="nyx-btn-primary"
            >
              {addRepo.isPending ? 'Adding...' : 'Add Repository'}
            </button>
            <button onClick={() => setShowAdd(false)} className="nyx-btn-ghost">Cancel</button>
          </div>
          {addRepo.isError && (
            <p className="text-red-400 text-sm">{(addRepo.error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to add repository.'}</p>
          )}
        </div>
      )}

      {syncResult && (
        <div className="nyx-card p-3 border border-nyx-iris/20 text-xs text-nyx-mist flex items-center justify-between">
          <span>Code Scanning sync: <span className="text-nyx-lavender">{syncResult.message}</span></span>
          <button onClick={() => setSyncResult(null)} className="text-nyx-mist/50 hover:text-nyx-mist">✕</button>
        </div>
      )}

      {isLoading && <div className="text-nyx-mist p-8 text-center">Loading repositories...</div>}

      {!isLoading && (repos as Repository[]).length === 0 && (
        <div className="nyx-card p-12 text-center">
          <GitBranch size={32} className="text-nyx-iris mx-auto mb-3 opacity-50" />
          <p className="text-nyx-mist">No repositories registered yet.</p>
          <p className="text-nyx-mist/50 text-sm mt-1">Click "Add Repository" to connect your first GitHub repo.</p>
        </div>
      )}

      {/* Org-grouped repo cards */}
      {orgs.map(org => (
        <div key={org}>
          <div className="flex items-center gap-2 mb-3">
            <Building2 size={14} className="text-nyx-iris/60" />
            <h2 className="text-nyx-mist text-sm font-semibold">{org}</h2>
            <span className="text-nyx-mist/40 text-xs">({grouped[org].length} repo{grouped[org].length !== 1 ? 's' : ''})</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mb-6">
            {grouped[org].map((repo: Repository) => (
              <RepoCard
                key={repo.id}
                repo={repo}
                onDelete={(id) => deleteRepo.mutate(id)}
                onRefreshWebhook={(id) => refreshWebhook.mutate(id)}
                onSyncCodeScanning={handleSyncCodeScanning}
                syncingId={syncingId}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
