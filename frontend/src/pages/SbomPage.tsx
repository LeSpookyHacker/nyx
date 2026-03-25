import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { sbomApi, SbomAlert, SbomChange } from '../api/sbom'
import { repositoriesApi } from '../api/repositories'
import { Plus, Minus, ArrowUpDown, CheckCheck, Package, ChevronDown, ChevronRight, Play, Loader2 } from 'lucide-react'
import { format } from 'date-fns'
import { clsx } from 'clsx'

function ChangeRow({ c }: { c: SbomChange }) {
  const icons = {
    added: <Plus size={11} className="text-green-400 shrink-0" />,
    removed: <Minus size={11} className="text-red-400 shrink-0" />,
    updated: <ArrowUpDown size={11} className="text-yellow-400 shrink-0" />,
  }
  const colors = { added: 'text-green-400', removed: 'text-red-400', updated: 'text-yellow-400' }
  return (
    <div className="flex items-center gap-2 py-1 border-b border-nyx-iris/5 last:border-0 text-xs">
      {icons[c.type]}
      <span className="text-nyx-moonbeam font-mono flex-1 truncate">{c.name}</span>
      {c.type === 'updated' && (
        <span className="text-nyx-mist shrink-0">{c.old_version} → {c.new_version}</span>
      )}
      {c.type !== 'updated' && (
        <span className={clsx('shrink-0', colors[c.type])}>{c.new_version || c.old_version}</span>
      )}
    </div>
  )
}

function AlertRow({ alert, onAck }: { alert: SbomAlert; onAck: () => void }) {
  const [open, setOpen] = useState(false)
  const total = alert.added_count + alert.removed_count + alert.updated_count

  return (
    <div className={clsx(
      'border rounded-lg overflow-hidden',
      alert.acknowledged ? 'border-nyx-iris/10 opacity-60' : 'border-nyx-iris/25'
    )}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-nyx-twilight/40 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        {open ? <ChevronDown size={13} className="text-nyx-mist shrink-0" /> : <ChevronRight size={13} className="text-nyx-mist shrink-0" />}

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-nyx-moonbeam text-sm font-medium truncate">
              {alert.repository_name || alert.repository_id}
            </p>
            {!alert.acknowledged && (
              <span className="shrink-0 w-2 h-2 rounded-full bg-nyx-amethyst" />
            )}
          </div>
          <p className="text-nyx-mist text-xs">{format(new Date(alert.created_at), 'MMM d, yyyy HH:mm')}</p>
        </div>

        <div className="flex gap-1.5 items-center shrink-0">
          {alert.added_count > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 font-medium">
              +{alert.added_count}
            </span>
          )}
          {alert.removed_count > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-400 font-medium">
              -{alert.removed_count}
            </span>
          )}
          {alert.updated_count > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-900/30 text-yellow-400 font-medium">
              ~{alert.updated_count}
            </span>
          )}
          <span className="text-nyx-mist text-[10px]">{total} change{total !== 1 ? 's' : ''}</span>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-nyx-iris/10">
          <div className="mt-3 max-h-64 overflow-y-auto">
            {alert.changes.map((c, i) => <ChangeRow key={i} c={c} />)}
          </div>
          {!alert.acknowledged && (
            <button
              onClick={e => { e.stopPropagation(); onAck() }}
              className="mt-3 nyx-btn-ghost text-xs"
            >
              <CheckCheck size={12} /> Dismiss
            </button>
          )}
        </div>
      )}
    </div>
  )
}

export default function SbomPage() {
  const queryClient = useQueryClient()
  const [repoFilter, setRepoFilter] = useState<string>('all')
  const [triggeredRepos, setTriggeredRepos] = useState<Set<string>>(new Set())

  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['sbom-alerts'],
    queryFn: () => sbomApi.getAlerts(),
    refetchInterval: 30_000,
  })

  const { data: repos = [] } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => repositoriesApi.list(),
  })

  const ack = useMutation({
    mutationFn: (id: string) => sbomApi.acknowledgeAlert(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sbom-alerts'] }),
  })

  const ackAll = useMutation({
    mutationFn: () => sbomApi.acknowledgeAll(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sbom-alerts'] }),
  })

  const generate = useMutation({
    mutationFn: (repoId: string) => sbomApi.generateSbom(repoId),
    onSuccess: (_data, repoId) => {
      setTriggeredRepos(prev => new Set([...prev, repoId]))
    },
  })

  const unread = alerts.filter(a => !a.acknowledged).length

  const filtered = repoFilter === 'all'
    ? alerts
    : alerts.filter(a => a.repository_id === repoFilter)

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-nyx-moonbeam text-xl font-bold flex items-center gap-2">
            <Package size={20} className="text-nyx-amethyst" />
            SBOM
          </h1>
          <p className="text-nyx-mist text-sm mt-1">
            Software Bill of Materials — component inventory and change alerts.
          </p>
        </div>
        {unread > 0 && (
          <button
            onClick={() => ackAll.mutate()}
            disabled={ackAll.isPending}
            className="nyx-btn-ghost flex items-center gap-2 text-sm"
          >
            <CheckCheck size={14} />
            Dismiss all ({unread})
          </button>
        )}
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Alerts', value: alerts.length },
          { label: 'Unread', value: unread, highlight: unread > 0 },
          { label: 'Components Added', value: alerts.reduce((s, a) => s + a.added_count, 0) },
          { label: 'Components Removed', value: alerts.reduce((s, a) => s + a.removed_count, 0) },
        ].map(({ label, value, highlight }) => (
          <div key={label} className="nyx-card p-4">
            <p className="text-nyx-mist text-xs mb-1">{label}</p>
            <p className={clsx('text-2xl font-bold', highlight ? 'text-nyx-amethyst' : 'text-nyx-moonbeam')}>
              {value}
            </p>
          </div>
        ))}
      </div>

      {/* Generate SBOM per repo */}
      <div className="nyx-card p-5">
        <h3 className="text-nyx-moonbeam font-semibold mb-1">Generate SBOM</h3>
        <p className="text-nyx-mist text-xs mb-4">
          Triggers the <span className="font-mono text-nyx-lavender">nyx-scan.yml</span> workflow on the repository,
          which runs Trivy in CycloneDX format and submits the SBOM here automatically.
        </p>
        {repos.length === 0 && (
          <p className="text-nyx-mist/50 text-sm">No repositories registered yet.</p>
        )}
        <div className="space-y-2">
          {repos.map((r: { id: string; github_full_name: string; default_branch: string }) => {
            const triggered = triggeredRepos.has(r.id)
            const isPending = generate.isPending && generate.variables === r.id
            return (
              <div key={r.id} className="flex items-center justify-between py-2 border-b border-nyx-iris/10 last:border-0">
                <span className="text-nyx-moonbeam text-sm font-mono">{r.github_full_name}</span>
                <button
                  onClick={() => generate.mutate(r.id)}
                  disabled={isPending || triggered}
                  className={clsx(
                    'nyx-btn-ghost text-xs flex items-center gap-1.5',
                    triggered && 'text-green-400 border-green-800/30'
                  )}
                >
                  {isPending ? (
                    <><Loader2 size={12} className="animate-spin" /> Triggering...</>
                  ) : triggered ? (
                    <><Play size={12} /> Triggered</>
                  ) : (
                    <><Play size={12} /> Generate SBOM</>
                  )}
                </button>
              </div>
            )
          })}
        </div>
      </div>

      {/* Alert list */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-nyx-moonbeam font-semibold">Change Alerts</h2>
          <select
            className="nyx-input text-xs py-1.5 pr-8"
            value={repoFilter}
            onChange={e => setRepoFilter(e.target.value)}
          >
            <option value="all">All repositories</option>
            {repos.map((r: { id: string; github_full_name: string }) => (
              <option key={r.id} value={r.id}>{r.github_full_name}</option>
            ))}
          </select>
        </div>

        {isLoading && <p className="text-nyx-mist text-sm animate-pulse">Loading...</p>}

        {!isLoading && filtered.length === 0 && (
          <div className="nyx-card p-8 text-center">
            <Package size={32} className="text-nyx-iris/30 mx-auto mb-3" />
            <p className="text-nyx-mist text-sm">No SBOM alerts yet.</p>
            <p className="text-nyx-mist/50 text-xs mt-1">
              Submit your first SBOM using the commands above.
            </p>
          </div>
        )}

        {filtered.map(alert => (
          <AlertRow
            key={alert.id}
            alert={alert}
            onAck={() => ack.mutate(alert.id)}
          />
        ))}
      </div>
    </div>
  )
}
