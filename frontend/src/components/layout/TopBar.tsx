import { useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Bell, RefreshCw, Plus, Minus, ArrowUpDown, CheckCheck, ExternalLink, RotateCcw, Sun, Moon } from 'lucide-react'
import { useTheme } from '../../hooks/useTheme'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { sbomApi, SbomAlert } from '../../api/sbom'
import { regressionAlertsApi, RegressionAutoAlert } from '../../api/regressionAlerts'
import { formatDistanceToNow } from 'date-fns'
import { clsx } from 'clsx'
import { useOnClickOutside } from '../../hooks/useOnClickOutside'

const PAGE_TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/findings': 'Findings',
  '/remediation': 'AI Remediation',
  '/repositories': 'Repositories',
  '/scans': 'Scan History',
  '/settings': 'Settings',
  '/audit': 'Audit Log',
  '/compliance': 'Compliance',
  '/sbom': 'SBOM',
}

function ChangeIcon({ type }: { type: string }) {
  if (type === 'added') return <Plus size={10} className="text-green-400 shrink-0" />
  if (type === 'removed') return <Minus size={10} className="text-red-400 shrink-0" />
  return <ArrowUpDown size={10} className="text-yellow-400 shrink-0" />
}

function AlertCard({ alert, onAck }: { alert: SbomAlert; onAck: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const previewChanges = alert.changes.slice(0, expanded ? 20 : 3)

  return (
    <div className={clsx(
      'px-4 py-3 border-b border-nyx-iris/10 last:border-0',
      alert.acknowledged && 'opacity-50'
    )}>
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="min-w-0">
          <p className="text-nyx-moonbeam text-xs font-medium truncate">
            {alert.repository_name || alert.repository_id}
          </p>
          <p className="text-nyx-mist text-[10px]">
            {formatDistanceToNow(new Date(alert.created_at))} ago
          </p>
        </div>
        <div className="flex gap-1 text-[10px] shrink-0">
          {alert.added_count > 0 && (
            <span className="px-1.5 py-0.5 rounded bg-green-900/30 text-green-400">+{alert.added_count}</span>
          )}
          {alert.removed_count > 0 && (
            <span className="px-1.5 py-0.5 rounded bg-red-900/30 text-red-400">-{alert.removed_count}</span>
          )}
          {alert.updated_count > 0 && (
            <span className="px-1.5 py-0.5 rounded bg-yellow-900/30 text-yellow-400">~{alert.updated_count}</span>
          )}
        </div>
      </div>

      <div className="space-y-0.5 mt-2">
        {previewChanges.map((c, i) => (
          <div key={i} className="flex items-center gap-1.5 text-[10px]">
            <ChangeIcon type={c.type} />
            <span className="text-nyx-mist font-mono truncate">{c.name}</span>
            {c.old_version && c.new_version && (
              <span className="text-nyx-mist/50 shrink-0">{c.old_version} → {c.new_version}</span>
            )}
            {c.new_version && !c.old_version && (
              <span className="text-nyx-mist/50 shrink-0">{c.new_version}</span>
            )}
          </div>
        ))}
        {alert.changes.length > 3 && (
          <button
            onClick={() => setExpanded(e => !e)}
            className="text-nyx-amethyst text-[10px] hover:underline mt-0.5"
          >
            {expanded ? 'Show less' : `+${alert.changes.length - 3} more`}
          </button>
        )}
      </div>

      {!alert.acknowledged && (
        <button
          onClick={() => onAck(alert.id)}
          className="mt-2 text-[10px] text-nyx-mist hover:text-nyx-moonbeam"
        >
          Dismiss
        </button>
      )}
    </div>
  )
}

function RegressionAlertCard({ alert, onAck }: { alert: RegressionAutoAlert; onAck: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const preview = alert.findings.slice(0, expanded ? 20 : 3)
  const SEVERITY_COLORS: Record<string, string> = {
    CRITICAL: 'text-red-400', HIGH: 'text-orange-400', MEDIUM: 'text-yellow-400', LOW: 'text-blue-400', INFO: 'text-slate-400',
  }

  return (
    <div className={clsx('px-4 py-3 border-b border-nyx-iris/10 last:border-0', alert.acknowledged && 'opacity-50')}>
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="min-w-0">
          <p className="text-nyx-moonbeam text-xs font-medium truncate">
            {alert.repository_name || alert.repository_id}
          </p>
          <p className="text-nyx-mist text-[10px]">{formatDistanceToNow(new Date(alert.created_at))} ago</p>
        </div>
        <span className="px-1.5 py-0.5 rounded bg-purple-900/30 text-purple-400 text-[10px] shrink-0">
          {alert.auto_sorted_count} auto-sorted
        </span>
      </div>
      <div className="space-y-0.5 mt-2">
        {preview.map((f, i) => (
          <div key={i} className="flex items-center gap-1.5 text-[10px]">
            <RotateCcw size={10} className="text-purple-400 shrink-0" />
            <span className={clsx('font-medium shrink-0', SEVERITY_COLORS[f.severity] || 'text-nyx-mist')}>{f.severity}</span>
            <span className="text-nyx-mist truncate">{f.title}</span>
            <span className="text-nyx-mist/50 shrink-0">→ {f.restored_status.replace('_', ' ')}</span>
          </div>
        ))}
        {alert.findings.length > 3 && (
          <button onClick={() => setExpanded(e => !e)} className="text-nyx-amethyst text-[10px] hover:underline mt-0.5">
            {expanded ? 'Show less' : `+${alert.findings.length - 3} more`}
          </button>
        )}
      </div>
      {!alert.acknowledged && (
        <button onClick={() => onAck(alert.id)} className="mt-2 text-[10px] text-nyx-mist hover:text-nyx-moonbeam">
          Dismiss
        </button>
      )}
    </div>
  )
}

export default function TopBar() {
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState<'sbom' | 'regression'>('sbom')
  const panelRef = useRef<HTMLDivElement>(null)
  useOnClickOutside(panelRef, () => setOpen(false))
  const { theme, toggle: toggleTheme } = useTheme()

  const title = PAGE_TITLES[location.pathname] || 'Nyx'

  const { data: alerts = [] } = useQuery({
    queryKey: ['sbom-alerts'],
    queryFn: () => sbomApi.getAlerts(),
    refetchInterval: 30_000,
  })

  const { data: regressionAlerts = [] } = useQuery({
    queryKey: ['regression-alerts'],
    queryFn: () => regressionAlertsApi.getAlerts(),
    refetchInterval: 30_000,
  })

  const sbomUnread = alerts.filter(a => !a.acknowledged).length
  const regressionUnread = regressionAlerts.filter(a => !a.acknowledged).length
  const unreadCount = sbomUnread + regressionUnread

  const ack = useMutation({
    mutationFn: (id: string) => sbomApi.acknowledgeAlert(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sbom-alerts'] }),
  })

  const ackAll = useMutation({
    mutationFn: () => sbomApi.acknowledgeAll(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sbom-alerts'] }),
  })

  const ackRegression = useMutation({
    mutationFn: (id: string) => regressionAlertsApi.acknowledgeAlert(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['regression-alerts'] }),
  })

  const ackAllRegression = useMutation({
    mutationFn: () => regressionAlertsApi.acknowledgeAll(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['regression-alerts'] }),
  })

  return (
    <header className="h-14 border-b border-nyx-iris/10 bg-nyx-midnight/80 backdrop-blur flex items-center justify-between px-6 shrink-0">
      <h1 className="text-nyx-moonbeam font-semibold text-base">{title}</h1>

      <div className="flex items-center gap-2">
        <button
          onClick={toggleTheme}
          className="nyx-btn-ghost p-2 rounded-lg"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
        </button>
        <button
          onClick={() => queryClient.invalidateQueries()}
          className="nyx-btn-ghost p-2 rounded-lg"
          title="Refresh all data"
        >
          <RefreshCw size={15} />
        </button>

        {/* Notification bell */}
        <div className="relative" ref={panelRef}>
          <button
            onClick={() => setOpen(o => !o)}
            className="nyx-btn-ghost p-2 rounded-lg relative"
            title="SBOM change alerts"
          >
            <Bell size={15} />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 min-w-[16px] h-4 px-0.5 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center leading-none">
                {unreadCount > 99 ? '99+' : unreadCount}
              </span>
            )}
          </button>

          {open && (
            <div className="absolute right-0 top-12 w-80 bg-nyx-dusk border border-nyx-iris/20 rounded-xl shadow-2xl z-50 overflow-hidden">
              {/* Tab bar */}
              <div className="flex border-b border-nyx-iris/10">
                <button
                  onClick={() => setTab('sbom')}
                  className={clsx(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors',
                    tab === 'sbom' ? 'text-nyx-moonbeam border-b-2 border-nyx-amethyst' : 'text-nyx-mist hover:text-nyx-moonbeam'
                  )}
                >
                  SBOM {sbomUnread > 0 && <span className="ml-1 px-1 rounded-full bg-red-500 text-white text-[9px]">{sbomUnread}</span>}
                </button>
                <button
                  onClick={() => setTab('regression')}
                  className={clsx(
                    'flex-1 px-3 py-2.5 text-xs font-medium transition-colors',
                    tab === 'regression' ? 'text-nyx-moonbeam border-b-2 border-nyx-amethyst' : 'text-nyx-mist hover:text-nyx-moonbeam'
                  )}
                >
                  Auto-Sorted {regressionUnread > 0 && <span className="ml-1 px-1 rounded-full bg-purple-500 text-white text-[9px]">{regressionUnread}</span>}
                </button>
              </div>

              {tab === 'sbom' && (
                <>
                  <div className="flex items-center justify-between px-4 py-2 border-b border-nyx-iris/10">
                    <p className="text-nyx-mist text-[10px]">SBOM component changes</p>
                    <div className="flex items-center gap-2">
                      {sbomUnread > 0 && (
                        <button onClick={() => ackAll.mutate()} className="flex items-center gap-1 text-[10px] text-nyx-mist hover:text-nyx-moonbeam" title="Dismiss all">
                          <CheckCheck size={11} /> All
                        </button>
                      )}
                      <button onClick={() => { setOpen(false); navigate('/sbom') }} className="flex items-center gap-1 text-[10px] text-nyx-amethyst hover:text-nyx-moonbeam">
                        View all <ExternalLink size={10} />
                      </button>
                    </div>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {alerts.length === 0 ? (
                      <p className="text-nyx-mist text-xs text-center py-6">No SBOM alerts yet.</p>
                    ) : (
                      alerts.slice(0, 10).map(alert => (
                        <AlertCard key={alert.id} alert={alert} onAck={id => ack.mutate(id)} />
                      ))
                    )}
                  </div>
                  {alerts.length > 10 && (
                    <div className="px-4 py-2 border-t border-nyx-iris/10 text-center">
                      <button onClick={() => { setOpen(false); navigate('/sbom') }} className="text-nyx-amethyst text-xs hover:underline">
                        View all {alerts.length} alerts
                      </button>
                    </div>
                  )}
                </>
              )}

              {tab === 'regression' && (
                <>
                  <div className="flex items-center justify-between px-4 py-2 border-b border-nyx-iris/10">
                    <p className="text-nyx-mist text-[10px]">Regressed findings auto-sorted</p>
                    {regressionUnread > 0 && (
                      <button onClick={() => ackAllRegression.mutate()} className="flex items-center gap-1 text-[10px] text-nyx-mist hover:text-nyx-moonbeam" title="Dismiss all">
                        <CheckCheck size={11} /> All
                      </button>
                    )}
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {regressionAlerts.length === 0 ? (
                      <p className="text-nyx-mist text-xs text-center py-6">No auto-sorted findings yet.</p>
                    ) : (
                      regressionAlerts.slice(0, 10).map(alert => (
                        <RegressionAlertCard key={alert.id} alert={alert} onAck={id => ackRegression.mutate(id)} />
                      ))
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
