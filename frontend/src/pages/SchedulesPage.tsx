import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { schedulesApi } from '../api/schedules'
import { repositoriesApi } from '../api/repositories'
import type { ScanSchedule } from '../types'
import { Clock, Play, Plus, Trash2, ToggleLeft, ToggleRight } from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import { clsx } from 'clsx'

const ALL_SCANNERS = ['SEMGREP', 'ZAP', 'SNYK', 'TRIVY', 'BANDIT', 'GRYPE', 'CHECKOV']
const INTERVAL_OPTIONS = [
  { label: '6 hours', value: 6 },
  { label: '12 hours', value: 12 },
  { label: '24 hours', value: 24 },
  { label: '48 hours', value: 48 },
  { label: '72 hours', value: 72 },
  { label: '1 week', value: 168 },
]

export default function SchedulesPage() {
  const queryClient = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [repoId, setRepoId] = useState('')
  const [selectedScanners, setSelectedScanners] = useState(['SEMGREP', 'BANDIT', 'TRIVY'])
  const [intervalHours, setIntervalHours] = useState(24)
  const [triggerMsg, setTriggerMsg] = useState<string | null>(null)

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: () => schedulesApi.list(),
  })

  const { data: repos = [] } = useQuery({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
  })

  const createSchedule = useMutation({
    mutationFn: () => schedulesApi.create({ repository_id: repoId, enabled_scanners: selectedScanners, interval_hours: intervalHours }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      setShowAdd(false)
      setRepoId('')
    },
  })

  const toggleSchedule = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      schedulesApi.update(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const deleteSchedule = useMutation({
    mutationFn: (id: string) => schedulesApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const triggerSchedule = useMutation({
    mutationFn: (id: string) => schedulesApi.trigger(id),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] })
      setTriggerMsg(data.message)
      setTimeout(() => setTriggerMsg(null), 4000)
    },
  })

  const toggleScanner = (s: string) =>
    setSelectedScanners(prev => prev.includes(s) ? prev.filter(v => v !== s) : [...prev, s])

  const repoName = (id: string) =>
    repos.find(r => r.id === id)?.github_full_name || id

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock size={18} className="text-nyx-amethyst" />
          <h1 className="text-nyx-moonbeam font-bold text-lg">Scan Schedules</h1>
        </div>
        <button onClick={() => setShowAdd(!showAdd)} className="nyx-btn-primary">
          <Plus size={14} /> Add Schedule
        </button>
      </div>

      <p className="text-nyx-mist text-sm">
        Automatically trigger security scans on a recurring interval without relying on push webhooks.
      </p>

      {triggerMsg && (
        <div className="nyx-card p-3 border border-green-800/30 text-green-400 text-sm">{triggerMsg}</div>
      )}

      {showAdd && (
        <div className="nyx-card p-5 border border-nyx-amethyst/30 space-y-4">
          <h3 className="text-nyx-moonbeam font-semibold">New Scan Schedule</h3>
          <div>
            <label className="text-nyx-mist text-sm mb-1.5 block">Repository</label>
            <select
              className="nyx-input w-full"
              value={repoId}
              onChange={e => setRepoId(e.target.value)}
            >
              <option value="">Select a repository...</option>
              {repos.map(r => (
                <option key={r.id} value={r.id}>{r.github_full_name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-nyx-mist text-sm mb-2 block">Scanners</label>
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
          <div>
            <label className="text-nyx-mist text-sm mb-1.5 block">Interval</label>
            <select className="nyx-input w-full" value={intervalHours} onChange={e => setIntervalHours(Number(e.target.value))}>
              {INTERVAL_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => createSchedule.mutate()}
              disabled={!repoId || selectedScanners.length === 0 || createSchedule.isPending}
              className="nyx-btn-primary"
            >
              {createSchedule.isPending ? 'Creating...' : 'Create Schedule'}
            </button>
            <button onClick={() => setShowAdd(false)} className="nyx-btn-ghost">Cancel</button>
          </div>
        </div>
      )}

      {isLoading && <div className="text-nyx-mist p-8 text-center">Loading schedules...</div>}

      {!isLoading && schedules.length === 0 && (
        <div className="nyx-card p-12 text-center">
          <Clock size={32} className="text-nyx-iris mx-auto mb-3 opacity-50" />
          <p className="text-nyx-mist">No scan schedules configured.</p>
          <p className="text-nyx-mist/50 text-sm mt-1">Add a schedule to run scans automatically on an interval.</p>
        </div>
      )}

      <div className="nyx-card overflow-hidden">
        {schedules.length > 0 && (
          <table className="w-full text-sm">
            <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
              <tr>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Repository</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Scanners</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Interval</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Last Run</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Next Run</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Status</th>
                <th className="px-4 py-3 w-32" />
              </tr>
            </thead>
            <tbody className="divide-y divide-nyx-iris/5">
              {schedules.map((s: ScanSchedule) => (
                <tr key={s.id} className="hover:bg-nyx-twilight/20">
                  <td className="px-4 py-3 text-nyx-moonbeam font-medium">{repoName(s.repository_id)}</td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1 flex-wrap">
                      {s.enabled_scanners.split(',').map(sc => (
                        <span key={sc} className="nyx-badge text-[10px] bg-nyx-dusk text-nyx-mist border border-nyx-iris/10">{sc.trim()}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-nyx-mist">Every {s.interval_hours}h</td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">
                    {s.last_run_at ? formatDistanceToNow(new Date(s.last_run_at)) + ' ago' : 'Never'}
                  </td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">
                    {s.next_run_at ? format(new Date(s.next_run_at), 'MMM d, HH:mm') : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('nyx-badge text-[10px]', s.enabled
                      ? 'bg-green-900/30 text-green-400 border border-green-800/30'
                      : 'bg-nyx-dusk text-nyx-mist/50 border border-nyx-iris/10')}>
                      {s.enabled ? 'Active' : 'Paused'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1 justify-end">
                      <button
                        onClick={() => triggerSchedule.mutate(s.id)}
                        className="nyx-btn-ghost p-1.5"
                        title="Run now"
                      >
                        <Play size={12} className="text-nyx-amethyst" />
                      </button>
                      <button
                        onClick={() => toggleSchedule.mutate({ id: s.id, enabled: !s.enabled })}
                        className="nyx-btn-ghost p-1.5"
                        title={s.enabled ? 'Pause' : 'Resume'}
                      >
                        {s.enabled
                          ? <ToggleRight size={12} className="text-green-400" />
                          : <ToggleLeft size={12} className="text-nyx-mist" />}
                      </button>
                      <button
                        onClick={() => { if (confirm('Delete this schedule?')) deleteSchedule.mutate(s.id) }}
                        className="nyx-btn-ghost p-1.5"
                        title="Delete"
                      >
                        <Trash2 size={12} className="text-red-400" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
