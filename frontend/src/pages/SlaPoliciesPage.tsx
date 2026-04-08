import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { slaPoliciesApi } from '../api/slaPolicies'
import { repositoriesApi } from '../api/repositories'
import type { SlaPolicy } from '../types'
import { ShieldAlert, Plus, Trash2 } from 'lucide-react'
import { clsx } from 'clsx'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const ACTIONS = ['NOTIFY', 'JIRA', 'BOTH', 'NONE']

const ACTION_COLORS: Record<string, string> = {
  NOTIFY: 'bg-blue-900/30 text-blue-400 border-blue-800/30',
  JIRA: 'bg-purple-900/30 text-purple-400 border-purple-800/30',
  BOTH: 'bg-nyx-eclipse text-nyx-lavender border-nyx-iris/30',
  NONE: 'bg-nyx-dusk text-nyx-mist/50 border-nyx-iris/10',
}
const SEV_COLORS: Record<string, string> = {
  ALL: 'text-nyx-lavender', CRITICAL: 'text-red-400', HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400', LOW: 'text-green-400', INFO: 'text-slate-400',
}

/** SLA policy configuration for severity-based remediation time limits. */
export default function SlaPoliciesPage() {
  const queryClient = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({
    name: '', repository_id: '', severity: 'ALL', max_days: 30,
    escalation_action: 'NOTIFY', jira_project_key: '', enabled: true,
  })

  const { data: policies = [], isLoading } = useQuery({
    queryKey: ['sla-policies'],
    queryFn: () => slaPoliciesApi.list(),
  })

  const { data: repos = [] } = useQuery({
    queryKey: ['repositories'],
    queryFn: repositoriesApi.list,
  })

  const createPolicy = useMutation({
    mutationFn: () => slaPoliciesApi.create({
      name: form.name,
      repository_id: form.repository_id || undefined,
      severity: form.severity,
      max_days: form.max_days,
      escalation_action: form.escalation_action,
      jira_project_key: form.jira_project_key || undefined,
      enabled: form.enabled,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sla-policies'] })
      setShowAdd(false)
      setForm({ name: '', repository_id: '', severity: 'ALL', max_days: 30, escalation_action: 'NOTIFY', jira_project_key: '', enabled: true })
    },
  })

  const togglePolicy = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => slaPoliciesApi.update(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sla-policies'] }),
  })

  const deletePolicy = useMutation({
    mutationFn: (id: string) => slaPoliciesApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sla-policies'] }),
  })

  const repoName = (id?: string) => id
    ? repos.find(r => r.id === id)?.github_full_name?.split('/')[1] || id
    : 'Org-wide'

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert size={18} className="text-nyx-amethyst" />
          <h1 className="text-nyx-moonbeam font-bold text-lg">SLA Policies</h1>
        </div>
        <button onClick={() => setShowAdd(!showAdd)} className="nyx-btn-primary">
          <Plus size={14} /> Add Policy
        </button>
      </div>

      <p className="text-nyx-mist text-sm">
        Define custom SLA deadlines per severity. When breached, findings are auto-escalated via notification or JIRA ticket.
      </p>

      {showAdd && (
        <div className="nyx-card p-5 border border-nyx-amethyst/30 space-y-4">
          <h3 className="text-nyx-moonbeam font-semibold">New SLA Policy</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-nyx-mist text-sm mb-1.5 block">Policy Name</label>
              <input className="nyx-input w-full" placeholder="e.g. Critical 3-day SLA" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <label className="text-nyx-mist text-sm mb-1.5 block">Scope</label>
              <select className="nyx-input w-full" value={form.repository_id} onChange={e => setForm(f => ({ ...f, repository_id: e.target.value }))}>
                <option value="">Org-wide (all repos)</option>
                {repos.map(r => <option key={r.id} value={r.id}>{r.github_full_name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-nyx-mist text-sm mb-1.5 block">Severity</label>
              <select className="nyx-input w-full" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-nyx-mist text-sm mb-1.5 block">Max Days</label>
              <input type="number" min={1} max={365} className="nyx-input w-full" value={form.max_days} onChange={e => setForm(f => ({ ...f, max_days: Number(e.target.value) }))} />
            </div>
            <div>
              <label className="text-nyx-mist text-sm mb-1.5 block">Escalation</label>
              <select className="nyx-input w-full" value={form.escalation_action} onChange={e => setForm(f => ({ ...f, escalation_action: e.target.value }))}>
                {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
            {(form.escalation_action === 'JIRA' || form.escalation_action === 'BOTH') && (
              <div>
                <label className="text-nyx-mist text-sm mb-1.5 block">JIRA Project Key</label>
                <input className="nyx-input w-full" placeholder="e.g. SEC" value={form.jira_project_key} onChange={e => setForm(f => ({ ...f, jira_project_key: e.target.value }))} />
              </div>
            )}
          </div>
          <div className="flex gap-2">
            <button onClick={() => createPolicy.mutate()} disabled={!form.name || createPolicy.isPending} className="nyx-btn-primary">
              {createPolicy.isPending ? 'Creating...' : 'Create Policy'}
            </button>
            <button onClick={() => setShowAdd(false)} className="nyx-btn-ghost">Cancel</button>
          </div>
          {createPolicy.isError && <p className="text-red-400 text-sm">Failed to create policy.</p>}
        </div>
      )}

      {isLoading && <div className="text-nyx-mist p-8 text-center">Loading policies...</div>}

      {!isLoading && policies.length === 0 && (
        <div className="nyx-card p-12 text-center">
          <ShieldAlert size={32} className="text-nyx-iris mx-auto mb-3 opacity-50" />
          <p className="text-nyx-mist">No SLA policies defined.</p>
          <p className="text-nyx-mist/50 text-sm mt-1">Add policies to enforce deadlines and auto-escalate breached findings.</p>
        </div>
      )}

      {policies.length > 0 && (
        <div className="nyx-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-nyx-iris/10 bg-nyx-dusk/30">
              <tr>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Name</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Scope</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Max Days</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Escalation</th>
                <th className="px-4 py-3 text-left text-nyx-mist font-medium">Status</th>
                <th className="px-4 py-3 w-20" />
              </tr>
            </thead>
            <tbody className="divide-y divide-nyx-iris/5">
              {policies.map((p: SlaPolicy) => (
                <tr key={p.id} className="hover:bg-nyx-twilight/20">
                  <td className="px-4 py-3 text-nyx-moonbeam font-medium">{p.name}</td>
                  <td className="px-4 py-3 text-nyx-mist text-xs">{repoName(p.repository_id)}</td>
                  <td className="px-4 py-3">
                    <span className={clsx('font-semibold text-xs', SEV_COLORS[p.severity] || 'text-nyx-mist')}>{p.severity}</span>
                  </td>
                  <td className="px-4 py-3 text-nyx-moonbeam">{p.max_days}d</td>
                  <td className="px-4 py-3">
                    <span className={clsx('nyx-badge text-[10px] border', ACTION_COLORS[p.escalation_action] || '')}>{p.escalation_action}</span>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => togglePolicy.mutate({ id: p.id, enabled: !p.enabled })}
                      className={clsx('nyx-badge text-[10px] border cursor-pointer', p.enabled
                        ? 'bg-green-900/30 text-green-400 border-green-800/30'
                        : 'bg-nyx-dusk text-nyx-mist/50 border-nyx-iris/10')}>
                      {p.enabled ? 'Active' : 'Disabled'}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => { if (confirm('Delete this policy?')) deletePolicy.mutate(p.id) }} className="nyx-btn-ghost p-1.5" title="Delete">
                      <Trash2 size={12} className="text-red-400" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
