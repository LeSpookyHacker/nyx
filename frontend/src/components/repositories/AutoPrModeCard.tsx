import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { Check, Zap } from 'lucide-react'
import { repositoriesApi } from '../../api/repositories'
import type { Repository, Severity } from '../../types'

const BUDGET_PRESETS = [10_000, 50_000, 100_000, 200_000]

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const SEVERITY_META: Record<Severity, { label: string; badge: string; dot: string }> = {
  CRITICAL: { label: 'Critical', badge: 'bg-red-900/30 text-red-400 border-red-500/40',   dot: 'bg-red-400' },
  HIGH:     { label: 'High',     badge: 'bg-orange-900/30 text-orange-400 border-orange-500/40', dot: 'bg-orange-400' },
  MEDIUM:   { label: 'Medium',   badge: 'bg-amber-900/30 text-amber-400 border-amber-500/40',  dot: 'bg-amber-400' },
  LOW:      { label: 'Low',      badge: 'bg-yellow-900/30 text-yellow-400 border-yellow-500/40', dot: 'bg-yellow-400' },
  INFO:     { label: 'Info',     badge: 'bg-blue-900/30 text-blue-400 border-blue-500/40',   dot: 'bg-blue-400' },
}

function parseSeverities(threshold: string): Severity[] {
  const valid = new Set<string>(ALL_SEVERITIES)
  const parts = threshold.split(',').map(s => s.trim().toUpperCase()).filter(s => valid.has(s))
  return parts.length > 0 ? (parts as Severity[]) : ['CRITICAL', 'HIGH']
}


interface ConfirmModalProps {
  selectedSeverities: Severity[]
  budget: number
  skipLow: boolean
  requireChecks: boolean
  audit: boolean
  isPending: boolean
  onSeverityToggle: (sev: Severity) => void
  onConfirm: () => void
  onCancel: () => void
}

function ConfirmModal({
  selectedSeverities, budget, skipLow, requireChecks, audit,
  isPending, onSeverityToggle, onConfirm, onCancel,
}: ConfirmModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="nyx-card w-full max-w-md p-6 space-y-5">
        {/* Header */}
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-amber-500/15">
            <Zap size={18} className="text-amber-400" />
          </div>
          <div>
            <h3 className="text-nyx-moonbeam font-semibold">Activate Auto PR Mode?</h3>
            <p className="text-nyx-mist text-xs mt-0.5">
              Review your configuration before enabling autonomous PR creation. Draft PRs
              always require human review before merging.
            </p>
          </div>
        </div>

        {/* Settings summary */}
        <div className="rounded-lg bg-nyx-dusk/60 border border-nyx-iris/10 divide-y divide-nyx-iris/10">
          {/* Severities — interactive pills so you can adjust right here */}
          <div className="px-4 py-3">
            <p className="text-nyx-mist text-xs mb-2">Target severities</p>
            <div className="flex flex-wrap gap-1.5">
              {ALL_SEVERITIES.map(sev => {
                const meta = SEVERITY_META[sev]
                const checked = selectedSeverities.includes(sev)
                return (
                  <label
                    key={sev}
                    className={clsx(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium cursor-pointer select-none transition-colors',
                      checked ? meta.badge : 'bg-nyx-dusk/60 text-nyx-mist/50 border-nyx-iris/10 hover:border-nyx-iris/30',
                    )}
                  >
                    <input
                      type="checkbox"
                      className="sr-only"
                      checked={checked}
                      onChange={() => onSeverityToggle(sev)}
                    />
                    <span className={clsx('w-1.5 h-1.5 rounded-full', checked ? meta.dot : 'bg-nyx-mist/30')} />
                    {meta.label}
                  </label>
                )
              })}
            </div>
            {selectedSeverities.length === 0 && (
              <p className="text-red-400 text-xs mt-1.5">Select at least one severity to continue.</p>
            )}
          </div>

          {/* Budget */}
          <div className="px-4 py-3 flex items-center justify-between">
            <p className="text-nyx-mist text-xs">Daily token budget</p>
            <span className="text-nyx-moonbeam text-sm font-medium tabular-nums">
              {budget.toLocaleString()} tokens
            </span>
          </div>

          {/* Behavior flags */}
          <div className="px-4 py-3 space-y-1.5">
            <p className="text-nyx-mist text-xs mb-2">Behavior</p>
            {[
              [skipLow,       'Skip low-confidence fixes'],
              [requireChecks, 'Require passing CI checks'],
              [audit,         'Security audit before committing'],
            ].map(([enabled, label]) => (
              <div key={label as string} className="flex items-center gap-2 text-xs">
                <Check
                  size={12}
                  className={enabled ? 'text-amber-400' : 'text-nyx-mist/30'}
                  strokeWidth={enabled ? 3 : 2}
                />
                <span className={enabled ? 'text-nyx-moonbeam' : 'text-nyx-mist/40 line-through'}>
                  {label as string}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={onConfirm}
            disabled={isPending || selectedSeverities.length === 0}
            className="nyx-btn-primary flex-1 text-sm py-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isPending ? 'Enabling…' : 'Enable & Run Now'}
          </button>
          <button
            onClick={onCancel}
            disabled={isPending}
            className="px-4 py-2 text-sm text-nyx-mist rounded-lg border border-nyx-iris/20 hover:border-nyx-iris/40 hover:text-nyx-moonbeam transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

/**
 * Auto PR Mode settings card. Off by default; an amber accent marks it as an
 * autonomous power feature. Toggling ON shows a confirmation modal summarising
 * the active settings; confirming saves config, enables the mode, and immediately
 * queues all eligible open findings. The toggle produces only draft PRs.
 */
export default function AutoPrModeCard({ repo }: { repo: Repository }) {
  const queryClient = useQueryClient()

  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>(
    () => parseSeverities(repo.auto_pr_severity_threshold),
  )
  const [budget, setBudget] = useState<number>(repo.auto_pr_daily_token_budget)
  const [skipLow, setSkipLow] = useState<boolean>(repo.auto_pr_skip_low_confidence)
  const [requireChecks, setRequireChecks] = useState<boolean>(repo.auto_pr_require_passing_checks)
  const [audit, setAudit] = useState<boolean>(repo.auto_pr_security_audit)
  const [showConfirm, setShowConfirm] = useState(false)
  const [triggeredCount, setTriggeredCount] = useState<number | null>(null)

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['repository', repo.id] })
    queryClient.invalidateQueries({ queryKey: ['autoPrBudget', repo.id] })
  }

  const toggleOff = useMutation({
    mutationFn: () => repositoriesApi.setAutoPrMode(repo.id, false),
    onSuccess: () => { setTriggeredCount(null); invalidate() },
  })

  /** Confirm enable: save settings, enable mode, trigger immediate run — all in one shot. */
  const confirmEnable = useMutation({
    mutationFn: async () => {
      await repositoriesApi.update(repo.id, {
        auto_pr_mode: true,
        auto_pr_severity_threshold: selectedSeverities.join(','),
        auto_pr_daily_token_budget: budget,
        auto_pr_skip_low_confidence: skipLow,
        auto_pr_require_passing_checks: requireChecks,
        auto_pr_security_audit: audit,
      })
      const result = await repositoriesApi.runAutoPr(repo.id)
      return result
    },
    onSuccess: (data) => {
      setShowConfirm(false)
      setTriggeredCount(data.queued)
      invalidate()
    },
    onError: () => {
      setShowConfirm(false)
    },
  })

  /** Save settings while mode is already ON — persists config then re-triggers a run with the new settings. */
  const save = useMutation({
    mutationFn: async () => {
      await repositoriesApi.update(repo.id, {
        auto_pr_severity_threshold: selectedSeverities.join(','),
        auto_pr_daily_token_budget: budget,
        auto_pr_skip_low_confidence: skipLow,
        auto_pr_require_passing_checks: requireChecks,
        auto_pr_security_audit: audit,
      })
      const result = await repositoriesApi.runAutoPr(repo.id)
      return result
    },
    onSuccess: (data) => {
      setTriggeredCount(data.queued)
      invalidate()
    },
  })

  const { data: budgetData } = useQuery({
    queryKey: ['autoPrBudget', repo.id],
    queryFn: () => repositoriesApi.getAutoPrBudget(repo.id),
    enabled: repo.auto_pr_mode,
    refetchInterval: 30_000,
  })

  const pctUsed = budgetData?.pct_used ?? 0
  const barColor = pctUsed >= 90 ? 'bg-red-500' : pctUsed >= 70 ? 'bg-amber-500' : 'bg-amber-400'

  const toggleSeverity = (sev: Severity) => {
    setSelectedSeverities(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev],
    )
  }

  return (
    <>
      {showConfirm && (
        <ConfirmModal
          selectedSeverities={selectedSeverities}
          budget={budget}
          skipLow={skipLow}
          requireChecks={requireChecks}
          audit={audit}
          isPending={confirmEnable.isPending}
          onSeverityToggle={toggleSeverity}
          onConfirm={() => confirmEnable.mutate()}
          onCancel={() => setShowConfirm(false)}
        />
      )}

      <div className={clsx(
        'nyx-card p-5 transition-colors',
        repo.auto_pr_mode && 'border-l-4 border-l-amber-500',
      )}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-2">
            <Zap size={18} className={repo.auto_pr_mode ? 'text-amber-400 mt-0.5' : 'text-nyx-mist/50 mt-0.5'} />
            <div>
              <p className="text-nyx-moonbeam font-semibold">Auto PR Mode</p>
              <p className="text-nyx-mist text-xs mt-0.5 max-w-md">
                Automatically triage and open <span className="text-amber-300">draft</span> fix PRs
                for the selected severity levels. Drafts always require human review before merging.
              </p>
            </div>
          </div>

          {/* Toggle */}
          <button
            role="switch"
            aria-checked={repo.auto_pr_mode}
            disabled={toggleOff.isPending || confirmEnable.isPending}
            onClick={() => {
              if (repo.auto_pr_mode) {
                toggleOff.mutate()
              } else {
                setShowConfirm(true)
              }
            }}
            className={clsx(
              'relative h-6 w-11 shrink-0 rounded-full transition-colors overflow-hidden',
              repo.auto_pr_mode ? 'bg-amber-500' : 'bg-nyx-dusk border border-nyx-iris/20',
            )}
          >
            <span className={clsx(
              'absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform',
              repo.auto_pr_mode ? 'translate-x-5' : 'translate-x-0',
            )} />
          </button>
        </div>

        {/* Triggered notice */}
        {triggeredCount !== null && repo.auto_pr_mode && (
          <div className="mt-3 flex items-center gap-2 text-xs text-amber-400 bg-amber-900/20 border border-amber-700/30 rounded-lg px-3 py-2">
            <Zap size={12} />
            {triggeredCount > 0
              ? `Queued ${triggeredCount} finding${triggeredCount === 1 ? '' : 's'} for immediate remediation`
              : 'No eligible open findings to queue right now — will pick up new ones as scans run'}
          </div>
        )}

        {repo.auto_pr_mode && (
          <div className="mt-4 pt-4 border-t border-amber-500/15 space-y-4">
            {/* Severity checkboxes */}
            <div>
              <p className="text-nyx-mist text-xs mb-2">Target severities</p>
              <div className="flex flex-wrap gap-2">
                {ALL_SEVERITIES.map(sev => {
                  const meta = SEVERITY_META[sev]
                  const checked = selectedSeverities.includes(sev)
                  return (
                    <label
                      key={sev}
                      className={clsx(
                        'flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium cursor-pointer select-none transition-colors',
                        checked ? meta.badge : 'bg-nyx-dusk text-nyx-mist/60 border-nyx-iris/10 hover:border-nyx-iris/30',
                      )}
                    >
                      <input
                        type="checkbox"
                        className="sr-only"
                        checked={checked}
                        onChange={() => toggleSeverity(sev)}
                      />
                      <span className={clsx('w-1.5 h-1.5 rounded-full', checked ? meta.dot : 'bg-nyx-mist/30')} />
                      {meta.label}
                    </label>
                  )
                })}
              </div>
              {selectedSeverities.length === 0 && (
                <p className="text-red-400 text-xs mt-1.5">Select at least one severity.</p>
              )}
            </div>

            {/* Daily token budget */}
            <div>
              <p className="text-nyx-mist text-xs mb-1.5">Daily token budget</p>
              <div className="flex items-center gap-2 flex-wrap">
                <input
                  type="number"
                  min={1000}
                  max={500000}
                  value={budget}
                  onChange={e => setBudget(Number(e.target.value))}
                  className="nyx-input w-32"
                />
                {BUDGET_PRESETS.map(p => (
                  <button
                    key={p}
                    onClick={() => setBudget(p)}
                    className={clsx('nyx-badge cursor-pointer border',
                      budget === p
                        ? 'bg-amber-900/30 text-amber-300 border-amber-700/40'
                        : 'bg-nyx-dusk text-nyx-mist border-nyx-iris/10')}
                  >
                    {p / 1000}k
                  </button>
                ))}
              </div>
            </div>

            {/* Behavior flags */}
            <div className="space-y-2">
              {([
                ['skipLow',       skipLow,       setSkipLow,       'Skip low-confidence fixes'],
                ['requireChecks', requireChecks, setRequireChecks, 'Require passing CI checks'],
                ['audit',         audit,         setAudit,         'Security audit each fix before committing'],
              ] as const).map(([key, val, setter, label]) => (
                <label key={key} className="flex items-center gap-2 cursor-pointer select-none text-sm">
                  <input type="checkbox" checked={val} onChange={e => setter(e.target.checked)} className="rounded" />
                  <span className="text-nyx-moonbeam">{label}</span>
                </label>
              ))}
            </div>

            {/* Budget usage bar */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-nyx-mist text-xs">Today's token usage</span>
                <span className="text-nyx-moonbeam text-xs font-medium">
                  {(budgetData?.tokens_used_today ?? 0).toLocaleString()} / {(budgetData?.daily_budget ?? budget).toLocaleString()}
                </span>
              </div>
              <div className="w-full h-2 bg-nyx-dusk rounded-full overflow-hidden">
                <div className={clsx('h-full rounded-full transition-all', barColor)} style={{ width: `${Math.min(pctUsed, 100)}%` }} />
              </div>
              {(budgetData?.tokens_used_today ?? 0) === 0 && (
                <p className="text-nyx-mist/40 text-xs mt-1">No auto PR activity today</p>
              )}
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => save.mutate()}
                disabled={save.isPending || selectedSeverities.length === 0}
                className="nyx-btn-primary text-sm px-4 py-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {save.isPending ? 'Saving…' : 'Save settings'}
              </button>
              {save.isSuccess && <span className="text-green-400 text-xs">Saved</span>}
              {save.isError && <span className="text-red-400 text-xs">Save failed</span>}
            </div>
          </div>
        )}
      </div>
    </>
  )
}
