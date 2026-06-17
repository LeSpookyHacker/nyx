import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { Zap } from 'lucide-react'
import { repositoriesApi } from '../../api/repositories'
import type { Repository } from '../../types'

const BUDGET_PRESETS = [10_000, 50_000, 100_000, 200_000]

/**
 * Auto PR Mode settings card. Off by default; an amber accent marks it as an
 * autonomous power feature. The toggle persists immediately; the rest of the
 * config is saved together. A draft PR is the only artifact this ever produces.
 */
export default function AutoPrModeCard({ repo }: { repo: Repository }) {
  const queryClient = useQueryClient()

  const [threshold, setThreshold] = useState<'CRITICAL' | 'HIGH'>(repo.auto_pr_severity_threshold)
  const [budget, setBudget] = useState<number>(repo.auto_pr_daily_token_budget)
  const [skipLow, setSkipLow] = useState<boolean>(repo.auto_pr_skip_low_confidence)
  const [requireChecks, setRequireChecks] = useState<boolean>(repo.auto_pr_require_passing_checks)
  const [audit, setAudit] = useState<boolean>(repo.auto_pr_security_audit)

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['repository', repo.id] })
    queryClient.invalidateQueries({ queryKey: ['autoPrBudget', repo.id] })
  }

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => repositoriesApi.setAutoPrMode(repo.id, enabled),
    onSuccess: invalidate,
  })

  const save = useMutation({
    mutationFn: () => repositoriesApi.update(repo.id, {
      auto_pr_severity_threshold: threshold,
      auto_pr_daily_token_budget: budget,
      auto_pr_skip_low_confidence: skipLow,
      auto_pr_require_passing_checks: requireChecks,
      auto_pr_security_audit: audit,
    }),
    onSuccess: invalidate,
  })

  const { data: budgetData } = useQuery({
    queryKey: ['autoPrBudget', repo.id],
    queryFn: () => repositoriesApi.getAutoPrBudget(repo.id),
    enabled: repo.auto_pr_mode,
    refetchInterval: 30_000,
  })

  const pctUsed = budgetData?.pct_used ?? 0
  const barColor = pctUsed >= 90 ? 'bg-red-500' : pctUsed >= 70 ? 'bg-amber-500' : 'bg-amber-400'

  return (
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
              for critical and high findings. Drafts always require human review before merging.
            </p>
          </div>
        </div>
        {/* Weighty amber toggle — autonomous action with real consequences */}
        <button
          role="switch"
          aria-checked={repo.auto_pr_mode}
          disabled={toggle.isPending}
          onClick={() => toggle.mutate(!repo.auto_pr_mode)}
          className={clsx(
            'relative h-7 w-12 shrink-0 rounded-full transition-colors',
            repo.auto_pr_mode ? 'bg-amber-500' : 'bg-nyx-dusk border border-nyx-iris/20',
          )}
        >
          <span className={clsx(
            'absolute top-0.5 h-6 w-6 rounded-full bg-white shadow transition-transform',
            repo.auto_pr_mode ? 'translate-x-5' : 'translate-x-0.5',
          )} />
        </button>
      </div>

      {repo.auto_pr_mode && (
        <div className="mt-4 pt-4 border-t border-amber-500/15 space-y-4">
          {/* Severity threshold */}
          <div>
            <p className="text-nyx-mist text-xs mb-1.5">Severity threshold</p>
            <div className="flex gap-2">
              {([['CRITICAL', 'Critical only'], ['HIGH', 'Critical + High']] as const).map(([value, label]) => (
                <label key={value} className="flex items-center gap-1.5 cursor-pointer text-sm">
                  <input
                    type="radio"
                    name="auto-pr-threshold"
                    checked={threshold === value}
                    onChange={() => setThreshold(value)}
                  />
                  <span className="text-nyx-moonbeam">{label}</span>
                </label>
              ))}
            </div>
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
                    budget === p ? 'bg-amber-900/30 text-amber-300 border-amber-700/40' : 'bg-nyx-dusk text-nyx-mist border-nyx-iris/10')}
                >
                  {p / 1000}k
                </button>
              ))}
            </div>
          </div>

          {/* Behavior flags */}
          <div className="space-y-2">
            {([
              ['skipLow', skipLow, setSkipLow, 'Skip low-confidence fixes'],
              ['requireChecks', requireChecks, setRequireChecks, 'Require passing CI checks'],
              ['audit', audit, setAudit, 'Security audit each fix before committing'],
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
              disabled={save.isPending}
              className="nyx-btn-primary text-sm px-4 py-1.5"
            >
              {save.isPending ? 'Saving…' : 'Save settings'}
            </button>
            {save.isSuccess && <span className="text-green-400 text-xs">Saved</span>}
            {save.isError && <span className="text-red-400 text-xs">Save failed</span>}
          </div>
        </div>
      )}
    </div>
  )
}
