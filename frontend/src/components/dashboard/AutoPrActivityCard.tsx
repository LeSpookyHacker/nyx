import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { isToday } from 'date-fns'
import { Zap, GitPullRequest, ShieldAlert } from 'lucide-react'
import { repositoriesApi } from '../../api/repositories'
import { remediationApi } from '../../api/remediation'

/**
 * Dashboard card summarizing today's Auto PR Mode activity. Renders only when at
 * least one repository has Auto PR Mode enabled. Stats are derived client-side
 * from the repositories and remediations lists (no dedicated endpoint needed).
 */
export default function AutoPrActivityCard() {
  const navigate = useNavigate()

  const { data: repos = [] } = useQuery({ queryKey: ['repositories'], queryFn: repositoriesApi.list })
  const { data: remediations = [] } = useQuery({
    queryKey: ['remediations'],
    queryFn: remediationApi.list,
    refetchInterval: 60_000,
  })

  const enabledRepos = repos.filter(r => r.auto_pr_mode)
  if (enabledRepos.length === 0) return null

  const auto = remediations.filter(r => r.is_auto_triggered)
  const draftsToday = auto.filter(r => r.status === 'COMMITTED' && isToday(new Date(r.updated_at))).length
  const blockedToday = auto.filter(
    r => (r.status === 'AUDIT_FAILED' || r.status === 'TEST_FAILED') && isToday(new Date(r.updated_at)),
  ).length

  const tokensUsed = enabledRepos.reduce((s, r) => s + (r.auto_pr_tokens_used_today || 0), 0)
  const tokensBudget = enabledRepos.reduce((s, r) => s + (r.auto_pr_daily_token_budget || 0), 0)
  const pct = tokensBudget > 0 ? Math.min(100, Math.round((100 * tokensUsed) / tokensBudget)) : 0

  return (
    <div className="nyx-card p-5 border-l-4 border-l-amber-500">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-nyx-moonbeam font-semibold flex items-center gap-2">
          <Zap size={16} className="text-amber-400" /> Auto PR Activity
        </h3>
        <button
          onClick={() => navigate('/remediation?filter=auto')}
          className="text-amber-300 hover:text-amber-200 text-xs"
        >
          View all Auto PR activity →
        </button>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <div>
          <p className="text-nyx-mist text-xs flex items-center gap-1"><GitPullRequest size={12} /> Draft PRs today</p>
          <p className="text-2xl font-bold text-nyx-moonbeam mt-1">{draftsToday}</p>
        </div>
        <div>
          <p className="text-nyx-mist text-xs flex items-center gap-1"><ShieldAlert size={12} /> Blocked today</p>
          <p className="text-2xl font-bold text-nyx-moonbeam mt-1">{blockedToday}</p>
        </div>
        <div>
          <p className="text-nyx-mist text-xs">Tokens used / budget</p>
          <p className="text-sm font-medium text-nyx-moonbeam mt-1">
            {tokensUsed.toLocaleString()} / {tokensBudget.toLocaleString()}
          </p>
          <div className="w-full h-1.5 bg-nyx-dusk rounded-full overflow-hidden mt-1.5">
            <div className="h-full rounded-full bg-amber-400" style={{ width: `${pct}%` }} />
          </div>
        </div>
      </div>
    </div>
  )
}
