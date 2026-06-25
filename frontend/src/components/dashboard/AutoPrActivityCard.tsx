import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { isToday } from 'date-fns'
import { Zap, GitPullRequest, ShieldAlert, XCircle, AlertTriangle } from 'lucide-react'
import { repositoriesApi } from '../../api/repositories'
import { remediationApi } from '../../api/remediation'
import type { Remediation } from '../../types'

// ── Gate metadata helpers ────────────────────────────────────────────────────

type BlockedGate = 'audit' | 'ci' | 'low_confidence'

function getGate(r: Remediation): BlockedGate {
  if (r.status === 'AUDIT_FAILED') return 'audit'
  if (r.status === 'TEST_FAILED') return 'ci'
  return 'low_confidence'
}

function getGateLabel(gate: BlockedGate): string {
  if (gate === 'audit') return 'Audit'
  if (gate === 'ci') return 'CI'
  return 'Low Conf.'
}

function getGateIcon(gate: BlockedGate) {
  if (gate === 'audit') return <ShieldAlert size={11} className="text-red-400 shrink-0 mt-0.5" />
  if (gate === 'ci') return <XCircle size={11} className="text-orange-400 shrink-0 mt-0.5" />
  return <AlertTriangle size={11} className="text-yellow-400 shrink-0 mt-0.5" />
}

function getGateBadgeClass(gate: BlockedGate): string {
  if (gate === 'audit') return 'bg-red-900/40 text-red-300'
  if (gate === 'ci') return 'bg-orange-900/40 text-orange-300'
  return 'bg-yellow-900/40 text-yellow-300'
}

/**
 * Extract a human-readable reason snippet for why the gate blocked the fix.
 * Kept short (≤90 chars) for the compact card layout.
 */
function getReason(r: Remediation): string {
  if (r.status === 'AUDIT_FAILED' && r.audit_result) {
    try {
      const parsed = JSON.parse(r.audit_result) as {
        risk_level?: string
        summary?: string
        findings?: string[]
      }
      const level = parsed.risk_level ?? 'UNKNOWN'
      const snippet =
        parsed.summary?.slice(0, 72) ??
        parsed.findings?.[0]?.slice(0, 72) ??
        'Security audit failed'
      return `${level} risk — ${snippet}${(parsed.summary?.length ?? 0) > 72 ? '…' : ''}`
    } catch {
      return 'Security audit failed'
    }
  }

  if (r.status === 'TEST_FAILED') {
    const conclusion = r.check_run_conclusion ? `checks: ${r.check_run_conclusion}` : null
    const details = r.ci_failure_details?.slice(0, 72)
    return conclusion ?? details ?? 'CI check failed'
  }

  // REVIEW_LOW_CONFIDENCE — distinguish between the two sub-reasons
  if (r.confidence_flagged) {
    const pct = r.ai_confidence != null ? ` (${Math.round(r.ai_confidence * 100)}%)` : ''
    return `AI confidence too low${pct} — needs human review`
  }
  if (r.diff_warnings) {
    try {
      const warnings = JSON.parse(r.diff_warnings) as string[]
      return `Diff warning — ${warnings[0]?.slice(0, 72) ?? 'heuristic flag'}`
    } catch {
      return 'Diff security warning — needs human review'
    }
  }
  return 'Flagged for human review'
}

/** Best-effort display title: prefer ai_fix_summary, fall back to short finding ID. */
function getTitle(r: Remediation): string {
  return r.ai_fix_summary?.slice(0, 50) ?? `Finding ${r.finding_id.slice(0, 8)}`
}

// ── Component ────────────────────────────────────────────────────────────────

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
  const draftsToday = auto.filter(
    r => r.status === 'COMMITTED' && isToday(new Date(r.updated_at)),
  ).length

  const blockedItems = auto.filter(
    r =>
      (r.status === 'AUDIT_FAILED' ||
        r.status === 'TEST_FAILED' ||
        r.status === 'REVIEW_LOW_CONFIDENCE') &&
      isToday(new Date(r.updated_at)),
  )
  const blockedToday = blockedItems.length

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

      {/* ── Top stats row ── */}
      <div className="grid grid-cols-3 gap-4">
        <div>
          <p className="text-nyx-mist text-xs flex items-center gap-1">
            <GitPullRequest size={12} /> Draft PRs today
          </p>
          <p className="text-2xl font-bold text-nyx-moonbeam mt-1">{draftsToday}</p>
        </div>
        <div>
          <p className="text-nyx-mist text-xs flex items-center gap-1">
            <ShieldAlert size={12} /> Blocked today
          </p>
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

      {/* ── Blocked detail breakdown ── */}
      {blockedItems.length > 0 && (
        <div className="mt-4 border-t border-nyx-dusk pt-3 space-y-2">
          <p className="text-nyx-mist text-xs font-medium uppercase tracking-wide mb-1">
            Blocked details
          </p>
          {blockedItems.slice(0, 5).map(r => {
            const gate = getGate(r)
            return (
              <button
                key={r.id}
                onClick={() => navigate(`/remediation/${r.id}`)}
                className="w-full text-left flex items-start gap-2 group"
              >
                {getGateIcon(gate)}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span
                      className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${getGateBadgeClass(gate)}`}
                    >
                      {getGateLabel(gate)}
                    </span>
                    <span className="text-nyx-moonbeam text-xs truncate group-hover:text-amber-300 transition-colors">
                      {getTitle(r)}
                    </span>
                  </div>
                  <p className="text-nyx-mist text-[11px] mt-0.5 leading-snug line-clamp-1">
                    {getReason(r)}
                  </p>
                </div>
              </button>
            )
          })}
          {blockedItems.length > 5 && (
            <p className="text-nyx-mist text-xs text-center pt-1">
              +{blockedItems.length - 5} more —{' '}
              <button
                onClick={() => navigate('/remediation?filter=auto')}
                className="text-amber-300 hover:text-amber-200"
              >
                view all
              </button>
            </p>
          )}
        </div>
      )}
    </div>
  )
}
