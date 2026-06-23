import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { remediationApi } from '../api/remediation'
import type { Remediation } from '../types'
import { formatDistanceToNow } from 'date-fns'
import { CheckCircle, ExternalLink, RefreshCw, XCircle, GitPullRequest, Wand2, AlertCircle, Ticket, Trash2, ShieldAlert, ShieldCheck, Zap } from 'lucide-react'
import { clsx } from 'clsx'
import MarkdownContent from '../components/common/MarkdownContent'
import { safeUrl } from '../utils/url'

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  PENDING:     { label: 'Pending',       color: 'text-slate-400',   icon: RefreshCw },
  GENERATING:  { label: 'Generating fix', color: 'text-blue-400',  icon: Wand2 },
  REVIEW:      { label: 'Ready for Review', color: 'text-yellow-400', icon: AlertCircle },
  REVIEW_LOW_CONFIDENCE: { label: 'Low confidence', color: 'text-amber-400', icon: AlertCircle },
  PR_CREATING: { label: 'Creating PR...',  color: 'text-blue-400',   icon: GitPullRequest },
  PR_OPEN:     { label: 'PR Open',         color: 'text-indigo-400',  icon: GitPullRequest },
  MERGED:      { label: 'Merged',          color: 'text-green-400',   icon: CheckCircle },
  FAILED:      { label: 'Failed',          color: 'text-red-400',     icon: XCircle },
  REJECTED:    { label: 'Rejected',        color: 'text-slate-400',   icon: XCircle },
  // Auto PR Mode pipeline
  AUTO_TRIGGERED:    { label: 'Queued',          color: 'text-slate-400',  icon: RefreshCw },
  AUDIT_IN_PROGRESS: { label: 'Security audit',  color: 'text-blue-400',   icon: ShieldAlert },
  AUDIT_FAILED:      { label: 'Blocked by audit', color: 'text-red-400',   icon: ShieldAlert },
  TEST_IN_PROGRESS:  { label: 'Awaiting CI',     color: 'text-amber-400',  icon: RefreshCw },
  TEST_FAILED:       { label: 'CI failed',       color: 'text-red-400',    icon: XCircle },
  COMMITTED:         { label: 'Draft PR open',   color: 'text-green-400',  icon: GitPullRequest },
  BUDGET_EXCEEDED:   { label: 'Budget cap reached', color: 'text-amber-400', icon: AlertCircle },
}

function RemediationCard({ rem, onSelect }: { rem: Remediation; onSelect: (id: string) => void }) {
  const queryClient = useQueryClient()
  const cfg = STATUS_CONFIG[rem.status] || STATUS_CONFIG.PENDING
  const Icon = cfg.icon

  const dismiss = useMutation({
    mutationFn: () => remediationApi.dismiss(rem.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['remediations'] }),
  })

  return (
    <div
      className="nyx-card p-4 cursor-pointer hover:border-nyx-amethyst/40 transition-colors"
      onClick={() => onSelect(rem.id)}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="flex items-center gap-1.5">
          <span className={clsx('flex items-center gap-1.5 text-xs font-medium', cfg.color)}>
            <Icon size={12} className={rem.status === 'GENERATING' ? 'animate-spin' : ''} />
            {cfg.label}
          </span>
          {rem.is_auto_triggered && (
            <span className="nyx-badge bg-amber-900/30 text-amber-400 border border-amber-800/30" title="Generated automatically by Auto PR Mode">
              <Zap size={10} /> AUTO
            </span>
          )}
        </span>
        <div className="flex items-center gap-1">
          <span className="text-nyx-mist text-xs">{formatDistanceToNow(new Date(rem.created_at))} ago</span>
          {['FAILED', 'REJECTED'].includes(rem.status) && (
            <button
              onClick={e => { e.stopPropagation(); dismiss.mutate() }}
              className="ml-1 p-1 rounded hover:bg-red-900/30 text-nyx-mist/40 hover:text-red-400 transition-colors"
              title="Dismiss"
            >
              <Trash2 size={11} />
            </button>
          )}
        </div>
      </div>
      {rem.ai_fix_summary && (
        <p className="text-nyx-moonbeam text-sm font-medium mb-1">{rem.ai_fix_summary}</p>
      )}
      {rem.ai_confidence !== undefined && rem.ai_confidence !== null && (
        <p className="text-nyx-mist text-xs">AI Confidence: {(rem.ai_confidence * 100).toFixed(0)}%</p>
      )}
      {rem.audit_passed !== undefined && rem.audit_passed !== null && (
        <span className={clsx('flex items-center gap-1 mt-1.5 text-xs font-medium',
          rem.audit_passed ? 'text-green-400' : 'text-red-400')}>
          <ShieldCheck size={11} /> Security audit {rem.audit_passed ? 'passed' : 'failed'}
        </span>
      )}
      {/* SEC-332: validate pr_url scheme */}
      {rem.pr_url && (
        <a href={safeUrl(rem.pr_url)} target="_blank" rel="noopener noreferrer"
          className="text-nyx-stardust text-xs flex items-center gap-1 mt-2 hover:text-nyx-amethyst"
          onClick={e => e.stopPropagation()}>
          <GitPullRequest size={11} />
          {rem.is_auto_triggered ? 'Draft — review required' : 'View PR'}
          <ExternalLink size={10} />
        </a>
      )}
      {rem.ci_status === 'fail' && (
        <span className="flex items-center gap-1 mt-1.5 text-xs text-red-400 font-medium">
          <ShieldAlert size={11} /> CI checks failed
        </span>
      )}
      {rem.ci_status === 'pass' && (
        <span className="flex items-center gap-1 mt-1.5 text-xs text-green-400">
          <ShieldCheck size={11} /> CI passed
        </span>
      )}
      {rem.jira_issue_key && (
        <span className="text-nyx-mist text-xs flex items-center gap-1 mt-1">
          <Ticket size={11} /> {rem.jira_issue_key}
        </span>
      )}
    </div>
  )
}

function RemediationPanel({ rem, onClose }: { rem: Remediation; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [notes, setNotes] = useState('')
  const [regenContext, setRegenContext] = useState('')
  const [autoMerge, setAutoMerge] = useState(false)
  const [jiraAssignee, setJiraAssignee] = useState('')

  const isNoCodeFix = rem.ai_fix_diff?.startsWith('NO_CODE_FIX')

  const approve = useMutation({
    mutationFn: () => remediationApi.approve(rem.id, notes, autoMerge, jiraAssignee || undefined),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['remediations'] }),
  })

  const reject = useMutation({
    mutationFn: () => remediationApi.reject(rem.id, notes || 'No reason provided.'),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['remediations'] }),
  })

  const regenerate = useMutation({
    mutationFn: () => remediationApi.regenerate(rem.id, regenContext),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['remediations'] }),
  })

  return (
    <div className="fixed inset-y-0 right-0 w-[600px] bg-nyx-midnight border-l border-nyx-iris/20 shadow-2xl z-50 overflow-y-auto">
      <div className="sticky top-0 bg-nyx-midnight/95 backdrop-blur border-b border-nyx-iris/10 px-5 py-4 flex items-center justify-between">
        <h2 className="text-nyx-moonbeam font-bold">AI Fix Review</h2>
        <button onClick={onClose} className="nyx-btn-ghost p-2"><XCircle size={16} /></button>
      </div>

      <div className="p-5 space-y-4">
        {/* Explanation */}
        {rem.ai_explanation && (
          <div className="nyx-card p-4">
            <h3 className="text-nyx-moonbeam font-semibold mb-3 text-sm">Explanation</h3>
            <MarkdownContent>{rem.ai_explanation}</MarkdownContent>
          </div>
        )}

        {/* Diff */}
        {rem.ai_fix_diff && !isNoCodeFix && (
          <div className="nyx-card overflow-hidden">
            <div className="px-4 py-3 border-b border-nyx-iris/10 flex items-center justify-between">
              <h3 className="text-nyx-moonbeam font-semibold text-sm">Proposed Fix</h3>
              {rem.ai_confidence !== undefined && rem.ai_confidence !== null && (
                <span className="text-nyx-mist text-xs">
                  Confidence: <span className="text-nyx-amethyst font-semibold">{(rem.ai_confidence * 100).toFixed(0)}%</span>
                </span>
              )}
            </div>
            <div className="overflow-auto max-h-[420px] bg-[#0d0d1a]">
              {rem.ai_fix_diff.split('\n').map((line, i) => {
                const isAdd = line.startsWith('+') && !line.startsWith('+++')
                const isDel = line.startsWith('-') && !line.startsWith('---')
                const isHunk = line.startsWith('@@')
                const isHeader = line.startsWith('+++') || line.startsWith('---') || line.startsWith('diff ')
                return (
                  <div
                    key={i}
                    className={clsx(
                      'px-4 py-px font-mono text-[11px] leading-5 whitespace-pre select-text',
                      isAdd && 'bg-green-900/25 text-green-300',
                      isDel && 'bg-red-900/25 text-red-300',
                      isHunk && 'bg-nyx-iris/10 text-nyx-lavender',
                      isHeader && 'text-nyx-mist/50',
                      !isAdd && !isDel && !isHunk && !isHeader && 'text-nyx-mist/70',
                    )}
                  >
                    {line || ' '}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* No-code-fix notice */}
        {isNoCodeFix && rem.ai_explanation && (
          <div className="nyx-card p-4 border border-yellow-800/30">
            <h3 className="text-yellow-400 font-semibold mb-2 text-sm flex items-center gap-2">
              <AlertCircle size={14} /> Manual Remediation Required
            </h3>
            <MarkdownContent>{rem.ai_explanation}</MarkdownContent>
          </div>
        )}

        {/* Actions */}
        {rem.status === 'REVIEW' && (
          <div className="nyx-card p-4 space-y-3">
            <textarea
              className="nyx-input w-full h-20 resize-none"
              placeholder="Engineer notes (optional)..."
              value={notes}
              onChange={e => setNotes(e.target.value)}
            />
            <input
              type="text"
              className="nyx-input w-full"
              placeholder="Assign JIRA ticket to (email or name)..."
              value={jiraAssignee}
              onChange={e => setJiraAssignee(e.target.value)}
            />
            {!isNoCodeFix && (
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoMerge}
                  onChange={e => setAutoMerge(e.target.checked)}
                  className="rounded"
                />
                <span className="text-nyx-mist text-sm">Auto-merge after PR creation</span>
              </label>
            )}
            <div className="flex gap-2">
              <button onClick={() => approve.mutate()} disabled={approve.isPending} className="nyx-btn-primary flex-1">
                <CheckCircle size={14} />
                {approve.isPending
                  ? (autoMerge ? 'Merging...' : 'Creating PR...')
                  : (autoMerge ? 'Approve & Auto-merge' : 'Approve & Create PR')}
              </button>
              <button onClick={() => reject.mutate()} disabled={reject.isPending} className="nyx-btn-danger flex-1">
                <XCircle size={14} />
                Reject
              </button>
            </div>
          </div>
        )}

        {/* Regenerate */}
        {(['REVIEW', 'FAILED', 'REJECTED'].includes(rem.status) || (rem.status === 'PR_OPEN' && rem.ci_status === 'fail')) && (
          <div className="nyx-card p-4 space-y-3">
            <h3 className="text-nyx-mist font-semibold text-sm">Regenerate Fix</h3>
            <textarea
              className="nyx-input w-full h-20 resize-none"
              placeholder="Tell the AI what was wrong or provide additional context..."
              value={regenContext}
              onChange={e => setRegenContext(e.target.value)}
            />
            <button onClick={() => regenerate.mutate()} disabled={!regenContext || regenerate.isPending} className="nyx-btn-ghost w-full">
              <RefreshCw size={14} />
              {regenerate.isPending ? 'Regenerating...' : 'Regenerate with Context'}
            </button>
          </div>
        )}

        {rem.error_message && (
          <div className="nyx-card p-4 border border-red-800/30">
            <p className="text-red-400 text-sm font-semibold mb-1">Error</p>
            <p className="text-nyx-mist text-xs font-mono">{rem.error_message}</p>
          </div>
        )}

        {rem.pr_url && (
          <div className="nyx-card p-4">
            <div className="flex items-center justify-between mb-1">
              <p className="text-nyx-mist text-sm">Pull Request</p>
              {rem.ci_status === 'fail' && (
                <span className="flex items-center gap-1 text-xs text-red-400 font-medium">
                  <ShieldAlert size={12} /> CI failed
                </span>
              )}
              {rem.ci_status === 'pass' && (
                <span className="flex items-center gap-1 text-xs text-green-400">
                  <ShieldCheck size={12} /> CI passed
                </span>
              )}
              {rem.ci_status === 'pending' && (
                <span className="flex items-center gap-1 text-xs text-yellow-400">
                  <RefreshCw size={12} className="animate-spin" /> CI running
                </span>
              )}
            </div>
            <a href={safeUrl(rem.pr_url)} target="_blank" rel="noopener noreferrer"
              className="text-nyx-stardust flex items-center gap-1 hover:text-nyx-amethyst text-sm">
              <GitPullRequest size={14} /> PR #{rem.pr_number} <ExternalLink size={12} />
            </a>
          </div>
        )}

        {rem.ci_status === 'fail' && rem.ci_failure_details && (
          <div className="nyx-card p-4 border border-red-800/40">
            <p className="text-red-400 text-sm font-semibold mb-2 flex items-center gap-1.5">
              <ShieldAlert size={14} /> CI Check Failures
            </p>
            <p className="text-nyx-mist text-xs leading-relaxed whitespace-pre-wrap font-mono">{rem.ci_failure_details}</p>
            <p className="text-nyx-mist/60 text-xs mt-3">The fix was committed but CI failed. Review the PR, fix the issues, or regenerate the fix with additional context below.</p>
          </div>
        )}

        {rem.jira_issue_key && rem.jira_issue_url && (
          <div className="nyx-card p-4">
            <p className="text-nyx-mist text-sm mb-1">JIRA Ticket</p>
            <a href={safeUrl(rem.jira_issue_url)} target="_blank" rel="noopener noreferrer"
              className="text-nyx-stardust flex items-center gap-1 hover:text-nyx-amethyst text-sm font-mono">
              <Ticket size={14} /> {rem.jira_issue_key} <ExternalLink size={12} />
            </a>
          </div>
        )}
      </div>
    </div>
  )
}

const ACTIVE_STATUSES = ['PENDING', 'GENERATING', 'REVIEW', 'PR_CREATING', 'PR_OPEN', 'FAILED']
const ALL_COLUMNS = ['PENDING', 'GENERATING', 'REVIEW', 'PR_OPEN', 'MERGED', 'FAILED']
const ACTIVE_COLUMNS = ['PENDING', 'GENERATING', 'REVIEW', 'PR_OPEN', 'FAILED']
const AUTO_COLUMNS = ['AUTO_TRIGGERED', 'GENERATING', 'AUDIT_IN_PROGRESS', 'TEST_IN_PROGRESS', 'COMMITTED', 'AUDIT_FAILED']

/** AI-driven remediation queue showing fix requests, diffs, and approval workflow. */
export default function RemediationPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [view, setView] = useState<'active' | 'all' | 'auto'>(
    () => (new URLSearchParams(window.location.search).get('filter') === 'auto' ? 'auto' : 'active')
  )

  const { data: remediations = [], isLoading } = useQuery({
    queryKey: ['remediations'],
    queryFn: remediationApi.list,
    refetchInterval: 5_000, // Poll for AI generation updates
  })

  // Always read the live version of the selected remediation from the query data
  const selected = remediations.find(r => r.id === selectedId) ?? null

  // Finding IDs that have a successful remediation (PR open or merged) — used to auto-hide superseded failures
  const succeededFindingIds = new Set(
    remediations
      .filter(r => ['PR_OPEN', 'PR_CREATING', 'MERGED'].includes(r.status))
      .map(r => r.finding_id)
  )

  const COLUMNS = view === 'auto' ? AUTO_COLUMNS : view === 'all' ? ALL_COLUMNS : ACTIVE_COLUMNS

  const visibleRemediations = remediations.filter(r => {
    if (view === 'auto') return r.is_auto_triggered === true
    if (r.status === 'FAILED' && succeededFindingIds.has(r.finding_id)) return false
    if (view === 'active' && !ACTIVE_STATUSES.includes(r.status)) return false
    return true
  })

  const byStatus = COLUMNS.reduce((acc, col) => {
    acc[col] = visibleRemediations.filter(r => r.status === col)
    return acc
  }, {} as Record<string, Remediation[]>)

  if (isLoading) return <div className="text-nyx-mist p-8">Loading remediations...</div>

  const activeCount = remediations.filter(r => ACTIVE_STATUSES.includes(r.status)).length

  return (
    <div className="space-y-4 relative">
      <div className="flex items-center justify-between">
        <p className="text-nyx-mist text-sm">{activeCount} active · {remediations.length} total</p>
        <div className="flex gap-1 text-sm">
          <button
            onClick={() => setView('active')}
            className={clsx('px-3 py-1.5 rounded transition-colors',
              view === 'active' ? 'text-nyx-moonbeam border-b-2 border-nyx-amethyst font-medium' : 'text-nyx-mist hover:text-nyx-moonbeam'
            )}
          >
            Active
          </button>
          <button
            onClick={() => setView('all')}
            className={clsx('px-3 py-1.5 rounded transition-colors',
              view === 'all' ? 'text-nyx-moonbeam border-b-2 border-nyx-amethyst font-medium' : 'text-nyx-mist hover:text-nyx-moonbeam'
            )}
          >
            All
          </button>
          <button
            onClick={() => setView('auto')}
            className={clsx('px-3 py-1.5 rounded transition-colors flex items-center gap-1',
              view === 'auto' ? 'text-amber-300 border-b-2 border-amber-400 font-medium' : 'text-nyx-mist hover:text-amber-300'
            )}
          >
            <Zap size={12} /> Auto PR
          </button>
        </div>
      </div>

      {remediations.length === 0 && (
        <div className="nyx-card p-12 text-center">
          <Wand2 size={32} className="text-nyx-iris mx-auto mb-3 opacity-50" />
          <p className="text-nyx-mist">No remediation requests yet.</p>
          <p className="text-nyx-mist/50 text-sm mt-1">Go to a finding and click "Request AI Fix" to start.</p>
        </div>
      )}

      {remediations.length > 0 && (
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
          {COLUMNS.map(col => {
            const cfg = STATUS_CONFIG[col]
            const Icon = cfg.icon
            const items = byStatus[col] || []
            return (
              <div key={col}>
                <div className="flex items-center gap-1.5 mb-2 px-1">
                  <Icon size={12} className={cfg.color} />
                  <span className={clsx('text-xs font-medium', cfg.color)}>{cfg.label}</span>
                  {items.length > 0 && (
                    <span className="ml-auto bg-nyx-dusk rounded-full px-1.5 text-[10px] text-nyx-mist">{items.length}</span>
                  )}
                </div>
                <div className="space-y-2">
                  {items.map(rem => (
                    <RemediationCard key={rem.id} rem={rem} onSelect={setSelectedId} />
                  ))}
                  {items.length === 0 && (
                    <div className="border border-dashed border-nyx-iris/10 rounded-lg p-3 text-center text-nyx-mist/30 text-xs">
                      empty
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {selected && (
        <>
          <div className="fixed inset-0 bg-black/40 z-40" onClick={() => setSelectedId(null)} />
          <RemediationPanel rem={selected} onClose={() => setSelectedId(null)} />
        </>
      )}
    </div>
  )
}
