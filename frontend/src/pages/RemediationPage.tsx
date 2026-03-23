import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { remediationApi } from '../api/remediation'
import type { Remediation } from '../types'
import { formatDistanceToNow } from 'date-fns'
import { CheckCircle, ExternalLink, RefreshCw, XCircle, GitPullRequest, Wand2, AlertCircle, Ticket } from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { clsx } from 'clsx'

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  PENDING:     { label: 'Pending',       color: 'text-slate-400',   icon: RefreshCw },
  GENERATING:  { label: 'Generating...',  color: 'text-purple-400',  icon: Wand2 },
  REVIEW:      { label: 'Ready for Review', color: 'text-yellow-400', icon: AlertCircle },
  PR_CREATING: { label: 'Creating PR...',  color: 'text-blue-400',   icon: GitPullRequest },
  PR_OPEN:     { label: 'PR Open',         color: 'text-indigo-400',  icon: GitPullRequest },
  MERGED:      { label: 'Merged',          color: 'text-green-400',   icon: CheckCircle },
  FAILED:      { label: 'Failed',          color: 'text-red-400',     icon: XCircle },
  REJECTED:    { label: 'Rejected',        color: 'text-slate-400',   icon: XCircle },
}

function RemediationCard({ rem, onSelect }: { rem: Remediation; onSelect: (r: Remediation) => void }) {
  const cfg = STATUS_CONFIG[rem.status] || STATUS_CONFIG.PENDING
  const Icon = cfg.icon

  return (
    <div
      className="nyx-card p-4 cursor-pointer hover:border-nyx-amethyst/40 transition-colors"
      onClick={() => onSelect(rem)}
    >
      <div className="flex items-center justify-between mb-2">
        <span className={clsx('flex items-center gap-1.5 text-xs font-medium', cfg.color)}>
          <Icon size={12} className={rem.status === 'GENERATING' ? 'animate-spin' : ''} />
          {cfg.label}
        </span>
        <span className="text-nyx-mist text-xs">{formatDistanceToNow(new Date(rem.created_at))} ago</span>
      </div>
      {rem.ai_fix_summary && (
        <p className="text-nyx-moonbeam text-sm font-medium mb-1">{rem.ai_fix_summary}</p>
      )}
      {rem.ai_confidence !== undefined && rem.ai_confidence !== null && (
        <p className="text-nyx-mist text-xs">AI Confidence: {(rem.ai_confidence * 100).toFixed(0)}%</p>
      )}
      {rem.pr_url && (
        <a href={rem.pr_url} target="_blank" rel="noopener noreferrer"
          className="text-nyx-stardust text-xs flex items-center gap-1 mt-2 hover:text-nyx-amethyst"
          onClick={e => e.stopPropagation()}>
          <GitPullRequest size={11} /> View PR <ExternalLink size={10} />
        </a>
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

  const approve = useMutation({
    mutationFn: () => remediationApi.approve(rem.id, notes),
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
            <h3 className="text-nyx-moonbeam font-semibold mb-2 text-sm">Explanation</h3>
            <p className="text-nyx-mist text-sm leading-relaxed whitespace-pre-wrap">{rem.ai_explanation}</p>
          </div>
        )}

        {/* Diff */}
        {rem.ai_fix_diff && (
          <div className="nyx-card overflow-hidden">
            <div className="px-4 py-3 border-b border-nyx-iris/10 flex items-center justify-between">
              <h3 className="text-nyx-moonbeam font-semibold text-sm">Proposed Fix (Diff)</h3>
              {rem.ai_confidence !== undefined && rem.ai_confidence !== null && (
                <span className="text-nyx-mist text-xs">
                  Confidence: <span className="text-nyx-amethyst font-semibold">{(rem.ai_confidence * 100).toFixed(0)}%</span>
                </span>
              )}
            </div>
            <SyntaxHighlighter
              language="diff"
              style={vscDarkPlus}
              customStyle={{ margin: 0, borderRadius: 0, background: '#0d0d1a', fontSize: '12px', maxHeight: '400px', overflow: 'auto' }}
            >
              {rem.ai_fix_diff}
            </SyntaxHighlighter>
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
            <div className="flex gap-2">
              <button onClick={() => approve.mutate()} disabled={approve.isPending} className="nyx-btn-primary flex-1">
                <CheckCircle size={14} />
                {approve.isPending ? 'Creating PR...' : 'Approve & Create PR'}
              </button>
              <button onClick={() => reject.mutate()} disabled={reject.isPending} className="nyx-btn-danger flex-1">
                <XCircle size={14} />
                Reject
              </button>
            </div>
          </div>
        )}

        {/* Regenerate */}
        {['REVIEW', 'FAILED', 'REJECTED'].includes(rem.status) && (
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
            <p className="text-nyx-mist text-sm mb-1">Pull Request</p>
            <a href={rem.pr_url} target="_blank" rel="noopener noreferrer"
              className="text-nyx-stardust flex items-center gap-1 hover:text-nyx-amethyst text-sm">
              <GitPullRequest size={14} /> PR #{rem.pr_number} <ExternalLink size={12} />
            </a>
          </div>
        )}

        {rem.jira_issue_key && rem.jira_issue_url && (
          <div className="nyx-card p-4">
            <p className="text-nyx-mist text-sm mb-1">JIRA Ticket</p>
            <a href={rem.jira_issue_url} target="_blank" rel="noopener noreferrer"
              className="text-nyx-stardust flex items-center gap-1 hover:text-nyx-amethyst text-sm font-mono">
              <Ticket size={14} /> {rem.jira_issue_key} <ExternalLink size={12} />
            </a>
          </div>
        )}
      </div>
    </div>
  )
}

const COLUMNS = ['PENDING', 'GENERATING', 'REVIEW', 'PR_OPEN', 'MERGED', 'FAILED']

export default function RemediationPage() {
  const [selected, setSelected] = useState<Remediation | null>(null)

  const { data: remediations = [], isLoading } = useQuery({
    queryKey: ['remediations'],
    queryFn: remediationApi.list,
    refetchInterval: 5_000, // Poll for AI generation updates
  })

  const byStatus = COLUMNS.reduce((acc, col) => {
    acc[col] = remediations.filter(r => r.status === col)
    return acc
  }, {} as Record<string, Remediation[]>)

  if (isLoading) return <div className="text-nyx-mist p-8">Loading remediations...</div>

  return (
    <div className="space-y-4 relative">
      <div className="flex items-center justify-between">
        <p className="text-nyx-mist text-sm">{remediations.length} remediation requests</p>
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
                    <RemediationCard key={rem.id} rem={rem} onSelect={setSelected} />
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
          <div className="fixed inset-0 bg-black/40 z-40" onClick={() => setSelected(null)} />
          <RemediationPanel rem={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  )
}
