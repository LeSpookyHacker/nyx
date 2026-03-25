import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsApi } from '../api/findings'
import { remediationApi } from '../api/remediation'
import { jiraApi } from '../api/jira'
import { repositoriesApi } from '../api/repositories'
import SeverityBadge from '../components/findings/SeverityBadge'
import ScannerBadge from '../components/findings/ScannerBadge'
import StatusBadge from '../components/findings/StatusBadge'
import { formatDistanceToNow, format } from 'date-fns'
import { ArrowLeft, CheckCircle, ExternalLink, FileCode, Globe, Wand2, AlertTriangle, ShieldAlert, Ticket, RefreshCw, Unlink, UserCheck, RotateCcw, GitBranch, ClipboardCopy, Check, X } from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'

const JIRA_STATUS_COLORS: Record<string, string> = {
  'To Do': 'bg-nyx-eclipse text-nyx-mist',
  'In Progress': 'bg-blue-900/30 text-blue-400',
  'In Review': 'bg-purple-900/30 text-purple-400',
  'Done': 'bg-green-900/30 text-green-400',
  'Closed': 'bg-green-900/30 text-green-400',
  'Resolved': 'bg-green-900/30 text-green-400',
}

function JiraPanel({ findingId }: { findingId: string }) {
  const queryClient = useQueryClient()

  const { data: ticket, isLoading, error } = useQuery({
    queryKey: ['jira-ticket', findingId],
    queryFn: () => jiraApi.getTicket(findingId),
    retry: false,
  })

  const create = useMutation({
    mutationFn: () => jiraApi.createTicket(findingId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['jira-ticket', findingId] }),
  })

  const sync = useMutation({
    mutationFn: () => jiraApi.syncTicket(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jira-ticket', findingId] })
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
    },
  })

  const unlink = useMutation({
    mutationFn: () => jiraApi.unlinkTicket(findingId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['jira-ticket', findingId] }),
  })

  const noTicket = !isLoading && (error || !ticket)
  const statusColor = ticket?.jira_status
    ? (JIRA_STATUS_COLORS[ticket.jira_status] ?? 'bg-nyx-eclipse text-nyx-mist')
    : ''

  return (
    <div className="nyx-card p-5">
      <h3 className="text-nyx-moonbeam font-semibold mb-3 flex items-center gap-2">
        <Ticket size={14} className="text-nyx-amethyst" />
        JIRA
      </h3>

      {isLoading && <p className="text-nyx-mist text-xs animate-pulse">Loading...</p>}

      {noTicket && (
        <div className="space-y-2">
          <p className="text-nyx-mist text-xs">No ticket linked.</p>
          <button
            onClick={() => create.mutate()}
            disabled={create.isPending}
            className="nyx-btn-primary w-full text-xs"
          >
            <Ticket size={12} />
            {create.isPending ? 'Creating...' : 'Create JIRA Ticket'}
          </button>
          {create.isError && (
            <p className="text-red-400 text-xs">{String((create.error as Error)?.message)}</p>
          )}
        </div>
      )}

      {ticket && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <a
              href={ticket.jira_issue_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-nyx-stardust font-mono text-sm font-bold hover:underline flex items-center gap-1"
            >
              {ticket.jira_issue_key} <ExternalLink size={11} />
            </a>
            {ticket.jira_status && (
              <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${statusColor}`}>
                {ticket.jira_status}
              </span>
            )}
          </div>

          <dl className="space-y-1.5 text-xs">
            {ticket.jira_priority && (
              <div className="flex justify-between">
                <dt className="text-nyx-mist">Priority</dt>
                <dd className="text-nyx-moonbeam">{ticket.jira_priority}</dd>
              </div>
            )}
            {ticket.jira_assignee && (
              <div className="flex justify-between">
                <dt className="text-nyx-mist">Assignee</dt>
                <dd className="text-nyx-moonbeam truncate max-w-[120px]">{ticket.jira_assignee}</dd>
              </div>
            )}
            {ticket.synced_at && (
              <div className="flex justify-between">
                <dt className="text-nyx-mist">Synced</dt>
                <dd className="text-nyx-mist">{formatDistanceToNow(new Date(ticket.synced_at))} ago</dd>
              </div>
            )}
          </dl>

          <div className="flex gap-2 pt-1">
            <button
              onClick={() => sync.mutate()}
              disabled={sync.isPending}
              className="nyx-btn-ghost flex-1 text-xs"
            >
              <RefreshCw size={11} className={sync.isPending ? 'animate-spin' : ''} />
              Sync
            </button>
            <button
              onClick={() => unlink.mutate()}
              disabled={unlink.isPending}
              className="nyx-btn-ghost text-xs text-red-400 hover:text-red-300"
              title="Remove link (does not delete the JIRA ticket)"
            >
              <Unlink size={11} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [suppressReason, setSuppressReason] = useState('')
  const [notes, setNotes] = useState('')
  const [showSuppressForm, setShowSuppressForm] = useState(false)
  const [assignee, setAssignee] = useState('')
  const [claudePrompt, setClaudePrompt] = useState<string | null>(null)
  const [promptCopied, setPromptCopied] = useState(false)

  const { data: finding, isLoading } = useQuery({
    queryKey: ['finding', id],
    queryFn: () => findingsApi.get(id!),
    enabled: !!id,
  })

  const { data: repository } = useQuery({
    queryKey: ['repository', finding?.repository_id],
    queryFn: () => repositoriesApi.get(finding!.repository_id),
    enabled: !!finding?.repository_id,
  })

  const requestFix = useMutation({
    mutationFn: () => remediationApi.request(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
      navigate('/remediation')
    },
  })

  const suppress = useMutation({
    mutationFn: () => findingsApi.suppress(id!, suppressReason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
      setShowSuppressForm(false)
    },
  })

  const updateNotes = useMutation({
    mutationFn: () => findingsApi.updateNotes(id!, notes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['finding', id] }),
  })

  const acceptRisk = useMutation({
    mutationFn: () => findingsApi.updateStatus(id!, 'ACCEPTED_RISK'),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['finding', id] }),
  })

  const markFixed = useMutation({
    mutationFn: () => findingsApi.updateStatus(id!, 'FIXED'),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['finding', id] }),
  })

  const assign = useMutation({
    mutationFn: (to: string) => findingsApi.assign(id!, to),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
      setAssignee('')
    },
  })

  const generatePrompt = useMutation({
    mutationFn: () => findingsApi.generateClaudePrompt([id!]),
    onSuccess: (data) => setClaudePrompt(data.prompt),
  })

  const { data: suppressionSuggestion } = useQuery({
    queryKey: ['suppression-suggestion', id],
    queryFn: () => findingsApi.getSuppressionSuggestion(id!),
    enabled: !!id && finding?.status === 'OPEN',
    retry: false,
  })

  if (isLoading) return <div className="text-nyx-mist p-8">Loading finding...</div>
  if (!finding) return <div className="text-nyx-mist p-8">Finding not found.</div>

  let cweList: string[] = []
  try { cweList = JSON.parse(finding.cwe_ids || '[]') } catch {}

  const lang = finding.file_path?.split('.').pop() || 'text'
  const langMap: Record<string, string> = { py: 'python', js: 'javascript', ts: 'typescript', go: 'go', java: 'java', rb: 'ruby', rs: 'rust', php: 'php' }

  return (
    <div className="max-w-6xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={() => navigate(-1)} className="nyx-btn-ghost p-2">
          <ArrowLeft size={16} />
        </button>
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity} />
          <ScannerBadge scanner={finding.scanner} />
          <StatusBadge status={finding.status} />
          {finding.is_regression && (
            <span className="flex items-center gap-1 nyx-badge bg-orange-900/30 text-orange-400 border border-orange-500/30">
              <RotateCcw size={11} /> REGRESSION
            </span>
          )}
        </div>
        <div className="ml-auto flex gap-2 flex-wrap">
          <button
            onClick={() => generatePrompt.mutate()}
            disabled={generatePrompt.isPending}
            className="nyx-btn-ghost text-sm"
            title="Generate a Claude Code remediation prompt for this finding"
          >
            <ClipboardCopy size={14} />
            {generatePrompt.isPending ? 'Generating...' : 'Claude Prompt'}
          </button>
          {(finding.status === 'OPEN' || finding.status === 'IN_REMEDIATION') && (
            <>
              <button
                onClick={() => setShowSuppressForm(!showSuppressForm)}
                className="nyx-btn-ghost text-sm"
              >
                Suppress
              </button>
              <button
                onClick={() => acceptRisk.mutate()}
                disabled={acceptRisk.isPending}
                className="nyx-btn-ghost gap-1.5 text-sm text-yellow-400 hover:text-yellow-300 border border-yellow-700/40 hover:bg-yellow-900/20"
              >
                <ShieldAlert size={14} />
                {acceptRisk.isPending ? 'Saving...' : 'Accept Risk'}
              </button>
              <button
                onClick={() => markFixed.mutate()}
                disabled={markFixed.isPending}
                className="nyx-btn-ghost gap-1.5 text-sm text-green-400 hover:text-green-300 border border-green-700/40 hover:bg-green-900/20"
              >
                <CheckCircle size={14} />
                {markFixed.isPending ? 'Saving...' : 'Mark Fixed'}
              </button>
              <button
                onClick={() => requestFix.mutate()}
                disabled={requestFix.isPending}
                className="nyx-btn-primary"
              >
                <Wand2 size={14} />
                {requestFix.isPending ? 'Requesting...' : 'Request AI Fix'}
              </button>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-4">
          {/* Title & Description */}
          <div className="nyx-card p-5">
            <h1 className="text-nyx-moonbeam text-xl font-bold mb-2">{finding.title}</h1>
            <p className="text-nyx-mist text-sm leading-relaxed">{finding.description}</p>
            {finding.owasp_category && (
              <span className="mt-2 inline-block nyx-badge bg-indigo-900/30 text-indigo-400 border border-indigo-800/30">
                {finding.owasp_category}
              </span>
            )}
          </div>

          {/* Code Snippet */}
          {finding.code_snippet && (
            <div className="nyx-card overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-nyx-iris/10">
                <FileCode size={14} className="text-nyx-amethyst" />
                <span className="text-nyx-moonbeam text-sm font-medium">Vulnerable Code</span>
                {finding.file_path && (
                  <span className="ml-auto text-nyx-mist text-xs font-mono">
                    {finding.file_path}:{finding.line_start}
                  </span>
                )}
              </div>
              <SyntaxHighlighter
                language={langMap[lang] || 'text'}
                style={vscDarkPlus}
                customStyle={{ margin: 0, borderRadius: 0, background: '#0d0d1a', fontSize: '12px' }}
                showLineNumbers
                startingLineNumber={finding.line_start || 1}
                wrapLongLines
              >
                {finding.code_snippet}
              </SyntaxHighlighter>
            </div>
          )}

          {/* URL (DAST) */}
          {finding.url && (
            <div className="nyx-card p-4">
              <div className="flex items-center gap-2">
                <Globe size={14} className="text-nyx-amethyst" />
                <span className="text-nyx-mist text-sm">Vulnerable URL</span>
              </div>
              <a href={finding.url} target="_blank" rel="noopener noreferrer"
                className="text-nyx-stardust text-sm break-all flex items-center gap-1 mt-1 hover:text-nyx-amethyst">
                {finding.url} <ExternalLink size={12} />
              </a>
            </div>
          )}

          {/* Remediation Guidance */}
          {finding.remediation_guidance && (
            <div className="nyx-card p-5">
              <h3 className="text-nyx-moonbeam font-semibold mb-2 flex items-center gap-2">
                <AlertTriangle size={14} className="text-nyx-amethyst" />
                Remediation Guidance
              </h3>
              <p className="text-nyx-mist text-sm leading-relaxed">{finding.remediation_guidance}</p>
            </div>
          )}

          {/* Notes */}
          <div className="nyx-card p-5">
            <h3 className="text-nyx-moonbeam font-semibold mb-3">Engineer Notes</h3>
            <textarea
              className="nyx-input w-full h-24 resize-none"
              placeholder="Add notes about this finding..."
              defaultValue={finding.notes || ''}
              onChange={e => setNotes(e.target.value)}
            />
            <button onClick={() => updateNotes.mutate()} className="nyx-btn-primary mt-2">
              Save Notes
            </button>
          </div>

          {/* Suppress Form */}
          {showSuppressForm && (
            <div className="nyx-card p-5 border border-yellow-800/30">
              <h3 className="text-yellow-400 font-semibold mb-3">Suppress Finding</h3>
              <textarea
                className="nyx-input w-full h-20 resize-none"
                placeholder="Reason for suppression (required)..."
                value={suppressReason}
                onChange={e => setSuppressReason(e.target.value)}
              />
              <div className="flex gap-2 mt-2">
                <button onClick={() => suppress.mutate()} disabled={!suppressReason || suppress.isPending} className="nyx-btn-primary">
                  Confirm Suppress
                </button>
                <button onClick={() => setShowSuppressForm(false)} className="nyx-btn-ghost">Cancel</button>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Metadata */}
          <div className="nyx-card p-5">
            <h3 className="text-nyx-moonbeam font-semibold mb-4">Details</h3>
            <dl className="space-y-2.5 text-sm">
              {[
                repository ? {
                  label: 'Repository',
                  value: (
                    <button
                      onClick={() => navigate(`/repositories/${repository.id}`)}
                      className="text-nyx-stardust hover:text-nyx-amethyst flex items-center gap-1 text-xs font-mono"
                    >
                      <GitBranch size={11} />
                      {repository.github_full_name}
                    </button>
                  )
                } : null,
                { label: 'Rule ID', value: <code className="text-nyx-amethyst text-xs">{finding.rule_id}</code> },
                { label: 'Category', value: finding.category },
                { label: 'Priority Score', value: <span className="text-nyx-amethyst font-bold">{finding.priority_score.toFixed(1)}</span> },
                finding.cvss_score ? { label: 'CVSS Score', value: finding.cvss_score.toFixed(1) } : null,
                finding.epss_score ? { label: 'EPSS Score', value: `${(finding.epss_score * 100).toFixed(1)}%` } : null,
                finding.cve_id ? { label: 'CVE', value: <a href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`} target="_blank" rel="noopener noreferrer" className="text-nyx-stardust hover:underline flex items-center gap-1">{finding.cve_id} <ExternalLink size={10} /></a> } : null,
                { label: 'First Seen', value: format(new Date(finding.first_seen_at), 'MMM d, yyyy') },
                { label: 'Last Seen', value: formatDistanceToNow(new Date(finding.last_seen_at)) + ' ago' },
                finding.sla_breach_at ? { label: 'SLA Breach', value: <span className="text-orange-400">{format(new Date(finding.sla_breach_at), 'MMM d, yyyy')}</span> } : null,
              ].filter(Boolean).map((row: any) => (
                <div key={row.label} className="flex justify-between gap-2">
                  <dt className="text-nyx-mist">{row.label}</dt>
                  <dd className="text-nyx-moonbeam text-right">{row.value}</dd>
                </div>
              ))}
            </dl>
          </div>

          {/* CWEs */}
          {cweList.length > 0 && (
            <div className="nyx-card p-5">
              <h3 className="text-nyx-moonbeam font-semibold mb-3">CWE References</h3>
              <div className="flex flex-wrap gap-2">
                {cweList.map((cwe: string) => (
                  <a
                    key={cwe}
                    href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="nyx-badge bg-nyx-eclipse text-nyx-lavender border border-nyx-iris/30 hover:bg-nyx-iris/20"
                  >
                    {cwe}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Assignment */}
          <div className="nyx-card p-5">
            <h3 className="text-nyx-moonbeam font-semibold mb-3 flex items-center gap-2">
              <UserCheck size={14} className="text-nyx-amethyst" />
              Assignment
            </h3>
            {finding.assigned_to ? (
              <p className="text-nyx-mist text-sm mb-2">
                Assigned to <span className="text-nyx-moonbeam font-medium">{finding.assigned_to}</span>
              </p>
            ) : (
              <p className="text-nyx-mist/50 text-xs mb-2">Unassigned</p>
            )}
            <div className="flex gap-2">
              <input
                className="nyx-input flex-1 text-xs"
                placeholder="Email or username"
                value={assignee}
                onChange={e => setAssignee(e.target.value)}
              />
              <button
                onClick={() => assign.mutate(assignee)}
                disabled={!assignee || assign.isPending}
                className="nyx-btn-primary text-xs px-3"
              >
                Assign
              </button>
            </div>
          </div>

          {/* Suppression suggestion */}
          {suppressionSuggestion?.has_pattern && (
            <div className="nyx-card p-5 border border-yellow-500/20">
              <h3 className="text-yellow-400 font-semibold mb-2 text-sm">Suppression Pattern Detected</h3>
              <p className="text-nyx-mist text-xs leading-relaxed">
                This rule (<code className="text-nyx-amethyst">{suppressionSuggestion.rule_id}</code>) has been
                suppressed {suppressionSuggestion.times_applied}× before.
                {suppressionSuggestion.similar_open > 0 && (
                  <span> There are {suppressionSuggestion.similar_open} similar open findings.</span>
                )}
              </p>
              {suppressionSuggestion.reason && (
                <p className="text-nyx-mist/60 text-xs mt-1 italic">"{suppressionSuggestion.reason}"</p>
              )}
            </div>
          )}

          {/* PR Link */}
          {finding.fix_pr_url && (
            <div className="nyx-card p-5">
              <h3 className="text-nyx-moonbeam font-semibold mb-3">Fix PR</h3>
              <a href={finding.fix_pr_url} target="_blank" rel="noopener noreferrer"
                className="text-nyx-stardust text-sm flex items-center gap-1 hover:text-nyx-amethyst">
                View Pull Request <ExternalLink size={12} />
              </a>
            </div>
          )}

          {/* JIRA */}
          <JiraPanel findingId={finding.id} />
        </div>
      </div>

      {/* Claude Code Prompt Modal */}
      {claudePrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="nyx-card w-full max-w-4xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-nyx-iris/20">
              <div>
                <h2 className="text-nyx-moonbeam font-semibold">Claude Code Remediation Prompt</h2>
                <p className="text-nyx-mist text-xs mt-0.5">
                  Copy this prompt and paste it into Claude Code on your machine.
                </p>
              </div>
              <button onClick={() => { setClaudePrompt(null); setPromptCopied(false) }}
                className="text-nyx-mist hover:text-nyx-moonbeam transition-colors ml-4">
                <X size={18} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              <pre className="text-xs text-nyx-mist/90 whitespace-pre-wrap font-mono leading-relaxed bg-nyx-eclipse/40 rounded-lg p-4 border border-nyx-iris/10">
                {claudePrompt}
              </pre>
            </div>
            <div className="flex items-center gap-3 px-5 py-4 border-t border-nyx-iris/20">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(claudePrompt)
                  setPromptCopied(true)
                  setTimeout(() => setPromptCopied(false), 2000)
                }}
                className={`nyx-btn-primary gap-2 flex-1 ${promptCopied ? 'bg-green-700 border-green-600' : ''}`}
              >
                {promptCopied ? <Check size={14} /> : <ClipboardCopy size={14} />}
                {promptCopied ? 'Copied!' : 'Copy to Clipboard'}
              </button>
              <button onClick={() => { setClaudePrompt(null); setPromptCopied(false) }} className="nyx-btn-ghost">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
