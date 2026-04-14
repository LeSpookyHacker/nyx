import { useEffect, useState, type FormEvent } from 'react'
import { KeyRound, Plus, Trash2, RefreshCw, Copy, CheckCircle2, XCircle, AlertTriangle, LogOut } from 'lucide-react'
import { authApi } from '../api/auth'
import { apiKeysApi, type ApiKeyRecord, type ApiKeyCreated } from '../api/apiKeys'
import client from '../api/client'

type HealthStatus = 'ok' | 'error' | 'not_configured'
type IntegrationsHealth = Record<string, { status: HealthStatus; detail?: string }>

function HealthCard() {
  const [data, setData] = useState<IntegrationsHealth | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function refresh() {
    setLoading(true)
    setError('')
    try {
      // /health/integrations lives outside /api/v1
      const { data } = await client.get('/health/integrations', { baseURL: '' })
      setData(data as IntegrationsHealth)
    } catch {
      setError('Failed to reach the backend health endpoint.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 30_000)
    return () => clearInterval(id)
  }, [])

  const iconFor = (status: HealthStatus) =>
    status === 'ok' ? (
      <CheckCircle2 size={14} className="text-green-400" />
    ) : status === 'error' ? (
      <XCircle size={14} className="text-red-400" />
    ) : (
      <AlertTriangle size={14} className="text-nyx-mist/60" />
    )

  return (
    <div className="nyx-card p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-nyx-moonbeam font-bold">Integration Health</h2>
        <button
          onClick={refresh}
          className="text-nyx-mist hover:text-nyx-moonbeam text-xs flex items-center gap-1"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>
      {error && <p className="text-red-400 text-xs mb-3">{error}</p>}
      {data && (
        <div className="space-y-2">
          {Object.entries(data).map(([name, info]) => (
            <div
              key={name}
              className="flex items-center justify-between p-3 bg-nyx-dusk rounded-lg border border-nyx-iris/10"
            >
              <div className="flex items-center gap-2">
                {iconFor(info.status)}
                <span className="text-nyx-moonbeam text-sm capitalize">{name}</span>
              </div>
              <span className="text-nyx-mist text-xs">
                {info.status === 'ok'
                  ? 'Connected'
                  : info.status === 'not_configured'
                  ? 'Not configured'
                  : info.detail || 'Error'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ApiKeysCard() {
  const [keys, setKeys] = useState<ApiKeyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState('readonly')
  const [expires, setExpires] = useState<number | ''>('')
  const [created, setCreated] = useState<ApiKeyCreated | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  async function load() {
    setLoading(true)
    try {
      setKeys(await apiKeysApi.list())
    } catch {
      setError('Could not load API keys. You may need admin scope.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (!name.trim()) {
      setError('Name is required.')
      return
    }
    try {
      const result = await apiKeysApi.create(
        name.trim(),
        scopes,
        expires === '' ? undefined : Number(expires),
      )
      setCreated(result)
      setName('')
      setExpires('')
      setScopes('readonly')
      await load()
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status
      setError(status === 403 ? 'Only admin-scoped keys can create new keys.' : 'Failed to create key.')
    }
  }

  async function onRevoke(id: string, name: string) {
    if (!confirm(`Revoke API key "${name}"? This cannot be undone.`)) return
    try {
      await apiKeysApi.revoke(id)
      await load()
    } catch {
      setError('Failed to revoke key.')
    }
  }

  async function copyKey() {
    if (!created) return
    await navigator.clipboard.writeText(created.key)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="nyx-card p-6">
      <div className="flex items-center gap-2 mb-1">
        <KeyRound size={15} className="text-nyx-amethyst" />
        <h2 className="text-nyx-moonbeam font-bold">API Keys</h2>
      </div>
      <p className="text-nyx-mist text-sm mb-4">
        Scoped keys for CI pipelines, dashboards, or team members. The plaintext is shown once — store it immediately.
      </p>

      {created && (
        <div className="mb-4 p-4 rounded-lg border border-nyx-amethyst/40 bg-nyx-amethyst/10">
          <p className="text-nyx-moonbeam text-sm font-bold mb-2">
            New key: {created.name}
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs text-nyx-moonbeam bg-nyx-void p-2 rounded break-all">
              {created.key}
            </code>
            <button
              onClick={copyKey}
              className="nyx-btn-primary px-3 py-2 text-xs flex items-center gap-1"
            >
              {copied ? <CheckCircle2 size={12} /> : <Copy size={12} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="text-nyx-mist text-xs mt-2">{created.warning}</p>
          <button
            onClick={() => setCreated(null)}
            className="text-nyx-mist text-xs underline mt-2"
          >
            Dismiss
          </button>
        </div>
      )}

      <form onSubmit={onCreate} className="flex flex-wrap items-end gap-2 mb-4 p-3 bg-nyx-dusk/40 rounded-lg border border-nyx-iris/10">
        <div className="flex-1 min-w-[160px]">
          <label className="text-nyx-mist text-xs block mb-1">Name</label>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g. ci-semgrep"
            className="w-full bg-nyx-dusk border border-nyx-iris/20 rounded px-2 py-1.5 text-sm text-nyx-moonbeam"
          />
        </div>
        <div>
          <label className="text-nyx-mist text-xs block mb-1">Scope</label>
          <select
            value={scopes}
            onChange={e => setScopes(e.target.value)}
            className="bg-nyx-dusk border border-nyx-iris/20 rounded px-2 py-1.5 text-sm text-nyx-moonbeam"
          >
            <option value="scanner">scanner</option>
            <option value="readonly">readonly</option>
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
        </div>
        <div>
          <label className="text-nyx-mist text-xs block mb-1">Expires (days)</label>
          <input
            type="number"
            min={1}
            max={730}
            value={expires}
            onChange={e => setExpires(e.target.value === '' ? '' : Number(e.target.value))}
            placeholder="never"
            className="w-24 bg-nyx-dusk border border-nyx-iris/20 rounded px-2 py-1.5 text-sm text-nyx-moonbeam"
          />
        </div>
        <button
          type="submit"
          className="nyx-btn-primary px-3 py-1.5 text-sm flex items-center gap-1"
        >
          <Plus size={12} /> Create
        </button>
      </form>

      {error && <p className="text-red-400 text-xs mb-3">{error}</p>}

      {loading ? (
        <p className="text-nyx-mist text-sm">Loading…</p>
      ) : keys.length === 0 ? (
        <p className="text-nyx-mist text-sm">No API keys yet.</p>
      ) : (
        <div className="space-y-2">
          {keys.map(k => (
            <div
              key={k.id}
              className="flex items-center justify-between p-3 bg-nyx-dusk rounded-lg border border-nyx-iris/10"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-nyx-moonbeam text-sm font-bold truncate">{k.name}</span>
                  <span className="nyx-badge bg-nyx-amethyst/20 text-nyx-amethyst text-[10px]">
                    {k.scopes}
                  </span>
                  {!k.is_active && (
                    <span className="nyx-badge bg-red-900/30 text-red-400 text-[10px]">revoked</span>
                  )}
                </div>
                <p className="text-nyx-mist text-xs">
                  {k.last_used_at ? `Last used ${new Date(k.last_used_at).toLocaleString()}` : 'Never used'}
                  {k.expires_at ? ` · expires ${new Date(k.expires_at).toLocaleDateString()}` : ''}
                </p>
              </div>
              {k.is_active && (
                <button
                  onClick={() => onRevoke(k.id, k.name)}
                  className="text-red-400 hover:text-red-300 p-2"
                  title="Revoke"
                >
                  <Trash2 size={14} />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function SessionCard() {
  async function onLogout() {
    await authApi.logout()
    window.location.href = '/login'
  }
  return (
    <div className="nyx-card p-6 flex items-center justify-between">
      <div>
        <h2 className="text-nyx-moonbeam font-bold">Session</h2>
        <p className="text-nyx-mist text-sm">Sign out of this browser. Your API key remains valid.</p>
      </div>
      <button
        onClick={onLogout}
        className="flex items-center gap-1.5 text-sm text-nyx-mist hover:text-nyx-moonbeam border border-nyx-iris/20 rounded-lg px-3 py-2"
      >
        <LogOut size={14} /> Sign out
      </button>
    </div>
  )
}

/** Application settings: session, API keys, integration health, and reference data. */
export default function SettingsPage() {
  return (
    <div className="max-w-2xl space-y-6">
      <SessionCard />
      <ApiKeysCard />
      <HealthCard />

      <div className="nyx-card p-6">
        <h2 className="text-nyx-moonbeam font-bold mb-1">Configuration</h2>
        <p className="text-nyx-mist text-sm mb-5">
          Nyx is configured via environment variables. Edit your <code className="text-nyx-amethyst">.env</code> file and restart the backend.
        </p>

        <div className="space-y-4">
          {[
            { key: 'GITHUB_TOKEN', desc: 'GitHub Personal Access Token with repo and admin:repo_hook scopes.', required: true },
            { key: 'GITHUB_WEBHOOK_ENDPOINT', desc: 'Public URL of your Nyx backend, e.g. https://nyx.example.com/api/v1/webhooks/github', required: true },
            { key: 'ANTHROPIC_API_KEY', desc: 'Your Anthropic API key for AI-powered fix generation.', required: true },
            { key: 'NYX_API_KEY', desc: 'Bootstrap API key used to sign in on a fresh install. Create additional keys from the API Keys panel above.', required: true },
            { key: 'DATABASE_URL', desc: 'SQLite (default) or PostgreSQL connection string.', required: false },
            { key: 'ANTHROPIC_MODEL', desc: 'Claude model to use for fix generation. Default: claude-sonnet-4-6', required: false },
            { key: 'DEFAULT_ENABLED_SCANNERS', desc: 'Comma-separated scanners enabled by default for new repos.', required: false },
            { key: 'NOTIFICATION_WEBHOOK_URL', desc: 'Slack-compatible webhook URL for critical finding alerts.', required: false },
          ].map(({ key, desc, required }) => (
            <div key={key} className="p-4 bg-nyx-dusk rounded-lg border border-nyx-iris/10">
              <div className="flex items-center gap-2 mb-1">
                <code className="text-nyx-amethyst text-sm font-mono">{key}</code>
                {required && <span className="nyx-badge bg-red-900/30 text-red-400 border border-red-800/30 text-[10px]">Required</span>}
              </div>
              <p className="text-nyx-mist text-xs">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="nyx-card p-6">
        <h2 className="text-nyx-moonbeam font-bold mb-1">SLA Targets</h2>
        <p className="text-nyx-mist text-sm mb-4">
          Configure via environment variables. Nyx will highlight findings approaching or breaching their SLA.
        </p>
        <div className="grid grid-cols-2 gap-3">
          {[
            { key: 'SLA_CRITICAL_DAYS', default: '7', label: 'Critical' },
            { key: 'SLA_HIGH_DAYS', default: '30', label: 'High' },
            { key: 'SLA_MEDIUM_DAYS', default: '90', label: 'Medium' },
            { key: 'SLA_LOW_DAYS', default: '180', label: 'Low' },
          ].map(({ key, default: def, label }) => (
            <div key={key} className="p-3 bg-nyx-dusk rounded-lg border border-nyx-iris/10 flex items-center justify-between">
              <span className="text-nyx-mist text-sm">{label}</span>
              <div className="text-right">
                <code className="text-nyx-amethyst text-xs">{key}</code>
                <p className="text-nyx-mist/50 text-xs">default: {def} days</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="nyx-card p-6">
        <h2 className="text-nyx-moonbeam font-bold mb-1">CI/CD Integration</h2>
        <p className="text-nyx-mist text-sm mb-4">
          Add this step to your GitHub Actions workflow to automatically import scan results into Nyx:
        </p>
        <pre className="bg-nyx-dusk rounded-lg p-4 text-xs font-mono text-nyx-mist overflow-x-auto border border-nyx-iris/10">
{`- name: Upload to Nyx
  if: always()
  run: |
    jq -n \\
      --arg repo "$REPO_ID" \\
      --arg ref "$GITHUB_REF_NAME" \\
      --slurpfile data semgrep-results.json \\
      '{repository_id: $repo, scanner: "SEMGREP", git_ref: $ref, data: $data[0]}' | \\
    curl -sf -X POST $NYX_URL/api/v1/scans/import-json \\
      -H "Content-Type: application/json" \\
      -H "X-API-Key: $NYX_API_KEY" \\
      -d @-
  env:
    NYX_URL: \${{ secrets.NYX_URL }}
    NYX_API_KEY: \${{ secrets.NYX_API_KEY }}
    REPO_ID: \${{ secrets.NYX_REPO_ID }}`}
        </pre>
      </div>
    </div>
  )
}
