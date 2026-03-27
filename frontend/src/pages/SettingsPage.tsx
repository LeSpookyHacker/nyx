import { useState } from 'react'
import { KeyRound, Check, Eye, EyeOff, LogOut } from 'lucide-react'
import axios from 'axios'

function ApiKeyCard() {
  const [value, setValue] = useState('')
  const [saved, setSaved] = useState(false)
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')

  async function save() {
    setError('')
    if (value.trim()) {
      try {
        // POST key to backend — server sets an HTTP-only SameSite=Strict cookie (C1).
        // The key is never stored in localStorage or any JS-accessible storage.
        await axios.post('/auth/session', { api_key: value.trim() }, { withCredentials: true })
        setValue('')
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
      } catch {
        setError('Invalid API key — check the value and try again.')
      }
    }
  }

  async function logout() {
    await axios.post('/auth/logout', {}, { withCredentials: true })
    setValue('')
    setSaved(false)
  }

  return (
    <div className="nyx-card p-6">
      <div className="flex items-center gap-2 mb-1">
        <KeyRound size={15} className="text-nyx-amethyst" />
        <h2 className="text-nyx-moonbeam font-bold">Dashboard API Key</h2>
      </div>
      <p className="text-nyx-mist text-sm mb-4">
        Enter the <code className="text-nyx-amethyst">NYX_API_KEY</code> value from your <code className="text-nyx-amethyst">.env</code> file.
        The key is validated by the server and stored in an HTTP-only cookie — never in your browser's local storage.
      </p>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <input
            type={show ? 'text' : 'password'}
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && save()}
            placeholder="nyx-your-secret-key-here"
            className="w-full bg-nyx-dusk border border-nyx-iris/20 rounded-lg px-3 py-2 text-sm text-nyx-moonbeam placeholder-nyx-mist/30 focus:outline-none focus:border-nyx-amethyst/60 pr-9"
          />
          <button
            type="button"
            onClick={() => setShow(s => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-nyx-mist hover:text-nyx-moonbeam"
          >
            {show ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>
        <button
          onClick={save}
          className="nyx-btn-primary px-4 py-2 text-sm flex items-center gap-1.5 shrink-0"
        >
          {saved ? <><Check size={14} /> Saved</> : 'Save'}
        </button>
        <button
          onClick={logout}
          title="Clear session"
          className="px-3 py-2 text-sm text-nyx-mist hover:text-nyx-moonbeam border border-nyx-iris/20 rounded-lg"
        >
          <LogOut size={14} />
        </button>
      </div>
      {error && <p className="text-red-400 text-xs mt-2">{error}</p>}
    </div>
  )
}

export default function SettingsPage() {
  return (
    <div className="max-w-2xl space-y-6">
      <ApiKeyCard />
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
            { key: 'NYX_API_KEY', desc: 'Master API key for the dashboard and CI/CD integration. Leave blank to disable auth (dev mode).', required: false },
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
    curl -X POST $NYX_URL/api/v1/scans/import \\
      -H "X-API-Key: $NYX_API_KEY" \\
      -F "repository_id=$REPO_ID" \\
      -F "scanner=SEMGREP" \\
      -F "git_ref=$GITHUB_REF_NAME" \\
      -F "file=@semgrep-results.json"
  env:
    NYX_URL: \${{ secrets.NYX_URL }}
    NYX_API_KEY: \${{ secrets.NYX_API_KEY }}
    REPO_ID: \${{ secrets.NYX_REPO_ID }}`}
        </pre>
      </div>
    </div>
  )
}
