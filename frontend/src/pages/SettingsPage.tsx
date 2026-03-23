export default function SettingsPage() {
  return (
    <div className="max-w-2xl space-y-6">
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
