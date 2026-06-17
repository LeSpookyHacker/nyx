import { useState, type FormEvent } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { KeyRound, Eye, EyeOff } from 'lucide-react'
import { authApi } from '../api/auth'

export default function LoginPage() {
  const [value, setValue] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  // SEC-229: validate redirectTo is a same-origin relative path to prevent open-redirect
  // via protocol-relative URLs like "//evil.com" that react-router passes to the history API.
  const rawRedirect = (location.state as { from?: string } | null)?.from
  const redirectTo = rawRedirect && rawRedirect.startsWith('/') && !rawRedirect.startsWith('//')
    ? rawRedirect
    : '/'

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    const trimmed = value.trim()
    if (!trimmed) {
      setError('Enter your Nyx API key.')
      return
    }
    setSubmitting(true)
    try {
      await authApi.login(trimmed)
      navigate(redirectTo, { replace: true })
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status === 429) {
        setError('Too many failed attempts — try again in a few minutes.')
      } else if (status === 401) {
        setError('Invalid API key — check the value in your .env and try again.')
      } else {
        setError('Could not reach the Nyx backend. Is it running?')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-nyx-void p-4">
      <form onSubmit={onSubmit} className="nyx-card p-8 w-full max-w-md space-y-5">
        <div className="flex items-center gap-2">
          <KeyRound size={20} className="text-nyx-amethyst" />
          <h1 className="text-nyx-moonbeam text-xl font-bold">Sign in to Nyx</h1>
        </div>
        <p className="text-nyx-mist text-sm">
          Paste your Nyx API key. On a fresh install it's the <code className="text-nyx-amethyst">NYX_API_KEY</code> value
          that <code className="text-nyx-amethyst">setup.sh</code> printed — or any key you've minted from Settings → API Keys.
        </p>
        <div className="relative">
          <input
            type={show ? 'text' : 'password'}
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="nyx-..."
            autoFocus
            className="w-full bg-nyx-dusk border border-nyx-iris/20 rounded-lg px-3 py-2 text-sm text-nyx-moonbeam placeholder-nyx-mist/30 focus:outline-none focus:border-nyx-amethyst/60 pr-9"
          />
          <button
            type="button"
            onClick={() => setShow(s => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-nyx-mist hover:text-nyx-moonbeam"
            tabIndex={-1}
          >
            {show ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>
        {error && <p className="text-red-400 text-xs">{error}</p>}
        <button
          type="submit"
          disabled={submitting}
          className="nyx-btn-primary w-full py-2 text-sm disabled:opacity-60"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
