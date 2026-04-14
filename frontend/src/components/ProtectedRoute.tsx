import { useEffect, useState, type ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { authApi } from '../api/auth'

type State = 'checking' | 'authenticated' | 'unauthenticated'

export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>('checking')
  const location = useLocation()

  useEffect(() => {
    let cancelled = false
    authApi
      .whoami()
      .then(() => {
        if (!cancelled) setState('authenticated')
      })
      .catch(() => {
        if (!cancelled) setState('unauthenticated')
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (state === 'checking') {
    return (
      <div className="flex items-center justify-center min-h-screen text-nyx-mist text-sm">
        Checking session…
      </div>
    )
  }

  if (state === 'unauthenticated') {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }

  return <>{children}</>
}
