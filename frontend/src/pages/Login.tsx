import { useState, type FormEvent } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/AuthProvider'

export default function Login() {
  const { state, signIn } = useAuth()
  const loc = useLocation() as { state?: { from?: string } }
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (state.status === 'authed') return <Navigate to={loc.state?.from ?? '/'} replace />

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await signIn(username.trim(), password)
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not sign in. Try again.')
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login">
      <form onSubmit={submit} className="stack" aria-describedby={error ? 'login-error' : undefined}>
        <div>
          <h1>Net<span style={{ color: 'var(--sea)' }}>Guard</span></h1>
          <p className="soft">Sign in to watch your network.</p>
        </div>
        <div className="field">
          <label htmlFor="u">Username</label>
          <input id="u" className="input" autoComplete="username" autoFocus required value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="p">Password</label>
          <input id="p" className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {error && <p id="login-error" className="form-error" role="alert">{error}</p>}
        <button className="btn primary" disabled={busy || !username || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </main>
  )
}
