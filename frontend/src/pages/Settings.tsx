import { useMutation, useQuery } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { changePassword, fetchSystemInfo, logoutAll } from '../api/hooks'
import { useAuth } from '../auth/AuthProvider'
import { ErrorNotice, Loading } from '../components/ui'

function Password() {
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const m = useMutation({ mutationFn: () => changePassword(cur, next), onSuccess: () => { setCur(''); setNext('') } })
  const submit = (e: FormEvent) => { e.preventDefault(); m.mutate() }
  return (
    <form className="stack" onSubmit={submit} style={{ maxWidth: '24rem' }}>
      <div className="field"><label htmlFor="cp">Current password</label><input id="cp" className="input" type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></div>
      <div className="field"><label htmlFor="np">New password</label><input id="np" className="input" type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} /><span className="hint">At least 12 characters, with a mix of characters. Not your username.</span></div>
      {m.isError && <ErrorNotice error={m.error} />}
      {m.isSuccess && <p className="form-ok" role="status">Password changed. Your other sessions have ended.</p>}
      <div><button className="btn primary" disabled={m.isPending}>Change password</button></div>
    </form>
  )
}

export default function Settings() {
  const { user, signOut } = useAuth()
  const info = useQuery({ queryKey: ['system-info'], queryFn: fetchSystemInfo })
  const everywhere = useMutation({ mutationFn: logoutAll, onSuccess: () => void signOut() })
  const i = info.data
  return (
    <>
      <div className="page-head"><h1>Settings</h1><p>How this NetGuard installation is set up. These values come from the server configuration and cannot be changed here.</p></div>

      <section>
        <h2 style={{ fontSize: 'var(--step-1)', marginBottom: '0.9rem' }}>Monitoring</h2>
        {info.isPending && <Loading what="settings" />}
        {info.isError && <ErrorNotice error={info.error} retry={() => void info.refetch()} />}
        {i && (
          <dl className="deflist">
            <dt>Network interface</dt><dd className="data">{i.monitored_interface ?? 'Not reported yet'}</dd>
            <dt>Authorised network</dt><dd className="data">{i.authorized_subnet ?? 'Not set in the API configuration'}</dd>
            <dt>Per-second data kept for</dt><dd>{i.retention_per_second_hours} hours</dd>
            <dt>Per-minute data kept for</dt><dd>{i.retention_per_minute_days} days</dd>
            <dt>Rule changes reach the monitor within</dt><dd>{i.rules_reload_seconds} seconds</dd>
            <dt>Monitor version</dt><dd>{i.monitor_version ?? 'Unknown (monitor has not reported)'}</dd>
            <dt>API version</dt><dd>{i.api_version} ({i.environment})</dd>
          </dl>
        )}
      </section>

      <section className="section">
        <h2>Sign-in security</h2>
        {i && (
          <dl className="deflist" style={{ marginBottom: '1.25rem' }}>
            <dt>Sessions end after</dt><dd>{i.session_ttl_minutes} minutes without activity</dd>
            <dt>Cookies sent only over HTTPS</dt><dd>{i.cookies_secure ? 'Yes' : 'No (acceptable only on localhost)'}</dd>
            <dt>Dashboard addresses allowed</dt><dd className="data">{i.allowed_origins.join(', ')}</dd>
          </dl>
        )}
      </section>

      <section className="section">
        <h2>Your account ({user?.username})</h2>
        <Password />
        <div style={{ marginTop: '1.25rem' }}>
          <button className="btn danger" disabled={everywhere.isPending} onClick={() => everywhere.mutate()}>Sign out on all devices</button>
          {everywhere.isError && <ErrorNotice error={everywhere.error} />}
        </div>
      </section>
    </>
  )
}
