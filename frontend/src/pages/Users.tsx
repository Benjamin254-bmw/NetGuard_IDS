import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { createUser, fetchAudit, fetchUsers, patchUser, resetPassword, unlockUser } from '../api/hooks'
import type { User } from '../api/types'
import { useAuth } from '../auth/AuthProvider'
import { Modal } from '../components/Modal'
import { Empty, ErrorNotice, Loading } from '../components/ui'
import { formatTime } from '../lib/format'

type Dialog = { kind: 'create' } | { kind: 'reset'; user: User } | null

function CreateForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient()
  const [f, setF] = useState({ username: '', email: '', password: '', role: 'analyst' })
  const m = useMutation({
    mutationFn: () => createUser({ username: f.username.trim(), password: f.password, role: f.role, email: f.email.trim() || undefined }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['users'] }); onDone() },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); m.mutate() }
  return (
    <form className="stack" onSubmit={submit}>
      <div className="field"><label htmlFor="c-u">Username</label><input id="c-u" className="input" required autoComplete="off" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /><span className="hint">3 to 64 letters, numbers, dots, dashes or underscores.</span></div>
      <div className="field"><label htmlFor="c-e">Email (optional)</label><input id="c-e" className="input" type="email" autoComplete="off" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></div>
      <div className="field"><label htmlFor="c-p">Temporary password</label><input id="c-p" className="input" type="password" required autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /><span className="hint">At least 12 characters. Share it privately; they can change it in Settings.</span></div>
      <div className="field"><label htmlFor="c-r">Role</label><select id="c-r" className="input" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option value="analyst">Analyst: view, investigate, acknowledge</option><option value="admin">Administrator: also rules and users</option></select></div>
      {m.isError && <ErrorNotice error={m.error} />}
      <div className="row"><button className="btn primary" disabled={m.isPending}>Create user</button><button type="button" className="btn quiet" onClick={onDone}>Cancel</button></div>
    </form>
  )
}

function ResetForm({ user, onDone }: { user: User; onDone: () => void }) {
  const [pw, setPw] = useState('')
  const m = useMutation({ mutationFn: () => resetPassword(user.id, pw), onSuccess: onDone })
  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); m.mutate() }}>
      <p>Set a new password for <strong>{user.username}</strong>. Their current sessions end immediately.</p>
      <div className="field"><label htmlFor="rp">New password</label><input id="rp" className="input" type="password" required autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} /><span className="hint">At least 12 characters.</span></div>
      {m.isError && <ErrorNotice error={m.error} />}
      <div className="row"><button className="btn primary" disabled={m.isPending}>Reset password</button><button type="button" className="btn quiet" onClick={onDone}>Cancel</button></div>
    </form>
  )
}

function Accounts() {
  const { user: me } = useAuth()
  const qc = useQueryClient()
  const [dialog, setDialog] = useState<Dialog>(null)
  const q = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const done = () => void qc.invalidateQueries({ queryKey: ['users'] })
  const change = useMutation({ mutationFn: (v: { id: number; body: Record<string, unknown> }) => patchUser(v.id, v.body), onSuccess: done })
  const unlock = useMutation({ mutationFn: (id: number) => unlockUser(id), onSuccess: done })

  return (
    <>
      <div className="row" style={{ justifyContent: 'space-between', marginBottom: '1rem' }}>
        <p className="soft">People who can sign in to NetGuard.</p>
        <button className="btn primary" onClick={() => setDialog({ kind: 'create' })}>Add user</button>
      </div>
      {q.isPending && <Loading what="users" />}
      {q.isError && <ErrorNotice error={q.error} retry={() => void q.refetch()} />}
      {(change.isError || unlock.isError) && <ErrorNotice error={change.error ?? unlock.error} />}
      {q.data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {q.data.map((u) => (
                <tr key={u.id}>
                  <td><strong>{u.username}</strong>{u.id === me?.id && <span className="tag" style={{ marginLeft: '0.5rem' }}>you</span>}<div className="soft">{u.email ?? 'No email'}</div></td>
                  <td>
                    <label className="sr-only" htmlFor={`role-${u.id}`}>Role for {u.username}</label>
                    <select id={`role-${u.id}`} className="input" style={{ width: 'auto' }} value={u.role} disabled={change.isPending} onChange={(e) => change.mutate({ id: u.id, body: { role: e.target.value } })}>
                      <option value="analyst">Analyst</option><option value="admin">Administrator</option>
                    </select>
                  </td>
                  <td>{!u.is_active ? <span className="tag bad">Disabled</span> : u.locked ? <span className="tag warn">Locked</span> : <span className="tag good">Active</span>}</td>
                  <td>{formatTime(u.last_login_at)}</td>
                  <td>
                    <div className="row" style={{ justifyContent: 'flex-end' }}>
                      {u.locked && <button className="btn small" onClick={() => unlock.mutate(u.id)}>Unlock</button>}
                      <button className="btn small" onClick={() => setDialog({ kind: 'reset', user: u })}>Reset password</button>
                      <button className="btn small danger" disabled={change.isPending} onClick={() => change.mutate({ id: u.id, body: { is_active: !u.is_active } })}>{u.is_active ? 'Disable' : 'Enable'}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {dialog?.kind === 'create' && <Modal title="Add user" onClose={() => setDialog(null)}><CreateForm onDone={() => setDialog(null)} /></Modal>}
      {dialog?.kind === 'reset' && <Modal title="Reset password" onClose={() => setDialog(null)}><ResetForm user={dialog.user} onDone={() => setDialog(null)} /></Modal>}
    </>
  )
}

function Audit() {
  const q = useInfiniteQuery({
    queryKey: ['audit'],
    queryFn: ({ pageParam }) => fetchAudit(pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => last.next_before_id ?? undefined,
  })
  const rows = q.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <>
      <p className="soft" style={{ marginBottom: '1rem' }}>Every sign-in, account change, rule change and status change, newest first.</p>
      {q.isPending && <Loading what="audit log" />}
      {q.isError && <ErrorNotice error={q.error} retry={() => void q.refetch()} />}
      {q.data && rows.length === 0 && <div className="table-wrap"><Empty title="Nothing recorded yet" /></div>}
      {rows.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Action</th><th>By</th><th>Target</th><th>From address</th><th>Details</th></tr></thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id}>
                  <td>{formatTime(a.occurred_at)}</td>
                  <td className="data">{a.action}</td>
                  <td>{a.actor_user_id ? `User ${a.actor_user_id}` : a.actor_type}</td>
                  <td>{a.target_type ? `${a.target_type} ${a.target_id ?? ''}` : '—'}</td>
                  <td className="data">{a.source_ip ?? '—'}</td>
                  <td className="data soft" style={{ maxWidth: '28ch', overflowWrap: 'anywhere' }}>{Object.keys(a.details).length ? JSON.stringify(a.details) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.hasNextPage && <div className="pager"><span /><button className="btn small" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>Load older entries</button></div>}
    </>
  )
}

export default function Users() {
  const [tab, setTab] = useState<'accounts' | 'audit'>('accounts')
  return (
    <>
      <div className="page-head"><h1>Users</h1><p>Accounts and who did what.</p></div>
      <div className="tabs" role="tablist" aria-label="Users sections">
        <button role="tab" id="tab-accounts" aria-selected={tab === 'accounts'} aria-controls="panel" onClick={() => setTab('accounts')}>Accounts</button>
        <button role="tab" id="tab-audit" aria-selected={tab === 'audit'} aria-controls="panel" onClick={() => setTab('audit')}>Audit log</button>
      </div>
      <div id="panel" role="tabpanel" aria-labelledby={`tab-${tab}`}>{tab === 'accounts' ? <Accounts /> : <Audit />}</div>
    </>
  )
}
