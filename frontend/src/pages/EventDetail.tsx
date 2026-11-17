import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { fetchEvent, setAlertStatus, setEventStatus } from '../api/hooks'
import type { AlertStatus, EventStatus } from '../api/types'
import { ErrorNotice, Loading, SeverityTag } from '../components/ui'
import { CATEGORY_LABEL, STATUS_LABEL, formatCount, formatTime } from '../lib/format'

export default function EventDetail() {
  const id = Number(useParams().id)
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['event', id], queryFn: () => fetchEvent(id), enabled: Number.isInteger(id) && id > 0, refetchInterval: 15_000 })
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['event', id] })
    void qc.invalidateQueries({ queryKey: ['events'] })
    void qc.invalidateQueries({ queryKey: ['overview'] })
  }
  const status = useMutation({ mutationFn: (s: EventStatus) => setEventStatus(id, s), onSuccess: refresh })
  const alert = useMutation({ mutationFn: (v: { id: number; s: AlertStatus }) => setAlertStatus(v.id, v.s), onSuccess: refresh })

  if (!Number.isInteger(id) || id <= 0) return <ErrorNotice error={null} />
  if (q.isPending) return <Loading what="event" />
  if (q.isError) return <><p><Link to="/events">Back to events</Link></p><ErrorNotice error={q.error} retry={() => void q.refetch()} /></>
  const e = q.data
  const r = e.rule_snapshot

  return (
    <>
      <p><Link to="/events">← All events</Link></p>
      <div className="page-head" style={{ marginTop: '0.75rem' }}>
        <h1>{CATEGORY_LABEL[e.category] ?? e.category} from <span className="data">{e.src_ip}</span></h1>
        <SeverityTag severity={e.severity} />
      </div>
      <p style={{ marginBottom: '1.5rem' }}>{e.description}</p>

      <div className="overview-grid">
        <div>
          <section>
            <h2 style={{ fontSize: 'var(--step-1)', marginBottom: '0.9rem' }}>Details</h2>
            <dl className="deflist">
              <dt>Source</dt><dd className="data">{e.src_ip}</dd>
              <dt>Target</dt><dd className="data">{e.dst_ip ? `${e.dst_ip}${e.dst_port != null ? ':' + e.dst_port : ''}` : '—'}</dd>
              <dt>Protocol</dt><dd>{e.protocol ? e.protocol.toUpperCase() : '—'}</dd>
              <dt>Hits</dt><dd>{formatCount(e.hit_count)}</dd>
              <dt>First detected</dt><dd>{formatTime(e.detected_at)}</dd>
              <dt>Last seen</dt><dd>{formatTime(e.last_seen_at)} {e.is_open ? <span className="tag warn">still active</span> : <span className="tag">ended</span>}</dd>
            </dl>
          </section>

          <section className="section">
            <h2>Alerts</h2>
            <ul className="ledger">
              {e.alerts.map((a) => (
                <li key={a.id} style={{ ['--c' as string]: `var(--sev-${a.severity})`, gridTemplateColumns: '4.2rem 1fr auto' }}>
                  <SeverityTag severity={a.severity} />
                  <span className="title">{a.title}<div className="soft">{formatTime(a.created_at)} · {STATUS_LABEL[a.status]}</div></span>
                  <span className="row">
                    {a.status !== 'acknowledged' && <button className="btn small" disabled={alert.isPending} onClick={() => alert.mutate({ id: a.id, s: 'acknowledged' })}>Acknowledge</button>}
                    {a.status !== 'dismissed' && <button className="btn small quiet" disabled={alert.isPending} onClick={() => alert.mutate({ id: a.id, s: 'dismissed' })}>Dismiss</button>}
                    {a.status !== 'new' && <button className="btn small quiet" disabled={alert.isPending} onClick={() => alert.mutate({ id: a.id, s: 'new' })}>Reopen</button>}
                  </span>
                </li>
              ))}
            </ul>
            {alert.isError && <ErrorNotice error={alert.error} />}
          </section>

          <section className="section">
            <h2>Evidence</h2>
            {Object.keys(e.evidence).length === 0 ? <p className="soft">The monitor recorded no extra evidence for this event.</p> : (
              <pre className="evidence data" tabIndex={0}>{JSON.stringify(e.evidence, null, 2)}</pre>
            )}
          </section>
        </div>

        <div>
          <section>
            <h2 style={{ fontSize: 'var(--step-1)', marginBottom: '0.9rem' }}>Investigation</h2>
            <div className="field">
              <label htmlFor="st">Status</label>
              <select id="st" className="input" value={e.status} disabled={status.isPending} onChange={(ev) => status.mutate(ev.target.value as EventStatus)}>
                {(['new', 'investigating', 'resolved', 'false_positive'] as const).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
              </select>
              <span className="hint">{e.status_updated_at ? `Changed ${formatTime(e.status_updated_at)}` : 'Not changed yet'}</span>
            </div>
            {status.isError && <ErrorNotice error={status.error} />}
          </section>

          <section className="section">
            <h2>Rule when this fired</h2>
            {r ? (
              <>
                <p className="soft" style={{ marginBottom: '0.75rem' }}>{r.name}, version {r.version}. Later changes to the rule do not alter this record.</p>
                <dl className="deflist">
                  <dt>Threshold</dt><dd>{formatCount(r.threshold)}</dd>
                  <dt>Window</dt><dd>{r.window_seconds} s</dd>
                  <dt>Cooldown</dt><dd>{r.cooldown_seconds} s</dd>
                  <dt>Severity</dt><dd><SeverityTag severity={r.severity} /></dd>
                </dl>
              </>
            ) : <p className="soft">The rule version for this event is no longer available.</p>}
          </section>
        </div>
      </div>
    </>
  )
}
