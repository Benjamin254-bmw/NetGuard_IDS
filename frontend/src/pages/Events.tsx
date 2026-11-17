import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { fetchEvents, type EventFilters } from '../api/hooks'
import { Empty, ErrorNotice, Loading, SeverityTag } from '../components/ui'
import { CATEGORY_LABEL, SEVERITIES, STATUS_LABEL, formatCount, formatTime } from '../lib/format'

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
export const isIpv4 = (s: string) => {
  const m = IPV4.exec(s)
  return !!m && m.slice(1).every((p) => Number(p) <= 255)
}

export default function Events() {
  const [filters, setFilters] = useState<Omit<EventFilters, 'before_id'>>({ is_open: '' })
  const [ipText, setIpText] = useState('')
  const [stack, setStack] = useState<number[]>([]) // before_id of each older page we have moved through
  const before = stack.at(-1)

  const ipBad = ipText !== '' && !isIpv4(ipText)
  const q = useQuery({
    queryKey: ['events', filters, before],
    queryFn: () => fetchEvents({ ...filters, before_id: before }),
    refetchInterval: 15_000,
  })
  const set = (k: keyof typeof filters, v: string) => {
    setFilters((f) => ({ ...f, [k]: v }))
    setStack([])
  }

  return (
    <>
      <div className="page-head">
        <h1>Events</h1>
        <p>Detections raised by the monitor. Repeated activity from the same source is grouped into one event.</p>
      </div>

      <form className="filters" onSubmit={(e) => { e.preventDefault(); if (!ipBad) set('src_ip', ipText) }} aria-label="Filter events">
        <div className="field">
          <label htmlFor="f-sev">Severity</label>
          <select id="f-sev" className="input" value={filters.severity ?? ''} onChange={(e) => set('severity', e.target.value)}>
            <option value="">Any</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-cat">Type</label>
          <select id="f-cat" className="input" value={filters.category ?? ''} onChange={(e) => set('category', e.target.value)}>
            <option value="">Any</option>
            {Object.entries(CATEGORY_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-st">Status</label>
          <select id="f-st" className="input" value={filters.status ?? ''} onChange={(e) => set('status', e.target.value)}>
            <option value="">Any</option>
            {['new', 'investigating', 'resolved', 'false_positive'].map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-open">Activity</label>
          <select id="f-open" className="input" value={filters.is_open ?? ''} onChange={(e) => set('is_open', e.target.value)}>
            <option value="">All</option>
            <option value="true">Still active</option>
            <option value="false">Ended</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-ip">Source address</label>
          <input id="f-ip" className="input data" inputMode="decimal" placeholder="10.10.10.30" value={ipText} aria-invalid={ipBad} aria-describedby={ipBad ? 'ip-err' : undefined}
            onChange={(e) => { setIpText(e.target.value); if (e.target.value === '') set('src_ip', '') }} />
          {ipBad && <span id="ip-err" className="form-error">Enter an IPv4 address, like 10.10.10.30.</span>}
        </div>
        <button className="btn" disabled={ipBad}>Apply</button>
      </form>

      {q.isPending && <Loading what="events" />}
      {q.isError && <ErrorNotice error={q.error} retry={() => void q.refetch()} />}
      {q.data && q.data.items.length === 0 && (
        <div className="table-wrap"><Empty title="No events match">Try removing a filter. Events appear here once a detection rule fires.</Empty></div>
      )}
      {q.data && q.data.items.length > 0 && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Severity</th><th>What happened</th><th>Source</th><th>Target</th><th className="num">Hits</th><th>Last seen</th><th>Status</th></tr>
              </thead>
              <tbody>
                {q.data.items.map((e) => (
                  <tr key={e.id}>
                    <td><SeverityTag severity={e.severity} /></td>
                    <td>
                      <Link className="row-link" to={`/events/${e.id}`}>{CATEGORY_LABEL[e.category] ?? e.category}</Link>
                      <div className="soft" style={{ maxWidth: '38ch' }}>{e.description}</div>
                    </td>
                    <td className="data">{e.src_ip}</td>
                    <td className="data">{e.dst_ip ? `${e.dst_ip}${e.dst_port != null ? ':' + e.dst_port : ''}` : '—'}</td>
                    <td className="num">{formatCount(e.hit_count)}</td>
                    <td>{formatTime(e.last_seen_at)}{e.is_open && <span className="tag warn" style={{ marginLeft: '0.5rem' }}>active</span>}</td>
                    <td>{STATUS_LABEL[e.status]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button className="btn small" disabled={stack.length === 0} onClick={() => setStack((s) => s.slice(0, -1))}>Newer</button>
            <span>{stack.length === 0 ? 'Showing the newest events' : `Page ${stack.length + 1}`}</span>
            <button className="btn small" disabled={q.data.next_before_id === null} onClick={() => setStack((s) => [...s, q.data!.next_before_id!])}>Older</button>
          </div>
        </>
      )}
    </>
  )
}
