import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { fetchDevices, fetchOverview, fetchProtocols, fetchTalkers, fetchTraffic } from '../api/hooks'
import type { Severity } from '../api/types'
import { SegmentBar } from '../charts/SegmentBar'
import { TrafficChart } from '../charts/TrafficChart'
import { Empty, ErrorNotice, Loading, SeverityTag, severityColor, severityLabel } from '../components/ui'
import { CATEGORY_LABEL, SEVERITIES, formatBytes, formatCount, timeAgo } from '../lib/format'
import { useLive } from '../live/LiveProvider'

const REFRESH = 10_000
const MINUTES = 15

export default function Overview() {
  const { snapshot, status, now } = useLive()
  const overview = useQuery({ queryKey: ['overview'], queryFn: fetchOverview, refetchInterval: REFRESH })
  const traffic = useQuery({ queryKey: ['traffic', 5, MINUTES], queryFn: () => fetchTraffic(5, MINUTES), refetchInterval: REFRESH })
  const talkers = useQuery({ queryKey: ['talkers', 60], queryFn: () => fetchTalkers(60), refetchInterval: 30_000 })
  const protocols = useQuery({ queryKey: ['protocols', 60], queryFn: () => fetchProtocols(60), refetchInterval: 30_000 })
  const devices = useQuery({ queryKey: ['devices'], queryFn: fetchDevices, refetchInterval: 30_000 })

  // An alert is highlighted for a few seconds after it arrives by push; alerts loaded from the
  // server (first visit, catch-up after a reconnect) are not.
  const isFresh = (id: number) => {
    const at = snapshot.pushedAt[id]
    return at !== undefined && now - at < 4000
  }
  const o = overview.data
  const open = o?.open_events_by_severity ?? {}
  const openTotal = SEVERITIES.reduce((n, s) => n + (open[s] ?? 0), 0)

  return (
    <>
      <div className="page-head">
        <h1>Overview</h1>
        <p>{status.current ? 'What the network is doing right now.' : 'The last data NetGuard saved.'}</p>
      </div>

      {overview.isError && <ErrorNotice error={overview.error} retry={() => void overview.refetch()} />}
      {overview.isPending && <Loading what="overview" />}

      {o && (
        <section aria-labelledby="open-h">
          <h2 id="open-h" className="sr-only">Open events</h2>
          <div className="vitals">
            <div className="vital"><b>{formatCount(openTotal)}</b><span>open events</span></div>
            <div className="vital"><b>{formatCount(o.alerts.new)}</b><span>new alerts</span></div>
            <div className="vital"><b>{formatCount(devices.data?.items.filter((d) => d.status === 'active').length ?? o.devices.active)}</b><span>active devices</span></div>
            <div className="vital"><b>{formatBytes(o.traffic_last_5m.bytes)}</b><span>in the last 5 minutes</span></div>
          </div>
          <div style={{ marginTop: '1.25rem' }}>
            <SegmentBar
              unit="open events"
              emptyText={status.current ? 'No open events. Nothing needs attention.' : 'No events are marked active in saved data. NetGuard is not live, so this may be out of date.'}
              segments={SEVERITIES.map((s) => ({ key: s, value: open[s] ?? 0, color: severityColor(s), label: severityLabel(s) }))}
            />
          </div>
        </section>
      )}

      <div className="section">
        <h2>Traffic, last {MINUTES} minutes</h2>
        {traffic.data ? (
          <TrafficChart points={traffic.data.points} bucketSeconds={traffic.data.bucket_seconds} from={traffic.data.from} to={traffic.data.to} />
        ) : traffic.isError ? (
          <ErrorNotice error={traffic.error} />
        ) : (
          <Loading what="traffic" />
        )}
      </div>

      <div className="overview-grid section">
        <div>
          <section className="section">
            <h2>Latest alerts</h2>
            {snapshot.alerts.length === 0 ? (
              <div className="ledger" style={{ padding: 0 }}>
                <Empty title="No alerts yet">
                  {status.current
                    ? 'New alerts appear here the moment the monitor raises them.'
                    : 'The monitor is not live, so nothing new can arrive.'}
                </Empty>
              </div>
            ) : (
              <ul className="ledger" aria-live="off">
                {snapshot.alerts.slice(0, 12).map((a) => (
                  <li key={a.id} style={{ ['--c' as string]: severityColor(a.severity) }} data-fresh={isFresh(a.id) || undefined}>
                    <SeverityTag severity={a.severity} />
                    <span className="title">
                      <Link to={`/events/${a.event_id}`}>{a.title}</Link>
                      <span className="soft"> · {CATEGORY_LABEL[a.category] ?? a.category}</span>
                    </span>
                    <span className="when">{timeAgo(a.created_at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <div>
          <section className="section">
            <h2>Busiest sources, last hour</h2>
            {talkers.data && talkers.data.items.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Address</th><th className="num">Data</th><th className="num">Packets</th></tr></thead>
                  <tbody>
                    {talkers.data.items.map((t) => (
                      <tr key={t.ip}><td className="data">{t.ip}</td><td className="num">{formatBytes(t.bytes)}</td><td className="num">{formatCount(t.packets)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="soft">{talkers.isError ? 'Could not load sources.' : 'No traffic recorded in the last hour.'}</p>
            )}
          </section>
          <section className="section">
            <h2>Protocols, last hour</h2>
            <SegmentBar
              unit="packets"
              emptyText="No traffic recorded in the last hour."
              segments={(protocols.data?.items ?? []).map((p, i) => ({ key: p.protocol, value: p.packets, label: p.protocol.toUpperCase(), color: PROTO_COLORS[i % PROTO_COLORS.length] }))}
            />
          </section>
        </div>
      </div>
    </>
  )
}

const PROTO_COLORS = ['#0b7a75', '#2a68ad', '#a86d00', '#7a4fa3', '#566b77', '#c94a14', '#3f8f4f', '#8a6d3b']
export type { Severity }
