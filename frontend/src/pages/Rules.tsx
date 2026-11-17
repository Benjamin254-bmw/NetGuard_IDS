import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { fetchRules } from '../api/hooks'
import { ErrorNotice, Loading, SeverityTag } from '../components/ui'
import { CATEGORY_LABEL, formatCount, formatTime } from '../lib/format'

export default function Rules() {
  const q = useQuery({ queryKey: ['rules'], queryFn: fetchRules })
  return (
    <>
      <div className="page-head">
        <h1>Rules</h1>
        <p>What counts as suspicious. Each change creates a new version, and events keep the version that raised them.</p>
      </div>
      {q.isPending && <Loading what="rules" />}
      {q.isError && <ErrorNotice error={q.error} retry={() => void q.refetch()} />}
      {q.data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Rule</th><th>Severity</th><th className="num">Threshold</th><th className="num">Window</th><th className="num">Cooldown</th><th>State</th><th className="num">Version</th><th>Changed</th></tr></thead>
            <tbody>
              {q.data.items.map((r) => (
                <tr key={r.id}>
                  <td><Link className="row-link" to={`/rules/${r.id}`}>{r.name}</Link><div className="soft">{CATEGORY_LABEL[r.category]}</div></td>
                  <td><SeverityTag severity={r.severity} /></td>
                  <td className="num">{formatCount(r.threshold)}</td>
                  <td className="num">{r.window_seconds} s</td>
                  <td className="num">{r.cooldown_seconds} s</td>
                  <td>{r.enabled ? <span className="tag good">On</span> : <span className="tag bad">Off</span>}</td>
                  <td className="num">{r.version}</td>
                  <td>{formatTime(r.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
