import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { fetchRule, patchRule } from '../api/hooks'
import type { RuleDetail as RuleDetailT, Severity } from '../api/types'
import { useAuth } from '../auth/AuthProvider'
import { ErrorNotice, Loading, SeverityTag } from '../components/ui'
import { CATEGORY_LABEL, SEVERITIES, formatTime } from '../lib/format'

type ParamDraft = Record<string, string | boolean>

const toDraft = (p: Record<string, unknown>): ParamDraft =>
  Object.fromEntries(Object.entries(p).map(([k, v]) => [k, Array.isArray(v) ? v.join('\n') : typeof v === 'boolean' ? v : String(v)]))

/** Only parameters that changed are sent; the server rejects unknown keys and wrong types. */
export function buildPatch(rule: RuleDetailT, d: { enabled: boolean; severity: string; threshold: string; window: string; cooldown: string; params: ParamDraft }) {
  const body: Record<string, unknown> = {}
  if (d.enabled !== rule.enabled) body.enabled = d.enabled
  if (d.severity !== rule.severity) body.severity = d.severity
  if (Number(d.threshold) !== rule.threshold) body.threshold = Number(d.threshold)
  if (Number(d.window) !== rule.window_seconds) body.window_seconds = Number(d.window)
  if (Number(d.cooldown) !== rule.cooldown_seconds) body.cooldown_seconds = Number(d.cooldown)
  const params: Record<string, unknown> = {}
  for (const [k, orig] of Object.entries(rule.params)) {
    const v = d.params[k]
    if (Array.isArray(orig)) {
      const list = String(v).split('\n').map((s) => s.trim()).filter(Boolean)
      if (JSON.stringify(list) !== JSON.stringify(orig)) params[k] = list
    } else if (typeof orig === 'boolean') {
      if (v !== orig) params[k] = v
    } else if (typeof orig === 'number') {
      if (Number(v) !== orig) params[k] = Number(v)
    } else if (v !== orig) params[k] = v
  }
  if (Object.keys(params).length) body.params = params
  return body
}

function Editor({ rule }: { rule: RuleDetailT }) {
  const qc = useQueryClient()
  const [d, setD] = useState({
    enabled: rule.enabled, severity: rule.severity as string, threshold: String(rule.threshold),
    window: String(rule.window_seconds), cooldown: String(rule.cooldown_seconds), params: toDraft(rule.params),
  })
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => patchRule(rule.id, body),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['rule', rule.id] }); void qc.invalidateQueries({ queryKey: ['rules'] }) },
  })
  const body = buildPatch(rule, d)
  const changed = Object.keys(body).length > 0
  const submit = (e: FormEvent) => { e.preventDefault(); if (changed) save.mutate(body) }

  return (
    <form className="stack" onSubmit={submit} style={{ maxWidth: '30rem' }}>
      <label className="row"><input type="checkbox" checked={d.enabled} onChange={(e) => setD({ ...d, enabled: e.target.checked })} /> Rule is on</label>
      <div className="field">
        <label htmlFor="r-sev">Severity</label>
        <select id="r-sev" className="input" value={d.severity} onChange={(e) => setD({ ...d, severity: e.target.value })}>
          {[...SEVERITIES].reverse().map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
        </select>
      </div>
      <div className="field"><label htmlFor="r-th">Threshold</label><input id="r-th" className="input" inputMode="numeric" value={d.threshold} onChange={(e) => setD({ ...d, threshold: e.target.value })} /><span className="hint">How much activity within the window triggers this rule. The unit depends on the rule: ports, connections, failed attempts.</span></div>
      <div className="field"><label htmlFor="r-w">Window (seconds)</label><input id="r-w" className="input" inputMode="numeric" value={d.window} onChange={(e) => setD({ ...d, window: e.target.value })} /><span className="hint">1 to 3600.</span></div>
      <div className="field"><label htmlFor="r-c">Cooldown (seconds)</label><input id="r-c" className="input" inputMode="numeric" value={d.cooldown} onChange={(e) => setD({ ...d, cooldown: e.target.value })} /><span className="hint">Quiet time before the same source can raise a new event. 0 to 86400.</span></div>
      {Object.entries(rule.params).map(([k, orig]) => (
        <div className="field" key={k}>
          {typeof orig === 'boolean' ? (
            <label className="row"><input type="checkbox" checked={d.params[k] === true} onChange={(e) => setD({ ...d, params: { ...d.params, [k]: e.target.checked } })} /> {k}</label>
          ) : Array.isArray(orig) ? (
            <>
              <label htmlFor={`p-${k}`}>{k}</label>
              <textarea id={`p-${k}`} className="input data" rows={4} value={String(d.params[k] ?? '')} onChange={(e) => setD({ ...d, params: { ...d.params, [k]: e.target.value } })} />
              <span className="hint">One entry per line.</span>
            </>
          ) : (
            <>
              <label htmlFor={`p-${k}`}>{k}</label>
              <input id={`p-${k}`} className="input" value={String(d.params[k] ?? '')} onChange={(e) => setD({ ...d, params: { ...d.params, [k]: e.target.value } })} />
            </>
          )}
        </div>
      ))}
      {save.isError && <ErrorNotice error={save.error} />}
      {save.isSuccess && !changed && <p className="form-ok" role="status">Saved. This is now version {save.data.version}.</p>}
      <div className="row">
        <button className="btn primary" disabled={!changed || save.isPending}>{save.isPending ? 'Saving…' : 'Save changes'}</button>
        {changed && <button type="button" className="btn quiet" onClick={() => setD({ enabled: rule.enabled, severity: rule.severity, threshold: String(rule.threshold), window: String(rule.window_seconds), cooldown: String(rule.cooldown_seconds), params: toDraft(rule.params) })}>Discard</button>}
      </div>
    </form>
  )
}

export default function RuleDetail() {
  const id = Number(useParams().id)
  const { isAdmin } = useAuth()
  const q = useQuery({ queryKey: ['rule', id], queryFn: () => fetchRule(id), enabled: Number.isInteger(id) && id > 0 })
  if (q.isPending) return <Loading what="rule" />
  if (q.isError) return <><p><Link to="/rules">Back to rules</Link></p><ErrorNotice error={q.error} /></>
  const r = q.data
  return (
    <>
      <p><Link to="/rules">← All rules</Link></p>
      <div className="page-head" style={{ marginTop: '0.75rem' }}>
        <h1>{r.name}</h1>
        <span className="soft">{CATEGORY_LABEL[r.category]} · version {r.version}</span>
      </div>
      <p style={{ marginBottom: '1.5rem', maxWidth: '65ch' }}>{r.description}</p>
      <div className="overview-grid">
        <section>
          <h2 style={{ fontSize: 'var(--step-1)', marginBottom: '0.9rem' }}>{isAdmin ? 'Settings' : 'Current settings'}</h2>
          {isAdmin ? <Editor key={r.version} rule={r} /> : (
            <>
              <dl className="deflist">
                <dt>State</dt><dd>{r.enabled ? 'On' : 'Off'}</dd>
                <dt>Severity</dt><dd><SeverityTag severity={r.severity as Severity} /></dd>
                <dt>Threshold</dt><dd>{r.threshold}</dd>
                <dt>Window</dt><dd>{r.window_seconds} s</dd>
                <dt>Cooldown</dt><dd>{r.cooldown_seconds} s</dd>
              </dl>
              <p className="soft" style={{ marginTop: '1rem' }}>Only administrators can change rules.</p>
            </>
          )}
        </section>
        <section>
          <h2 style={{ fontSize: 'var(--step-1)', marginBottom: '0.9rem' }}>Version history</h2>
          <div className="table-wrap">
            <table>
              <thead><tr><th className="num">Version</th><th className="num">Threshold</th><th className="num">Window</th><th>Changed</th></tr></thead>
              <tbody>{r.versions.map((v) => <tr key={v.version}><td className="num">{v.version}</td><td className="num">{v.threshold}</td><td className="num">{v.window_seconds} s</td><td>{formatTime(v.changed_at)}</td></tr>)}</tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  )
}
