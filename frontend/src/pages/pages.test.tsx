import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { RuleDetail } from '../api/types'
import { SegmentBar } from '../charts/SegmentBar'
import { TrafficChart } from '../charts/TrafficChart'
import { StatusPulse } from '../components/StatusPulse'
import { deriveStatus } from '../live/status'
import { isIpv4 } from './Events'
import { buildPatch } from './RuleDetail'

const rule: RuleDetail = {
  id: 1, key: 'port_scan', name: 'Port scan', category: 'port_scan', description: 'd', enabled: true,
  severity: 'high', threshold: 15, window_seconds: 10, cooldown_seconds: 60, version: 1,
  params: { ignore: ['10.0.0.1'], min_ports: 5, strict: false, label: 'x' }, updated_at: '', updated_by: null, versions: [],
}
const same = { enabled: true, severity: 'high', threshold: '15', window: '10', cooldown: '60', params: { ignore: '10.0.0.1', min_ports: '5', strict: false, label: 'x' } }

describe('rule patch', () => {
  it('sends nothing when nothing changed', () => {
    expect(buildPatch(rule, same)).toEqual({})
  })
  it('sends only the fields that changed, as numbers', () => {
    expect(buildPatch(rule, { ...same, threshold: '20', enabled: false })).toEqual({ threshold: 20, enabled: false })
  })
  it('sends only changed parameters, keeping their types', () => {
    const body = buildPatch(rule, { ...same, params: { ...same.params, ignore: '10.0.0.1\n10.0.0.2\n\n', min_ports: '8', strict: true } })
    expect(body).toEqual({ params: { ignore: ['10.0.0.1', '10.0.0.2'], min_ports: 8, strict: true } })
  })
})

describe('source address filter', () => {
  it.each(['10.10.10.30', '0.0.0.0', '255.255.255.255'])('accepts %s', (v) => expect(isIpv4(v)).toBe(true))
  it.each(['', '10.10.10', '256.1.1.1', '10.10.10.30.1', '::1', 'a.b.c.d', '10.10.10.30 '])('rejects "%s"', (v) => expect(isIpv4(v)).toBe(false))
})

describe('accessible charts', () => {
  it('describes the segment bar in words, including only non-zero parts', () => {
    render(<SegmentBar unit="open events" emptyText="none" segments={[
      { key: 'a', value: 2, color: 'red', label: 'High' }, { key: 'b', value: 0, color: 'blue', label: 'Low' },
    ]} />)
    expect(screen.getByRole('img')).toHaveAttribute('aria-label', 'High 2 open events')
  })
  it('says so when there is nothing to show', () => {
    render(<SegmentBar unit="x" emptyText="Nothing here." segments={[{ key: 'a', value: 0, color: 'red', label: 'High' }]} />)
    expect(screen.getByText('Nothing here.')).toBeInTheDocument()
    expect(screen.queryByRole('img')).toBeNull()
  })
  it('summarises the traffic chart, including an empty period', () => {
    render(<TrafficChart points={[]} bucketSeconds={5} from="2026-11-11T10:00:00Z" to="2026-11-11T10:15:00Z" />)
    expect(screen.getByRole('img').getAttribute('aria-label')).toMatch(/^No traffic recorded/)
  })
})

describe('header pulse', () => {
  it('exposes the level and text, and draws a flat line unless live', () => {
    const down = deriveStatus({ monitor: null, receivedAt: null, feed: 'closed', apiReachable: false, now: 0 })
    const { container } = render(<StatusPulse status={down} />)
    expect(screen.getByRole('status')).toHaveAttribute('data-level', 'unreachable')
    expect(container.querySelector('.live-trace')).toBeNull()
    expect(screen.getByText('Cannot reach NetGuard')).toBeInTheDocument()
  })
  it('animates only when the monitor is verifiably live', () => {
    const live = deriveStatus({
      monitor: { state: 'running', effective_state: 'running', interface: 'br-lab', heartbeat_age_seconds: 2 },
      receivedAt: 1000, feed: 'open', apiReachable: true, now: 2000,
    })
    const { container } = render(<StatusPulse status={live} />)
    expect(container.querySelector('.live-trace')).not.toBeNull()
  })
})
