import { describe, expect, it } from 'vitest'
import type { MonitorStatus } from '../api/types'
import { deriveStatus, type Inputs } from './status'

const NOW = 1_800_000_000_000
const mon = (o: Partial<MonitorStatus> = {}): MonitorStatus => ({
  state: 'running',
  effective_state: 'running',
  interface: 'br-lab',
  heartbeat_at: new Date(NOW - 3000).toISOString(),
  heartbeat_age_seconds: 3,
  degraded_reasons: [],
  ...o,
})
const base = (o: Partial<Inputs> = {}): Inputs => ({
  monitor: mon(),
  receivedAt: NOW - 1000,
  feed: 'open',
  apiReachable: true,
  now: NOW,
  ...o,
})

describe('header status', () => {
  it('is live only when the feed is open, fresh, and the monitor is running', () => {
    const d = deriveStatus(base())
    expect(d.level).toBe('live')
    expect(d.current).toBe(true)
    expect(d.title).toContain('br-lab')
  })
  it('reports problems the monitor reports', () => {
    const d = deriveStatus(base({ monitor: mon({ effective_state: 'degraded', degraded_reasons: ['capture queue full'] }) }))
    expect(d.level).toBe('degraded')
    expect(d.current).toBe(true)
    expect(d.detail).toContain('capture queue full')
  })
  it('says the monitor is silent when the server marks the heartbeat stale', () => {
    const d = deriveStatus(base({ monitor: mon({ effective_state: 'stale', heartbeat_age_seconds: 120 }) }))
    expect(d.level).toBe('silent')
    expect(d.current).toBe(false)
  })
  it('does not trust a "running" status that has aged in the browser', () => {
    // last push said age 3 s, but it arrived 14 s ago: effective age 17 s > 15 s
    const d = deriveStatus(base({ receivedAt: NOW - 14_000 }))
    expect(d.level).toBe('silent')
  })
  it('says the feed is disconnected, not that the monitor is fine, when the socket is down', () => {
    for (const feed of ['closed', 'connecting'] as const) {
      const d = deriveStatus(base({ feed }))
      expect(d.level).toBe('disconnected')
      expect(d.current).toBe(false)
      expect(d.detail).toMatch(/as of/)
    }
  })
  it('treats an open but silent feed as disconnected', () => {
    const d = deriveStatus(base({ receivedAt: NOW - 25_000 }))
    expect(d.level).toBe('disconnected')
  })
  it('prefers "cannot reach the API" over everything else', () => {
    const d = deriveStatus(base({ apiReachable: false }))
    expect(d.level).toBe('unreachable')
    expect(d.current).toBe(false)
  })
  it('handles first load and a monitor that never ran', () => {
    expect(deriveStatus(base({ monitor: null, receivedAt: null, feed: 'connecting' })).level).toBe('connecting')
    const never = deriveStatus(base({ monitor: mon({ state: 'never_started', effective_state: 'never_started' }) }))
    expect(never.level).toBe('never')
    expect(never.current).toBe(false)
  })
  it('flags a running monitor whose packet count has not moved for two minutes', () => {
    const d = deriveStatus(base({ lastCaptureAt: NOW - 125_000 }))
    expect(d.level).toBe('quiet')
    expect(d.current).toBe(true) // the data is current; there is just none
    expect(d.title).toContain('br-lab')
    expect(d.detail).toMatch(/2 min/)
    expect(d.detail).toContain('NETGUARD_PROMISCUOUS')
  })
  it('stays live while packets keep arriving, and before anything has been observed', () => {
    expect(deriveStatus(base({ lastCaptureAt: NOW - 119_000 })).level).toBe('live')
    expect(deriveStatus(base({ lastCaptureAt: null })).level).toBe('live')
    expect(deriveStatus(base()).level).toBe('live')
  })
  it('reports worse states before quiet', () => {
    const old = NOW - 600_000
    expect(deriveStatus(base({ lastCaptureAt: old, monitor: mon({ effective_state: 'stale' }) })).level).toBe('silent')
    expect(deriveStatus(base({ lastCaptureAt: old, feed: 'closed' })).level).toBe('disconnected')
    const deg = mon({ effective_state: 'degraded', degraded_reasons: ['capture error'] })
    expect(deriveStatus(base({ lastCaptureAt: old, monitor: deg })).level).toBe('degraded')
  })
  it('never reports current data unless the level is live, quiet or degraded', () => {
    const cases: Partial<Inputs>[] = [
      { feed: 'closed' },
      { apiReachable: false },
      { monitor: mon({ effective_state: 'stopped' }) },
      { monitor: mon({ effective_state: 'starting' }) },
      { monitor: null, receivedAt: null, feed: 'connecting' },
    ]
    for (const c of cases) expect(deriveStatus(base(c)).current).toBe(false)
  })
})
