import { beforeEach, describe, expect, it } from 'vitest'
import type { Alert } from '../api/types'
import { LiveFeed, MAX_ALERTS, type Deps, type SocketLike } from './feed'

class FakeSocket implements SocketLike {
  onopen: SocketLike['onopen'] = null
  onmessage: SocketLike['onmessage'] = null
  onclose: SocketLike['onclose'] = null
  onerror: SocketLike['onerror'] = null
  sent: string[] = []
  closed = false
  send(d: string) { this.sent.push(d) }
  close() { this.closed = true }
  open() { this.onopen?.({}) }
  push(o: unknown) { this.onmessage?.({ data: typeof o === 'string' ? o : JSON.stringify(o) }) }
  drop(code = 1006) { this.onclose?.({ code }) }
}

const alert = (id: number): Alert => ({
  id, event_id: 1, severity: 'high', title: `a${id}`, created_at: '2026-11-11T19:00:00Z',
  status: 'new', acknowledged_by: null, acknowledged_at: null, category: 'port_scan', src_ip: '10.10.10.30',
})

let sockets: FakeSocket[]
let timers: { fn: () => void; ms: number; live: boolean }[]
let loads: (number | undefined)[]
let store: Alert[]
let gate: (() => void) | null
let clock = 1000

function make() {
  const deps: Deps = {
    url: () => 'ws://x/api/ws',
    createSocket: () => { const s = new FakeSocket(); sockets.push(s); return s },
    loadAlerts: async (after) => {
      loads.push(after)
      if (gate) await new Promise<void>((r) => { const g = gate; gate = () => { g?.(); r() } })
      return store.filter((a) => after === undefined || a.id > after)
    },
    now: () => clock,
    setTimer: (fn, ms) => { const t = { fn, ms, live: true }; timers.push(t); return t },
    clearTimer: (h) => { (h as { live: boolean }).live = false },
  }
  return new LiveFeed(deps)
}
const flush = () => new Promise((r) => setTimeout(r, 0))
const reconnectTimer = () => timers.filter((t) => t.live && t.ms >= 1000 && t.ms <= 15000).at(-1)

beforeEach(() => { sockets = []; timers = []; loads = []; store = []; gate = null; clock = 1000 })

describe('LiveFeed', () => {
  it('goes open on connect and loads the initial alerts from REST', async () => {
    store = [alert(2), alert(1)]
    const f = make(); f.start()
    sockets[0].open()
    expect(f.getSnapshot().feed).toBe('open')
    sockets[0].push({ type: 'hello', last_alert_id: 2, server_time: 't' })
    await flush()
    expect(loads).toEqual([undefined])
    expect(f.getSnapshot().alerts.map((a) => a.id)).toEqual([2, 1])
  })

  it('adds pushed alerts newest first, without duplicates, capped', () => {
    const f = make(); f.start(); sockets[0].open()
    sockets[0].push({ type: 'alert', alert: alert(5) })
    sockets[0].push({ type: 'alert', alert: alert(5) })
    sockets[0].push({ type: 'alert', alert: alert(6) })
    expect(f.getSnapshot().alerts.map((a) => a.id)).toEqual([6, 5])
    for (let i = 10; i < 10 + MAX_ALERTS + 20; i++) sockets[0].push({ type: 'alert', alert: alert(i) })
    expect(f.getSnapshot().alerts).toHaveLength(MAX_ALERTS)
    expect(f.getSnapshot().alerts[0].id).toBe(10 + MAX_ALERTS + 19)
  })

  it('marks only pushed alerts as freshly arrived', async () => {
    store = [alert(1)]
    const f = make(); f.start(); sockets[0].open()
    sockets[0].push({ type: 'hello', last_alert_id: 1, server_time: 't' })
    await flush()
    sockets[0].push({ type: 'alert', alert: alert(2) })
    expect(f.getSnapshot().pushedAt).toEqual({ 2: 1000 })
  })

  it('keeps the monitor status and when it arrived', () => {
    const f = make(); f.start(); sockets[0].open()
    sockets[0].push({ type: 'monitor', status: { state: 'running', effective_state: 'running' } })
    expect(f.getSnapshot().monitor?.state).toBe('running')
    expect(f.getSnapshot().receivedAt).toBe(1000)
  })

  it('records when the packet counter last moved, for the "no packets" header state', () => {
    const f = make(); f.start(); sockets[0].open()
    const status = (n: number) => ({ type: 'monitor', status: { state: 'running', effective_state: 'running', packets_captured: n } })
    sockets[0].push(status(8))
    expect(f.getSnapshot().capturedChangedAt).toBe(1000) // first sight counts as a change
    clock = 6000; sockets[0].push(status(8))
    expect(f.getSnapshot().capturedChangedAt).toBe(1000) // unchanged count: keep the old time
    clock = 11000; sockets[0].push(status(9))
    expect(f.getSnapshot().capturedChangedAt).toBe(11000)
    clock = 16000; sockets[0].push(status(3)) // a restarted monitor counts from zero: also a change
    expect(f.getSnapshot().capturedChangedAt).toBe(16000)
  })

  it('backfills from the newest known id on resync and on a hello that reports newer alerts', async () => {
    const f = make(); f.start(); sockets[0].open()
    sockets[0].push({ type: 'alert', alert: alert(3) })
    store = [alert(5), alert(4), alert(3)]
    sockets[0].push({ type: 'resync' })
    await flush()
    expect(loads.at(-1)).toBe(3)
    expect(f.getSnapshot().alerts.map((a) => a.id)).toEqual([5, 4, 3])
    store.unshift(alert(9))
    sockets[0].push({ type: 'hello', last_alert_id: 9, server_time: 't' })
    await flush()
    expect(loads.at(-1)).toBe(5)
    expect(f.getSnapshot().alerts[0].id).toBe(9)
  })

  it('does not reload on a hello when nothing is newer', async () => {
    const f = make(); f.start(); sockets[0].open()
    sockets[0].push({ type: 'alert', alert: alert(3) })
    sockets[0].push({ type: 'hello', last_alert_id: 3, server_time: 't' })
    await flush()
    expect(loads).toEqual([])
    expect(f.getSnapshot().alerts).toHaveLength(1)
  })

  it('collapses overlapping syncs into one follow-up', async () => {
    const f = make(); f.start(); sockets[0].open()
    gate = () => undefined
    sockets[0].push({ type: 'resync' }); sockets[0].push({ type: 'resync' }); sockets[0].push({ type: 'resync' })
    await flush()
    expect(loads).toHaveLength(1)
    gate?.(); gate = null
    await flush(); await flush()
    expect(loads.length).toBeLessThanOrEqual(2)
  })

  it('reconnects with growing delays and resets after a good connection', () => {
    const f = make(); f.start()
    sockets[0].drop(); expect(reconnectTimer()?.ms).toBe(1000)
    reconnectTimer()!.fn(); sockets[1].drop(); expect(reconnectTimer()?.ms).toBe(2000)
    reconnectTimer()!.fn(); sockets[2].drop(); expect(reconnectTimer()?.ms).toBe(4000)
    reconnectTimer()!.fn(); sockets[3].open(); sockets[3].drop()
    expect(reconnectTimer()?.ms).toBe(1000)
    expect(f.getSnapshot().feed).toBe('closed')
  })

  it.each([4401, 1008])('does not retry after close code %i and flags the lost session', (code) => {
    const f = make(); f.start(); sockets[0].open(); sockets[0].drop(code)
    expect(f.getSnapshot().authLost).toBe(true)
    expect(reconnectTimer()).toBeUndefined()
    expect(sockets).toHaveLength(1)
  })

  it('retries after being cut off for being slow (1013)', () => {
    const f = make(); f.start(); sockets[0].open(); sockets[0].drop(1013)
    expect(f.getSnapshot().authLost).toBe(false)
    expect(reconnectTimer()).toBeDefined()
  })

  it('stop() closes the socket and cancels any retry', () => {
    const f = make(); f.start(); sockets[0].drop()
    const t = reconnectTimer()!
    f.stop()
    expect(t.live).toBe(false)
    expect(f.getSnapshot().feed).toBe('closed')
  })

  it('sends a ping on the keep-alive timer', () => {
    const f = make(); f.start(); sockets[0].open()
    timers.filter((t) => t.live && t.ms === 25000).at(-1)!.fn()
    expect(sockets[0].sent).toEqual(['ping'])
  })

  it('ignores malformed messages', () => {
    const f = make(); f.start(); sockets[0].open()
    sockets[0].push('not json {')
    sockets[0].push({ type: 'something-new' })
    expect(f.getSnapshot().alerts).toEqual([])
  })
})
