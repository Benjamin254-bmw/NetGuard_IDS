import type { Alert, LiveMessage, MonitorStatus } from '../api/types'
import type { FeedState } from './status'

export interface SocketLike {
  onopen: ((ev: unknown) => void) | null
  onmessage: ((ev: { data: unknown }) => void) | null
  onclose: ((ev: { code: number }) => void) | null
  onerror: ((ev: unknown) => void) | null
  send(data: string): void
  close(code?: number): void
}

export interface Deps {
  url: () => string
  createSocket: (url: string) => SocketLike
  /** Alerts newer than `afterId` (or the latest page when undefined), oldest or newest first. */
  loadAlerts: (afterId?: number) => Promise<Alert[]>
  now: () => number
  setTimer: (fn: () => void, ms: number) => unknown
  clearTimer: (h: unknown) => void
}

export interface Snapshot {
  feed: FeedState
  monitor: MonitorStatus | null
  receivedAt: number | null
  alerts: Alert[] // newest first, at most MAX_ALERTS
  /** when each alert arrived by push (ms); alerts loaded from REST have no entry */
  pushedAt: Record<number, number>
  /** set when the server ended the session (close code 4401) or refused us (1008) */
  authLost: boolean
}

export const MAX_ALERTS = 50
const BACKOFF = [1000, 2000, 4000, 8000, 15000]
const PING_MS = 25_000

/**
 * The browser side of /api/ws. The database stays the record: after any gap (reconnect, a
 * `resync`, or a hello that reports newer alerts than we hold) alerts are re-read over REST
 * starting from the newest id we have, so a dropped connection cannot silently lose an alert.
 */
export class LiveFeed {
  private snap: Snapshot = {
    feed: 'connecting',
    monitor: null,
    receivedAt: null,
    alerts: [],
    pushedAt: {},
    authLost: false,
  }
  private listeners = new Set<() => void>()
  private socket: SocketLike | null = null
  private attempt = 0
  private retry: unknown = null
  private ping: unknown = null
  private stopped = true
  private syncing = false
  private syncAgain = false

  private deps: Deps
  constructor(deps: Deps) {
    this.deps = deps
  }

  subscribe = (fn: () => void) => {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }
  getSnapshot = () => this.snap

  start() {
    if (!this.stopped) return
    this.stopped = false
    this.snap = { ...this.snap, authLost: false }
    this.open()
  }

  stop() {
    this.stopped = true
    if (this.retry) this.deps.clearTimer(this.retry)
    if (this.ping) this.deps.clearTimer(this.ping)
    this.retry = this.ping = null
    const s = this.socket
    this.socket = null
    if (s) {
      s.onclose = null
      s.close(1000)
    }
    this.set({ feed: 'closed' })
  }

  private set(patch: Partial<Snapshot>) {
    this.snap = { ...this.snap, ...patch }
    this.listeners.forEach((fn) => fn())
  }

  private open() {
    this.set({ feed: this.snap.monitor ? 'closed' : 'connecting' })
    const s = this.deps.createSocket(this.deps.url())
    this.socket = s
    s.onopen = () => {
      this.attempt = 0
      this.set({ feed: 'open' })
      this.schedulePing()
    }
    s.onmessage = (ev) => this.onMessage(ev.data)
    s.onerror = () => undefined // onclose follows and carries the code
    s.onclose = (ev) => this.onClose(ev.code)
  }

  private schedulePing() {
    if (this.ping) this.deps.clearTimer(this.ping)
    this.ping = this.deps.setTimer(() => {
      this.socket?.send('ping')
      this.schedulePing()
    }, PING_MS)
  }

  private onClose(code: number) {
    if (this.ping) this.deps.clearTimer(this.ping)
    this.socket = null
    if (this.stopped) return
    if (code === 4401 || code === 1008) {
      // Session ended or request refused: retrying with the same cookie cannot succeed.
      this.set({ feed: 'closed', authLost: true })
      return
    }
    this.set({ feed: 'closed' })
    const wait = BACKOFF[Math.min(this.attempt, BACKOFF.length - 1)]
    this.attempt += 1
    this.retry = this.deps.setTimer(() => this.open(), wait)
  }

  private onMessage(raw: unknown) {
    let msg: LiveMessage
    try {
      msg = JSON.parse(String(raw)) as LiveMessage
    } catch {
      return
    }
    switch (msg.type) {
      case 'hello': {
        const newest = this.snap.alerts[0]?.id ?? 0
        if (this.snap.alerts.length === 0 || msg.last_alert_id > newest) void this.sync()
        break
      }
      case 'alert':
        this.addAlerts([msg.alert], true)
        break
      case 'monitor':
        this.set({ monitor: msg.status, receivedAt: this.deps.now() })
        break
      case 'resync':
        void this.sync()
        break
      default:
        break
    }
  }

  private addAlerts(incoming: Alert[], pushed = false) {
    const byId = new Map(this.snap.alerts.map((a) => [a.id, a]))
    for (const a of incoming) byId.set(a.id, a)
    const merged = [...byId.values()].sort((x, y) => y.id - x.id).slice(0, MAX_ALERTS)
    const pushedAt = { ...this.snap.pushedAt }
    if (pushed) for (const a of incoming) pushedAt[a.id] ??= this.deps.now()
    const keep = new Set(merged.map((a) => a.id))
    for (const id of Object.keys(pushedAt)) if (!keep.has(Number(id))) delete pushedAt[Number(id)]
    this.set({ alerts: merged, pushedAt })
  }

  /** Re-read alerts from REST. Overlapping requests collapse into one follow-up. */
  async sync() {
    if (this.syncing) {
      this.syncAgain = true
      return
    }
    this.syncing = true
    try {
      do {
        this.syncAgain = false
        const newest = this.snap.alerts[0]?.id
        try {
          this.addAlerts(await this.deps.loadAlerts(newest))
        } catch {
          /* the next hello or resync retries; the UI keeps what it has */
        }
      } while (this.syncAgain && !this.stopped)
    } finally {
      this.syncing = false
    }
  }
}
