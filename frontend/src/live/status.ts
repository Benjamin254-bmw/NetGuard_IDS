import type { MonitorStatus } from '../api/types'

export type FeedState = 'connecting' | 'open' | 'closed'

/** What the header can say. `current` is false whenever the numbers on screen may be old. */
export type Level =
  | 'live'
  | 'quiet'
  | 'degraded'
  | 'starting'
  | 'silent'
  | 'never'
  | 'disconnected'
  | 'unreachable'
  | 'connecting'

export interface Inputs {
  monitor: MonitorStatus | null
  /** when the newest monitor status arrived in this browser (ms since epoch) */
  receivedAt: number | null
  feed: FeedState
  apiReachable: boolean
  now: number
  /** when this browser last saw `packets_captured` change, or first saw it (ms); null = not seen yet */
  lastCaptureAt?: number | null
}
export interface Derived {
  level: Level
  current: boolean
  title: string
  detail: string
}

/** The server marks a heartbeat older than this stale; we apply the same limit to what we hold. */
export const STALE_SECONDS = 15
/** The server pushes status every 5 s; three missed pushes means the feed is not delivering. */
export const FEED_SILENCE_MS = 20_000
/** A running monitor whose packet count has not moved for this long is flagged: on a real network
 *  something (ARP, broadcasts) always arrives, so silence usually means the wrong interface or a bridge or
 *  mirror port without promiscuous mode. An idle lab is legitimately quiet, so it is a warning, not an error. */
export const QUIET_MS = 120_000

const hhmm = (ms: number) =>
  new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })

export function deriveStatus(i: Inputs): Derived {
  const since = i.receivedAt ? ` Showing data as of ${hhmm(i.receivedAt)}.` : ''
  if (!i.apiReachable) {
    return {
      level: 'unreachable',
      current: false,
      title: 'Cannot reach NetGuard',
      detail: `The dashboard cannot contact the API.${since}`,
    }
  }
  if (i.feed === 'connecting' && !i.monitor) {
    return { level: 'connecting', current: false, title: 'Connecting', detail: 'Opening the live feed.' }
  }
  const silent = i.receivedAt === null || i.now - i.receivedAt > FEED_SILENCE_MS
  if (i.feed !== 'open' || (i.feed === 'open' && silent && i.monitor)) {
    return {
      level: 'disconnected',
      current: false,
      title: 'Live feed disconnected',
      detail: `New alerts will not appear until it reconnects.${since}`,
    }
  }
  const m = i.monitor
  if (!m) return { level: 'connecting', current: false, title: 'Connecting', detail: 'Waiting for the monitor status.' }
  if (m.effective_state === 'never_started') {
    return {
      level: 'never',
      current: false,
      title: 'Monitor has not started',
      detail: 'Nothing is being captured. Stored data is historical.',
    }
  }
  const age = (m.heartbeat_age_seconds ?? 0) + (i.now - (i.receivedAt ?? i.now)) / 1000
  if (m.effective_state === 'stale' || m.effective_state === 'stopped' || age > STALE_SECONDS) {
    return {
      level: 'silent',
      current: false,
      title: 'Monitor is not responding',
      detail: m.heartbeat_at
        ? `No heartbeat since ${hhmm(Date.parse(m.heartbeat_at))}. Stored data is historical.`
        : 'No heartbeat received. Stored data is historical.',
    }
  }
  if (m.effective_state === 'starting') {
    return { level: 'starting', current: false, title: 'Monitor is starting', detail: 'Capture has not begun yet.' }
  }
  const where = m.interface ? ` on ${m.interface}` : ''
  if (m.effective_state === 'degraded') {
    const why = m.degraded_reasons?.length ? m.degraded_reasons.join(', ') : 'see monitor status'
    return {
      level: 'degraded',
      current: true,
      title: `Monitoring${where} with problems`,
      detail: `Some traffic may be missed: ${why}.`,
    }
  }
  if (i.lastCaptureAt != null && i.now - i.lastCaptureAt >= QUIET_MS) {
    const mins = Math.floor((i.now - i.lastCaptureAt) / 60_000)
    return {
      level: 'quiet',
      current: true,
      title: `Monitoring${where}, no packets`,
      detail:
        `Nothing captured for ${mins} min. If this network is not idle, check the interface ` +
        'and promiscuous mode (NETGUARD_PROMISCUOUS) on bridge or mirror ports.',
    }
  }
  return { level: 'live', current: true, title: `Monitoring${where}`, detail: 'Live. Alerts appear as they happen.' }
}
