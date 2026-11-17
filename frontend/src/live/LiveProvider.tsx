import { createContext, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from 'react'
import { onReachability } from '../api/client'
import { loadAlerts } from '../api/hooks'
import { useAuth } from '../auth/AuthProvider'
import { LiveFeed, type Snapshot } from './feed'
import { deriveStatus, type Derived } from './status'

interface Live {
  snapshot: Snapshot
  status: Derived
  now: number
}
const Ctx = createContext<Live | null>(null)

function socketUrl(): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${location.host}/api/ws`
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const { state, refresh } = useAuth()
  const authed = state.status === 'authed'

  const feed = useMemo(
    () =>
      new LiveFeed({
        url: socketUrl,
        createSocket: (u) => new WebSocket(u) as unknown as ReturnType<ConstructorParameters<typeof LiveFeed>[0]['createSocket']>,
        loadAlerts,
        now: () => Date.now(),
        setTimer: (fn, ms) => window.setTimeout(fn, ms),
        clearTimer: (h) => window.clearTimeout(h as number),
      }),
    [],
  )
  useEffect(() => {
    if (!authed) return
    feed.start()
    return () => feed.stop()
  }, [authed, feed])

  const snapshot = useSyncExternalStore(feed.subscribe, feed.getSnapshot)

  // The server ended the session (or refused us): ask the API so the sign-in screen appears.
  useEffect(() => {
    if (snapshot.authLost) void refresh()
  }, [snapshot.authLost, refresh])

  const [reachable, setReachable] = useState(true)
  useEffect(() => onReachability(setReachable), [])
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [])

  const status = useMemo(
    () =>
      deriveStatus({
        monitor: snapshot.monitor,
        receivedAt: snapshot.receivedAt,
        feed: snapshot.feed,
        apiReachable: reachable,
        now,
        lastCaptureAt: snapshot.capturedChangedAt,
      }),
    [snapshot.monitor, snapshot.receivedAt, snapshot.capturedChangedAt, snapshot.feed, reachable, now],
  )
  const value = useMemo(() => ({ snapshot, status, now }), [snapshot, status, now])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useLive(): Live {
  const v = useContext(Ctx)
  if (!v) throw new Error('useLive outside LiveProvider')
  return v
}
