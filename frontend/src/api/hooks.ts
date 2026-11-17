import { get, patch, post } from './client'
import type {
  Alert, AuditEntry, Device, EventDetail, EventStatus, AlertStatus, Overview, Page, ProtocolRow,
  Rule, RuleDetail, SecurityEvent, SessionOut, SystemInfo, Talker, TrafficSeries, User, MonitorStatus,
} from './types'

export const keys = {
  overview: ['overview'] as const,
  traffic: (bucket: number, minutes: number) => ['traffic', bucket, minutes] as const,
}

export const fetchMe = () => get<SessionOut>('/api/auth/me')
export const login = (username: string, password: string) =>
  post<SessionOut>('/api/auth/login', { username, password })
export const logout = () => post<void>('/api/auth/logout')

export const fetchOverview = () => get<Overview>('/api/overview')
export const fetchMonitor = () => get<MonitorStatus>('/api/monitor/status')
export const fetchDevices = () => get<{ items: Device[]; total: number }>('/api/devices', { limit: 200 })
export const fetchSystemInfo = () => get<SystemInfo>('/api/system/info')

export async function fetchTraffic(bucket: number, minutes: number): Promise<TrafficSeries> {
  const to = new Date()
  const from = new Date(to.getTime() - minutes * 60_000)
  const raw = await get<{ from: string; to: string; bucket_seconds: number; points: { t: string; packets: number; bytes: number; new_connections: number }[] }>(
    '/api/traffic/series',
    { from: from.toISOString(), to: to.toISOString(), bucket },
  )
  return raw
}
export const fetchProtocols = (minutes: number) => {
  const to = new Date()
  return get<{ items: ProtocolRow[] }>('/api/traffic/protocols', {
    from: new Date(to.getTime() - minutes * 60_000).toISOString(),
    to: to.toISOString(),
  })
}
export const fetchTalkers = (minutes: number, by: 'bytes' | 'packets' = 'bytes') => {
  const to = new Date()
  return get<{ items: Talker[] }>('/api/traffic/top-talkers', {
    from: new Date(to.getTime() - minutes * 60_000).toISOString(),
    to: to.toISOString(),
    by,
    limit: 8,
  })
}

export interface EventFilters {
  severity?: string
  category?: string
  status?: string
  is_open?: string
  src_ip?: string
  before_id?: number
}
export const fetchEvents = (f: EventFilters) =>
  get<Page<SecurityEvent>>('/api/events', { ...f, limit: 25 })
export const fetchEvent = (id: number) => get<EventDetail>(`/api/events/${id}`)
export const setEventStatus = (id: number, status: EventStatus) =>
  patch<SecurityEvent>(`/api/events/${id}`, { status })
export const setAlertStatus = (id: number, status: AlertStatus) =>
  patch<Alert>(`/api/alerts/${id}`, { status })

/** Alerts newer than afterId (following pages until caught up), or the latest page without one. */
export async function loadAlerts(afterId?: number): Promise<Alert[]> {
  if (afterId === undefined) return (await get<Page<Alert>>('/api/alerts', { limit: 30 })).items
  const out: Alert[] = []
  let cursor = afterId
  for (let i = 0; i < 5; i++) {
    const r = await get<Page<Alert> & { has_more_newer?: boolean }>('/api/alerts', { after_id: cursor, limit: 200 })
    out.push(...r.items)
    if (!r.has_more_newer || r.items.length === 0) break
    cursor = Math.max(...r.items.map((a) => a.id))
  }
  return out
}

export const fetchRules = () => get<{ items: Rule[] }>('/api/rules')
export const fetchRule = (id: number) => get<RuleDetail>(`/api/rules/${id}`)
export const patchRule = (id: number, body: Record<string, unknown>) => patch<Rule>(`/api/rules/${id}`, body)

export const fetchUsers = () => get<User[]>('/api/users')
export const createUser = (b: { username: string; password: string; role: string; email?: string }) =>
  post<User>('/api/users', b)
export const patchUser = (id: number, b: Record<string, unknown>) => patch<User>(`/api/users/${id}`, b)
export const resetPassword = (id: number, new_password: string) =>
  post<void>(`/api/users/${id}/reset-password`, { new_password })
export const unlockUser = (id: number) => post<void>(`/api/users/${id}/unlock`)
export const changePassword = (current_password: string, new_password: string) =>
  post<SessionOut>('/api/auth/change-password', { current_password, new_password })
export const logoutAll = () => post<void>('/api/auth/logout-all')
export const fetchAudit = (before_id?: number, action?: string) =>
  get<Page<AuditEntry>>('/api/audit-logs', { limit: 25, before_id, action })
