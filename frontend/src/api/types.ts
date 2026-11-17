// Shapes returned by the API (docs/api.md). Kept by hand and small on purpose.
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type EventStatus = 'new' | 'investigating' | 'resolved' | 'false_positive'
export type AlertStatus = 'new' | 'acknowledged' | 'dismissed'
export type Category =
  | 'port_scan'
  | 'excessive_connections'
  | 'auth_failures'
  | 'abnormal_traffic'
  | 'suspicious_dns'
export type Role = 'admin' | 'analyst'

export interface User {
  id: number
  username: string
  email: string | null
  role: Role
  is_active: boolean
  created_at: string | null
  last_login_at: string | null
  locked: boolean
}
export interface SessionOut {
  user: User
}

export interface MonitorStatus {
  state: 'stopped' | 'starting' | 'running' | 'degraded' | 'never_started'
  effective_state: 'stopped' | 'starting' | 'running' | 'degraded' | 'never_started' | 'stale'
  interface?: string | null
  started_at?: string | null
  heartbeat_at?: string
  heartbeat_age_seconds?: number
  packets_captured?: number
  packets_dropped?: number
  packets_per_second?: number
  capture_queue_depth?: number
  write_queue_depth?: number
  spill_backlog?: number
  degraded_reasons?: string[]
  last_error?: string | null
  version?: string | null
}

export interface Overview {
  generated_at: string
  monitor: MonitorStatus
  open_events_by_severity: Partial<Record<Severity, number>>
  events_24h_by_category: Partial<Record<Category, number>>
  alerts: { new: number; total: number }
  devices: { active: number; inactive: number }
  traffic_last_5m: { packets: number; bytes: number }
}

export interface Alert {
  id: number
  event_id: number
  severity: Severity
  title: string
  created_at: string
  status: AlertStatus
  acknowledged_by: number | null
  acknowledged_at: string | null
  category: Category
  src_ip: string
}
export interface SecurityEvent {
  id: number
  event_uuid: string
  category: Category
  rule_id: number
  rule_version: number
  severity: Severity
  src_ip: string
  dst_ip: string | null
  dst_port: number | null
  protocol: string | null
  description: string
  is_open: boolean
  hit_count: number
  detected_at: string
  last_seen_at: string
  status: EventStatus
  status_updated_at: string | null
  status_updated_by: number | null
}
export interface RuleSnapshot {
  rule_id: number
  version: number
  key: string
  name: string
  enabled: boolean
  severity: Severity
  threshold: number
  window_seconds: number
  cooldown_seconds: number
  params: Record<string, unknown>
  changed_at: string
}
export interface EventDetail extends SecurityEvent {
  evidence: Record<string, unknown>
  dedup_key: string
  alerts: Omit<Alert, 'category' | 'src_ip' | 'event_id'>[]
  rule_snapshot: RuleSnapshot | null
}
export interface Page<T> {
  items: T[]
  next_before_id: number | null
}

export interface Rule {
  id: number
  key: string
  name: string
  category: Category
  description: string
  enabled: boolean
  severity: Severity
  threshold: number
  window_seconds: number
  cooldown_seconds: number
  params: Record<string, unknown>
  version: number
  updated_at: string
  updated_by: number | null
}
export interface RuleVersion {
  version: number
  enabled: boolean
  severity: Severity
  threshold: number
  window_seconds: number
  cooldown_seconds: number
  params: Record<string, unknown>
  changed_by: number | null
  changed_at: string
}
export interface RuleDetail extends Rule {
  versions: RuleVersion[]
}

export interface Device {
  id: number
  ip: string
  mac: string | null
  hostname: string | null
  status: 'active' | 'inactive'
  discovery_source: string
  first_seen: string
  last_seen: string
}
export interface TrafficPoint {
  t: string
  packets: number
  bytes: number
  new_connections: number
}
export interface TrafficSeries {
  from: string
  to: string
  bucket_seconds: number
  points: TrafficPoint[]
}
export interface ProtocolRow {
  protocol: string
  packets: number
  bytes: number
}
export interface Talker {
  ip: string
  bytes: number
  packets: number
  flows: number
}
export interface AuditEntry {
  id: number
  occurred_at: string
  actor_type: string
  actor_user_id: number | null
  action: string
  target_type: string | null
  target_id: string | null
  source_ip: string | null
  details: Record<string, unknown>
}
export interface SystemInfo {
  api_version: string
  environment: string
  monitor_version: string | null
  monitored_interface: string | null
  authorized_subnet: string | null
  retention_per_second_hours: number
  retention_per_minute_days: number
  rules_reload_seconds: number
  session_ttl_minutes: number
  cookies_secure: boolean
  allowed_origins: string[]
}

export type LiveMessage =
  | { type: 'hello'; last_alert_id: number; server_time: string }
  | { type: 'alert'; alert: Alert }
  | { type: 'monitor'; status: MonitorStatus }
  | { type: 'resync' }
  | { type: 'pong' }
