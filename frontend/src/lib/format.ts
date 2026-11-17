export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '0 B'
  const units = ['B', 'kB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i += 1
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}
export function formatCount(n: number): string {
  return new Intl.NumberFormat('en').format(n)
}
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return 'unknown'
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}
export function timeAgo(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000))
  if (s < 5) return 'just now'
  if (s < 60) return `${s} s ago`
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}
export const CATEGORY_LABEL: Record<string, string> = {
  port_scan: 'Port scan',
  excessive_connections: 'Excessive connections',
  auth_failures: 'Failed sign-ins',
  abnormal_traffic: 'Abnormal traffic',
  suspicious_dns: 'Suspicious DNS',
}
export const STATUS_LABEL: Record<string, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False positive',
  acknowledged: 'Acknowledged',
  dismissed: 'Dismissed',
}
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const
