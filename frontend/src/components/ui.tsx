import type { ReactNode } from 'react'
import { ApiError } from '../api/client'
import type { Severity } from '../api/types'

const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)',
  low: 'var(--sev-low)', informational: 'var(--sev-informational)',
}
const SEV_LABEL: Record<Severity, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info',
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return (
    <span className="sev" data-sev={severity} style={{ ['--c' as string]: SEV_COLOR[severity] }}>
      {SEV_LABEL[severity]}
    </span>
  )
}
export const severityColor = (s: Severity) => SEV_COLOR[s]
export const severityLabel = (s: Severity) => SEV_LABEL[s]

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  )
}

export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof ApiError ? error.detail : 'Something went wrong. Try again.'
  return (
    <div className="notice bad" role="alert">
      {msg}{' '}
      {retry && (
        <button className="btn small" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  )
}

export function Loading({ what }: { what: string }) {
  return (
    <p className="soft" role="status">
      Loading {what}…
    </p>
  )
}
