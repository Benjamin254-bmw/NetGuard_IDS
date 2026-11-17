import type { Derived } from '../live/status'

/** A heartbeat trace. It moves only while the monitor is verifiably live; otherwise it lies flat. */
export function StatusPulse({ status }: { status: Derived }) {
  const moving = status.level === 'live' || status.level === 'degraded'
  return (
    <div className="status" data-level={status.level} role="status" aria-live="polite">
      <svg viewBox="0 0 120 36" aria-hidden="true">
        {moving ? (
          <>
            <path className="trace" opacity="0.22" d="M0 18 H34 L40 18 L46 6 L54 30 L61 12 L66 18 H120" />
            <path className="trace live-trace" d="M0 18 H34 L40 18 L46 6 L54 30 L61 12 L66 18 H120" />
          </>
        ) : (
          <path className="trace flat" d="M0 18 H120" />
        )}
      </svg>
      <div className="status-text">
        <div className="status-title">{status.title}</div>
        <div className="status-detail" title={status.detail}>
          {status.detail}
        </div>
      </div>
    </div>
  )
}
