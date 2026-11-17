import { formatCount } from '../lib/format'
import { proportions, type Segment } from './scale'

/** One horizontal bar split by share, with a legend that carries the exact numbers. */
export function SegmentBar({ segments, unit, emptyText }: { segments: Segment[]; unit: string; emptyText: string }) {
  const widths = proportions(segments)
  const total = segments.reduce((a, s) => a + s.value, 0)
  return (
    <div>
      {total === 0 ? (
        <p className="soft">{emptyText}</p>
      ) : (
        <div className="segbar" role="img" aria-label={segments.filter((s) => s.value > 0).map((s) => `${s.label} ${formatCount(s.value)} ${unit}`).join(', ')}>
          {segments.map((s, i) => widths[i] > 0 && <span key={s.key} style={{ width: `${widths[i]}%`, background: s.color }} />)}
        </div>
      )}
      <ul className="legend">
        {segments.map((s) => (
          <li key={s.key} data-zero={s.value === 0 || undefined}>
            <i style={{ background: s.color }} aria-hidden="true" />
            <span>{s.label}</span>
            <b className="num">{formatCount(s.value)}</b>
          </li>
        ))}
      </ul>
    </div>
  )
}
