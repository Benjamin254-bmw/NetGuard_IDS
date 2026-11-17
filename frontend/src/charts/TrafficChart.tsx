import { useMemo } from 'react'
import type { TrafficPoint } from '../api/types'
import { formatBytes } from '../lib/format'
import { areaPath, niceCeil } from './scale'
import { useWidth } from './useWidth'

const H = 190
const PAD = { top: 12, right: 12, bottom: 24, left: 62 }

/** Bytes per second over time. Gaps in the data are drawn as gaps, not interpolated across. */
export function TrafficChart({ points, bucketSeconds, from, to }: { points: TrafficPoint[]; bucketSeconds: number; from: string; to: string }) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const t0 = Date.parse(from)
  const t1 = Date.parse(to)
  const innerW = width - PAD.left - PAD.right
  const innerH = H - PAD.top - PAD.bottom

  const model = useMemo(() => {
    const rates = points.map((p) => ({ t: Date.parse(p.t), v: p.bytes / bucketSeconds }))
    const max = niceCeil(Math.max(0, ...rates.map((r) => r.v)))
    const x = (t: number) => PAD.left + ((t - t0) / Math.max(1, t1 - t0)) * innerW
    const y = (v: number) => PAD.top + innerH - (v / max) * innerH
    // split into runs so a missing bucket breaks the line
    const runs: { x: number; y: number }[][] = []
    let run: { x: number; y: number }[] = []
    let prev: number | null = null
    for (const r of rates) {
      if (prev !== null && r.t - prev > bucketSeconds * 1500) {
        if (run.length) runs.push(run)
        run = []
      }
      run.push({ x: x(r.t), y: y(r.v) })
      prev = r.t
    }
    if (run.length) runs.push(run)
    const peak = rates.reduce((m, r) => Math.max(m, r.v), 0)
    return { max, runs, y, peak, latest: rates.at(-1)?.v ?? 0 }
  }, [points, bucketSeconds, t0, t1, innerW, innerH])

  const fmtT = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
  const summary = points.length
    ? `Traffic from ${fmtT(t0)} to ${fmtT(t1)}. Peak ${formatBytes(model.peak)} per second, latest ${formatBytes(model.latest)} per second.`
    : `No traffic recorded from ${fmtT(t0)} to ${fmtT(t1)}.`

  return (
    <div ref={ref} className="chart">
      <svg width={width} height={H} role="img" aria-label={summary}>
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={PAD.left} x2={width - PAD.right} y1={model.y(model.max * f)} y2={model.y(model.max * f)} stroke="var(--line)" />
            <text x={PAD.left - 8} y={model.y(model.max * f) + 4} textAnchor="end" fontSize="12" fill="var(--ink-soft)">
              {formatBytes(model.max * f)}/s
            </text>
          </g>
        ))}
        {model.runs.map((run, i) => {
          const { line, area } = areaPath(run, PAD.top + innerH)
          return (
            <g key={i}>
              <path d={area} fill="var(--sea)" opacity="0.14" />
              <path d={line} fill="none" stroke="var(--sea)" strokeWidth="2" strokeLinejoin="round" />
              {run.length === 1 && <circle cx={run[0].x} cy={run[0].y} r="2.5" fill="var(--sea)" />}
            </g>
          )
        })}
        <text x={PAD.left} y={H - 6} fontSize="12" fill="var(--ink-soft)">{fmtT(t0)}</text>
        <text x={width - PAD.right} y={H - 6} fontSize="12" textAnchor="end" fill="var(--ink-soft)">{fmtT(t1)}</text>
        {points.length === 0 && (
          <text x={PAD.left + innerW / 2} y={PAD.top + innerH / 2} textAnchor="middle" fontSize="14" fill="var(--ink-soft)">
            No traffic recorded in this period
          </text>
        )}
      </svg>
    </div>
  )
}
