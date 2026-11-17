/** Round a maximum up to a tidy axis ceiling (1, 2, 2.5, 5 x 10^n). */
export function niceCeil(v: number): number {
  if (!(v > 0)) return 1
  const exp = Math.floor(Math.log10(v))
  const base = 10 ** exp
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * base) return m * base
  return 10 * base
}

export interface Point {
  x: number
  y: number
}
export function areaPath(points: Point[], baseline: number): { line: string; area: string } {
  if (points.length === 0) return { line: '', area: '' }
  const line = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
  const first = points[0]
  const last = points[points.length - 1]
  return { line, area: `${line} L${last.x.toFixed(1)} ${baseline} L${first.x.toFixed(1)} ${baseline} Z` }
}

export interface Segment {
  key: string
  value: number
  color: string
  label: string
}
/** Widths in percent that always sum to 100 (or all zero when there is nothing to show). */
export function proportions(segments: Segment[]): number[] {
  const total = segments.reduce((a, s) => a + s.value, 0)
  if (total <= 0) return segments.map(() => 0)
  return segments.map((s) => (s.value / total) * 100)
}
