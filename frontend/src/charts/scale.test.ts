import { describe, expect, it } from 'vitest'
import { areaPath, niceCeil, proportions } from './scale'

describe('chart helpers', () => {
  it('rounds axis maxima up to tidy numbers and never to zero', () => {
    expect(niceCeil(0)).toBe(1)
    expect(niceCeil(0.7)).toBe(1)
    expect(niceCeil(1)).toBe(1)
    expect(niceCeil(1.2)).toBe(2)
    expect(niceCeil(4100)).toBe(5000)
    expect(niceCeil(23_000)).toBe(25_000)
    expect(niceCeil(99)).toBe(100)
  })
  it('builds a closed area under the line', () => {
    const { line, area } = areaPath([{ x: 0, y: 10 }, { x: 5, y: 2 }], 20)
    expect(line).toBe('M0.0 10.0 L5.0 2.0')
    expect(area).toBe('M0.0 10.0 L5.0 2.0 L5.0 20 L0.0 20 Z')
    expect(areaPath([], 20)).toEqual({ line: '', area: '' })
  })
  it('computes proportions that sum to 100, or zeros for no data', () => {
    const segs = [
      { key: 'a', value: 1, color: '', label: '' },
      { key: 'b', value: 3, color: '', label: '' },
    ]
    expect(proportions(segs)).toEqual([25, 75])
    expect(proportions(segs.map((s) => ({ ...s, value: 0 })))).toEqual([0, 0])
  })
})
