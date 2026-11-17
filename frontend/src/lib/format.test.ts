import { describe, expect, it } from 'vitest'
import { formatBytes, timeAgo } from './format'
import { describeError, readCookie, withQuery } from '../api/client'

describe('format', () => {
  it('formats bytes in decimal units', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(999)).toBe('999 B')
    expect(formatBytes(1500)).toBe('1.5 kB')
    expect(formatBytes(12_345_678)).toBe('12.3 MB')
    expect(formatBytes(-4)).toBe('0 B')
  })
  it('describes elapsed time', () => {
    const now = Date.parse('2026-11-11T12:00:00Z')
    expect(timeAgo('2026-11-11T11:59:58Z', now)).toBe('just now')
    expect(timeAgo('2026-11-11T11:58:00Z', now)).toBe('2 min ago')
    expect(timeAgo('2026-11-10T12:00:00Z', now)).toBe('1 d ago')
  })
})
describe('api helpers', () => {
  it('reads a cookie by name and decodes it', () => {
    expect(readCookie('ng_csrf', 'a=1; ng_csrf=x%2By; b=2')).toBe('x+y')
    expect(readCookie('missing', 'a=1')).toBeNull()
  })
  it('drops empty query values and encodes the rest', () => {
    expect(withQuery('/api/x', { a: 1, b: '', c: undefined, d: 'x y', e: false })).toBe('/api/x?a=1&d=x+y&e=false')
    expect(withQuery('/api/x', {})).toBe('/api/x')
  })
  it('turns validation errors into one readable line', () => {
    expect(describeError({ detail: 'nope' }, 'f')).toBe('nope')
    expect(describeError({ detail: [{ loc: ['body', 'threshold'], msg: 'must be >= 1' }] }, 'f')).toBe('threshold: must be >= 1')
    expect(describeError(null, 'fallback')).toBe('fallback')
  })
})
