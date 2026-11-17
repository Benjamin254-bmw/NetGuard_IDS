import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, onReachability, onSessionEnded } from './client'

function respond(status: number, body?: unknown) {
  return vi.fn().mockResolvedValue(new Response(body === undefined ? null : JSON.stringify(body), {
    status, headers: body === undefined ? {} : { 'content-type': 'application/json' },
  }))
}
const sentHeaders = (f: ReturnType<typeof vi.fn>) => (f.mock.calls[0][1] as RequestInit).headers as Record<string, string>

beforeEach(() => { document.cookie = 'ng_csrf=tok%2B1; path=/' })
afterEach(() => { vi.unstubAllGlobals(); document.cookie = 'ng_csrf=; max-age=0; path=/' })

describe('api client', () => {
  it('sends the CSRF header on unsafe methods and never on reads', async () => {
    for (const method of ['POST', 'PATCH', 'DELETE', 'PUT']) {
      const f = respond(200, {}); vi.stubGlobal('fetch', f)
      await api(method, '/api/x', { body: {} })
      expect(sentHeaders(f)['X-CSRF-Token']).toBe('tok+1')
    }
    const g = respond(200, {}); vi.stubGlobal('fetch', g)
    await api('GET', '/api/x')
    expect(sentHeaders(g)['X-CSRF-Token']).toBeUndefined()
  })
  it('always sends the session cookie and only same-origin', async () => {
    const f = respond(200, {}); vi.stubGlobal('fetch', f)
    await api('GET', '/api/x')
    expect((f.mock.calls[0][1] as RequestInit).credentials).toBe('same-origin')
  })
  it('announces a lost session on 401, but not for the sign-in attempt itself', async () => {
    const ended = vi.fn(); const off = onSessionEnded(ended)
    vi.stubGlobal('fetch', respond(401, { detail: 'not authenticated' }))
    await expect(api('GET', '/api/overview')).rejects.toMatchObject({ status: 401 })
    expect(ended).toHaveBeenCalledTimes(1)
    await expect(api('GET', '/api/auth/me', { quiet401: true })).rejects.toBeInstanceOf(ApiError)
    expect(ended).toHaveBeenCalledTimes(1)
    off()
  })
  it('turns a network failure into a clear error and reports the API as unreachable', async () => {
    const seen: boolean[] = []; const off = onReachability((ok) => seen.push(ok))
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('failed')))
    await expect(api('GET', '/api/x')).rejects.toMatchObject({ status: 0, detail: expect.stringContaining('Cannot reach') })
    expect(seen).toEqual([false])
    off()
  })
  it('reports reachable after any real answer, even an error status', async () => {
    const seen: boolean[] = []; const off = onReachability((ok) => seen.push(ok))
    vi.stubGlobal('fetch', respond(403, { detail: 'no' }))
    await expect(api('GET', '/api/x')).rejects.toBeInstanceOf(ApiError)
    expect(seen).toEqual([true])
    off()
  })
  it('returns undefined for 204 and surfaces validation messages', async () => {
    vi.stubGlobal('fetch', respond(204))
    await expect(api('POST', '/api/auth/logout', { body: {} })).resolves.toBeUndefined()
    vi.stubGlobal('fetch', respond(422, { detail: [{ loc: ['body', 'threshold'], msg: 'too small' }] }))
    await expect(api('PATCH', '/api/rules/1', { body: {} })).rejects.toMatchObject({ detail: 'threshold: too small' })
  })
})
