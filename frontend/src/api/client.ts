// One place that talks to the API. Rules it enforces for every call:
//  - same-origin, credentials included (the session is an HttpOnly cookie we never read);
//  - unsafe methods carry X-CSRF-Token copied from the readable ng_csrf cookie;
//  - a 401 on anything but login/me means the session ended: listeners are told once.
export class ApiError extends Error {
  readonly status: number
  readonly detail: string
  constructor(status: number, detail: string) {
    super(detail)
    this.status = status
    this.detail = detail
  }
}

type Query = Record<string, string | number | boolean | undefined | null>
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS'])
const sessionEndedListeners = new Set<() => void>()
const reachListeners = new Set<(ok: boolean) => void>()

/** Told true after any response from the API (even an error status) and false when none arrives. */
export function onReachability(fn: (ok: boolean) => void): () => void {
  reachListeners.add(fn)
  return () => reachListeners.delete(fn)
}

export function onSessionEnded(fn: () => void): () => void {
  sessionEndedListeners.add(fn)
  return () => sessionEndedListeners.delete(fn)
}

export function readCookie(name: string, source: string = document.cookie): string | null {
  for (const part of source.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    if (k === name) return decodeURIComponent(rest.join('='))
  }
  return null
}

export function withQuery(path: string, query?: Query): string {
  if (!query) return path
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') qs.set(k, String(v))
  }
  const s = qs.toString()
  return s ? `${path}?${s}` : path
}

/** Turn FastAPI error bodies (string, or a list of validation errors) into one readable line. */
export function describeError(body: unknown, fallback: string): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length > 0) {
    return detail
      .map((d: { loc?: unknown[]; msg?: string }) => {
        const where = (d.loc ?? []).filter((p) => p !== 'body' && p !== 'query').join('.')
        return where ? `${where}: ${d.msg ?? 'invalid'}` : (d.msg ?? 'invalid')
      })
      .join('; ')
  }
  return fallback
}

export async function api<T>(
  method: string,
  path: string,
  opts: { query?: Query; body?: unknown; quiet401?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (!SAFE.has(method)) {
    const csrf = readCookie('ng_csrf')
    if (csrf) headers['X-CSRF-Token'] = csrf
  }
  let res: Response
  try {
    res = await fetch(withQuery(path, opts.query), {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    })
  } catch {
    reachListeners.forEach((fn) => fn(false))
    throw new ApiError(0, 'Cannot reach the NetGuard API. Check that it is running.')
  }
  // A 502/503/504 from the dev proxy or a gateway means the API process itself is not answering.
  reachListeners.forEach((fn) => fn(![502, 503, 504].includes(res.status) || res.headers.has('content-type')))
  if (res.status === 204) return undefined as T
  let data: unknown = null
  try {
    data = await res.json()
  } catch {
    /* non-JSON body: keep null */
  }
  if (!res.ok) {
    if (res.status === 401 && !opts.quiet401) sessionEndedListeners.forEach((fn) => fn())
    throw new ApiError(res.status, describeError(data, `Request failed (${res.status}).`))
  }
  return data as T
}

export const get = <T>(path: string, query?: Query) => api<T>('GET', path, { query })
export const post = <T>(path: string, body?: unknown) => api<T>('POST', path, { body: body ?? {} })
export const patch = <T>(path: string, body: unknown) => api<T>('PATCH', path, { body })
