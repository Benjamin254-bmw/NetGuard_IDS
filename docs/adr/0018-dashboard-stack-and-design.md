# ADR 0018: Dashboard stack and design rules
Status: accepted. Supersedes the dependency list in ADR 0006 (decided after Gate A, as planned).

**Stack.** React 19 + TypeScript + Vite, React Router, TanStack Query for fetching/caching. Not adopted
from the ADR 0006 list: Tailwind (plain CSS with design tokens is enough for five pages and removes a
build plugin), Zustand (the only shared client state is auth and the live feed; both are small stores
read with `useSyncExternalStore`/context), Recharts and Radix (three charts are drawn as plain SVG,
which keeps the dependency tree short and the charts readable by screen readers). Fewer packages is
also fewer things to audit in a security tool.

**Self-hosted fonts.** Fonts come from `@fontsource` packages bundled by Vite. The dashboard makes no
request to any third-party host, so it works on an isolated lab network and leaks nothing.

**Same origin.** The dashboard and API are one origin (the Vite dev server proxies `/api` and the
WebSocket). The session cookie is SameSite=Strict, so cross-origin deployment would not work by
accident and CORS is not enabled anywhere.

**The server decides, the UI mirrors.** Pages for admin functions are hidden from analysts, but every
admin API route is already refused for analysts (tested in `test_api_rbac.py`). Hiding is convenience,
not security.

**Truthful status.** The header never shows a green "monitoring" state unless the live feed is open,
a monitor status arrived within 20 seconds, and the heartbeat (age reported by the server plus time
since it arrived) is under 15 seconds. Otherwise the whole page is marked as historical. See
`frontend/src/live/status.ts`; the rules are unit-tested.

**No secrets in the browser.** The session token is HttpOnly and never read by script. Only the CSRF
value (a cookie meant to be readable) is read, to send in `X-CSRF-Token`. Nothing is stored in
localStorage.

**Rendering untrusted text.** Event descriptions, evidence, DNS names and usernames can contain
attacker-controlled text. React escapes text by default; the dashboard never uses
`dangerouslySetInnerHTML`, and values shown from evidence are rendered as text.
