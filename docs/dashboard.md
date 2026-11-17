# Dashboard (Phase 6)

React 19 + TypeScript + Vite, in `frontend/`. Decisions: ADR 0018. The dashboard only displays what the
API returns; it holds no secrets and stores nothing in the browser.

## Run it
```bash
make frontend-install                      # once
make run-api                               # terminal 1, http://127.0.0.1:8000
make frontend-dev                          # terminal 2, http://127.0.0.1:5173
make create-admin USERNAME=name            # once, prompts for the password
```
Open http://127.0.0.1:5173. The dev server proxies `/api` and the WebSocket to the API, so the browser sees
one origin (the session cookie is SameSite=Strict and would not work across origins). Another API address:
`NETGUARD_API_URL=http://host:port make frontend-dev`. `make frontend-test` runs the unit tests,
`make frontend-lint` and `make frontend-build` check and build.

## Pages
| Page | Who | What it does |
|---|---|---|
| Overview | everyone | open events by severity, new alerts, devices, 15-minute traffic chart, latest alerts (live), busiest sources, protocols |
| Events, event detail | everyone | filters (severity, type, status, activity, source address), newer/older paging, evidence, alert acknowledge/dismiss/reopen, investigation status, the rule version that fired |
| Rules, rule detail | everyone view, admin edit | settings, version history; only changed fields are sent |
| Users | admin | accounts (add, role, disable, reset password, unlock) and the audit log |
| Settings | everyone | read-only monitoring and security configuration; change own password; sign out on all devices |

Admin pages are hidden from analysts and refused by the server for them (see `test_api_rbac.py`).

## The header status
The header always says whether NetGuard is watching. It shows one of: monitoring (live), monitoring with
problems (reasons from the monitor), starting, not responding, has not started, live feed disconnected,
cannot reach NetGuard, connecting. Only the first two are "live". In every other state a banner explains why,
the page tint changes, and the pulse line stops moving. Rules (`frontend/src/live/status.ts`, unit-tested):
- live needs an open feed, a monitor status received in the last 20 s, and a heartbeat under 15 s old, counting
  the time since the status arrived in the browser;
- a socket that is open but silent counts as disconnected;
- the monitor's own `stale`/`stopped` states are shown as "not responding".

## Live alerts
`frontend/src/live/feed.ts` keeps one WebSocket. It reconnects with growing delays (1 s up to 15 s). After a
reconnect, a `resync`, or a `hello` reporting newer alerts, it re-reads alerts over REST from the newest id it
holds, so a gap cannot lose an alert. A session ended by the server (close code 4401) or a refused connection
(1008) is not retried; the sign-in screen appears.

## Verified in the sandbox (real API, real PostgreSQL, real lab traffic, real browser)
Login and wrong-password message; all five pages; a port scan from a new source address appeared in Latest
alerts within seconds with a highlight; killing the monitor turned the header to "Monitor is not responding"
with the banner and historical tint in under 5 s, and restarting it returned to live in 5 s; killing the API
showed "Live feed disconnected" with the banner; an analyst sees no Users item and `/users` redirects;
a 390 px wide phone viewport has no horizontal scroll. Screenshots were reviewed by eye.

## Known limits
- Settings shows the API process's own configuration. The interface comes from the running monitor, but the
  authorised network is read from the API's settings: if the monitor was started with a different value (for
  example on its command line), Settings does not show the monitor's value. Keep both in `.env`.
- Charts are drawn by hand in SVG: one traffic series, two segment bars. No zoom or custom ranges yet.
- No dark-mode toggle (follows the system setting).
- Treat colour-contrast and screen-reader behaviour as reviewed by hand, not audited with a tool.
- A production build (`make frontend-build`) must be served from the same origin as the API behind a reverse
  proxy with HTTPS; that deployment is not set up (Phase 8).

## Accessibility
Automated audit (axe-core, 36 views: every page, the login page and a dialog, light and dark, desktop and phone):
0 violations after four fixes (`docs/evaluation.md`, Phase 7). Colours are tokens in `src/styles/tokens.css`; a
new colour must keep 4.5:1 against every surface it can sit on, including the historical-data tint. Re-run:
`python lab/a11y_audit.py --axe <path to axe.min.js> --user <admin>` against a served dashboard. Not checked by
hand: keyboard-only use, screen readers, zoom reflow, reduced motion, forced colours.
