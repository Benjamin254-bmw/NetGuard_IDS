# API reference (Phase 5)

Base path `/api`. JSON in, JSON out. Interactive docs (`/docs`) exist only when `NETGUARD_ENV` is not
`production`. The API runs as an unprivileged user and connects to PostgreSQL as the `api` role (see
ADR 0005 / `docs/database-schema.md` for what that role may touch).

Run: `make run-api` (host/port from `NETGUARD_API_HOST` / `NETGUARD_API_PORT`, default 127.0.0.1:8000).
In production it runs as the `netguard-api` service behind nginx on one HTTPS origin (`docs/deployment.md`).

**Client addresses.** The login limiter and the audit log use the client address. `X-Forwarded-For` and
`X-Forwarded-Proto` are honoured only from loopback (the local nginx, which overwrites them); this is pinned in
`app/__main__.py` (ADR 0020). A remote peer cannot set its address; a local process on the API port can.
First user: `make create-admin USERNAME=name` (password is prompted for, never on the command line).

## Authentication
- `POST /api/auth/login` `{username, password}` sets two cookies: `ng_session` (HttpOnly, SameSite=Strict,
  Path=/api, Secure when served over https) and `ng_csrf` (readable by the dashboard script).
- Every unsafe request (POST/PATCH/PUT/DELETE) must send `X-CSRF-Token` equal to the `ng_csrf` cookie, and,
  if the browser sends `Origin`, it must be the API's own origin or one of `NETGUARD_ALLOWED_ORIGINS`.
- Role, active flag and session version are re-read from the database on every request. A role change,
  deactivation, password change/reset, or "log out everywhere" invalidates existing sessions immediately.
- Sessions are 30 minutes (`NETGUARD_SESSION_TTL_MINUTES`) and renew while in use.
- Failed logins return one identical 401 whatever the cause (unknown user, wrong password, locked,
  inactive). Five consecutive failures lock the account for 15 minutes; 20 failures per source address in
  5 minutes returns 429.

| Method | Path | Who | Notes |
|---|---|---|---|
| POST | /auth/login | public | |
| GET | /auth/me | any user | |
| POST | /auth/logout | any user | this session only |
| POST | /auth/logout-all | any user | bumps session version |
| POST | /auth/change-password | any user | needs current password; wrong current password counts toward lockout |

## Users (admin only)
`GET /users`, `POST /users`, `PATCH /users/{id}` (role, is_active, email), `POST /users/{id}/reset-password`,
`POST /users/{id}/unlock`. The last active administrator cannot be demoted or deactivated (checked under a
row lock, so two concurrent requests cannot remove both).

## Monitoring data (any signed-in user)
| Path | Notes |
|---|---|
| GET /overview | open events by severity, 24 h events by category, alert counts, devices, last 5 min traffic, monitor status |
| GET /system/info | read-only configuration for the Settings page (interface, subnet, retention, reload interval, session length, versions, allowed origins); never secrets or credentials |
| GET /monitor/status | stored state plus `effective_state`; `stale` when the heartbeat is older than 15 s (a silent monitor is never shown as healthy) |
| GET /devices | `status`, `limit` (1-500), `offset` |
| GET /traffic/series | `from`, `to`, `bucket` in {1,5,10,30,60,300} s; at most 24 h and 2000 points |
| GET /traffic/protocols | `from`, `to` (max 24 h) |
| GET /traffic/top-talkers | `from`, `to` (max 30 d), `by` bytes/packets, `direction` src/dst, `limit` 1-50 |
| GET /events | filters `severity`, `category`, `status`, `is_open`, `src_ip` (IPv4), `from`, `to`; keyset pagination |
| GET /events/{id} | evidence, alerts, and the rule exactly as it was when the event fired (`rule_snapshot`) |
| GET /alerts | filters `status`, `severity`; keyset pagination |
| GET /rules, /rules/{id} | detail includes the full version history |

**Pagination.** Lists are newest first. `limit` is 1-200. The response has `next_before_id`; pass it as
`before_id` for the next page (it is `null` on the last page). `after_id` returns rows newer than an id
(oldest-first read, returned newest-first) and is how a client catches up after a disconnect. Using both is
a 422. Keyset paging does not skip or repeat rows when new events arrive.

## Changes (audited)
| Path | Who | Effect |
|---|---|---|
| PATCH /events/{id} `{status}` | any user | new / investigating / resolved / false_positive |
| PATCH /alerts/{id} `{status}` | any user | acknowledged / dismissed record who and when; `new` reopens |
| PATCH /rules/{id} | admin | `enabled, severity, threshold, window_seconds, cooldown_seconds, params` |

Rule changes: bounds are enforced (threshold >= 1, window 1-3600 s, cooldown 0-86400 s). `params` may only
contain keys the rule already has, with the same type (number, string, list of at most 100 short strings,
boolean) and a sane range; unknown keys are refused so a typo cannot silently do nothing. A change creates a
new rule version (database trigger) and an audit row with before/after; a patch that changes nothing creates
neither. The monitor picks the change up within `NETGUARD_RULES_RELOAD_SECONDS`.

`GET /audit-logs` (admin): filters `action`, `actor_user_id`, `before_id`, `limit`.

## WebSocket `/api/ws`
Same cookie and Origin rules as the REST API; a missing or invalid session is refused at the handshake.
Messages are JSON.

| `type` | When | Payload |
|---|---|---|
| `hello` | on connect | `last_alert_id`, `server_time` |
| `alert` | a new alert was committed | `alert` (same shape as `GET /alerts` items) |
| `monitor` | every 5 s while clients are connected | `status` (same as `/monitor/status`) |
| `resync` | the server may have missed notifications | client should call `GET /alerts?after_id=<last seen>` |
| `pong` | reply to the text message `ping` | |

Delivery model: the monitor commits an alert and sends `NOTIFY ids_alerts` with only the alert id; the API
reads the row and pushes it. NOTIFY is transient, so live delivery is best-effort and **the database is the
record**: after any reconnect the dashboard backfills with `after_id` starting from its last seen id (or
`last_alert_id` from `hello`). Each client has a queue of 100 messages; a client that cannot keep up is
closed (code 1013) rather than buffered without limit. Sessions are re-checked every 15 s and the socket is
closed with code 4401 when the session has ended.

## Errors
`401` not authenticated, `403` forbidden / CSRF / origin, `404`, `409` conflict, `422` validation,
`429` too many failed logins, `503` database unavailable. Error bodies contain `detail` only; no stack
traces, SQL, or internal names.
