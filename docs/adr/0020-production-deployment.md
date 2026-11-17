# ADR 0020: Production deployment: systemd services behind nginx on one HTTPS origin

Status: accepted, 2026-11-17

## Context
Until Phase 8 NetGuard ran from a terminal: `make monitor-run` (sudo once, then the user's own account with two
capabilities), `make run-api` and the Vite dev server. That is fine for development and evaluation, but it stops
when the terminal closes, serves the dashboard over plain http, and has the developer's account hold every
database password. ADR 0005 already fixed the privilege model for deployment (dedicated user, systemd
`AmbientCapabilities`); ADRs 0016-0018 require the dashboard and API to share one origin.

## Decisions
1. **Two systemd services, two system users.** `netguard-monitor` runs as user `netguard-monitor` with
   `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` and a bounding set of exactly those two; `netguard-api` runs
   as `netguard-api` with no capabilities. Both have no shell, no home, `NoNewPrivileges`, a read-only
   filesystem (`ProtectSystem=strict`) and restricted address families. The monitor may write only its
   spill directory (`StateDirectory`, ADR 0012). Exit status 2 (the monitor refused its configuration) is
   not retried.
2. **One secrets file per service, root-only, read by systemd.** `/etc/netguard/api.env` holds only the API
   database role and a new production session secret; `/etc/netguard/monitor.env` holds only the monitor
   role and the capture settings. The migrator password stays in the developer's `.env`: migrations remain an
   administrator task. Files are mode 600 root and passed as environment by systemd, so the service users never
   read them. `NETGUARD_ENV=production` is set for the API only, because production mode requires the session
   secret, which the monitor must not hold.
3. **nginx is the only way in, over HTTPS, on one origin.** It serves the built dashboard and proxies `/api`
   (including the WebSocket) to the API on loopback. The API keeps `NETGUARD_API_HOST=127.0.0.1`.
   `NETGUARD_ALLOWED_ORIGINS` is empty in production: the only accepted origin is the dashboard's own
   `https://host`, which the API derives from the forwarded scheme and the `Host` header (nginx passes
   `$http_host` so a non-default port still matches).
4. **Forwarded headers are trusted only from loopback, and pinned in code.** uvicorn's default already trusted
   `X-Forwarded-For` from 127.0.0.1 (via `FORWARDED_ALLOW_IPS`); a docstring wrongly said it was ignored.
   `app.__main__` now states `proxy_headers=True, forwarded_allow_ips="127.0.0.1,::1"` so an environment
   variable cannot widen it, and nginx overwrites `X-Forwarded-For` with `$remote_addr` (never appends), so a
   client cannot choose the address that the login limiter and the audit log see. A local process that talks
   to the API port directly can still claim an address; on a shared machine those addresses are advisory.
5. **A self-signed certificate by default, no HSTS.** A small network seldom has a public name, so
   `deploy/make_cert.sh` issues a P-256 certificate covering the host name, `<host>.local`, localhost and the
   machine's addresses, and prints its fingerprint for comparison in the browser. HSTS is left off: with a
   self-signed certificate it would remove the browser's option to proceed. Replacing the two files with a
   trusted certificate (internal CA, or ACME where a public name exists) is documented.
6. **Content-Security-Policy for the dashboard**: `default-src 'self'`, no inline script or style, `connect-src`
   limited to the same origin and its `wss://` form; framing denied. The API keeps its own stricter headers.
7. **Installed code is a copy, not the repository.** `deploy/install.sh` builds wheels and the dashboard as the
   developer, then installs a root-owned virtualenv in `/opt/netguard/venv` and the static files in
   `/opt/netguard/www`, versions constrained by `requirements.lock`. Services cannot modify their own code.
   Re-running the installer upgrades and keeps `/etc/netguard`.
8. **The installer refuses to start a second monitor.** A development monitor writing to the same database
   would double-count traffic, so the service is enabled but not started while one runs.

## Consequences
- `deploy/verify.sh` checks what this ADR claims on the running system: loopback-only API, headers,
  TLS >= 1.2, process users and capabilities, file modes, which secrets each file holds, and that a forged
  `X-Forwarded-For` is not what the audit log records.
- The dashboard is reachable from the local network on port 443; the host firewall is left to the operator.
- One API process: the login limiter is per process (ADR 0016) and stays correct.
- Development (`make run-api`, `make frontend-dev`) is unchanged and can run beside the services (the
  production API uses port 8100); two monitors cannot.
