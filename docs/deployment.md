# Deployment (Phase 8)

How to run NetGuard as system services: the monitor and the API start at boot, and the dashboard is served
over HTTPS to the local network. Design decisions: ADR 0020 (and ADR 0005 for the privilege model).
Development (`make run-api`, `make frontend-dev`, `make monitor-run`) is unchanged.

```
browser --https:443--> nginx --+-- /            static dashboard  (/opt/netguard/www)
                               +-- /api, /api/ws  127.0.0.1:8100 --> netguard-api      (user netguard-api, no capabilities)
                                                                          |
network --AF_PACKET--> netguard-monitor (user netguard-monitor, CAP_NET_RAW+CAP_NET_ADMIN only) --> PostgreSQL
```

## Before you install
- **Authorisation.** Monitor only a network you own or are explicitly authorised to monitor.
- The development setup works on this machine: `make doctor`, `make migrate`, `make frontend-install`.
- `sudo apt install nginx` (normally present on Kali).
- PostgreSQL running and starting at boot: `sudo systemctl enable --now postgresql@18-main`
  (on Kali the cluster is disabled by default).
- Decide what the monitor watches. The installer copies `NETGUARD_MONITOR_INTERFACE`,
  `NETGUARD_AUTHORIZED_SUBNET` and the other monitor settings from your `.env`; for the lab that is `br-lab`,
  which disappears at reboot (`make lab-up` recreates it). For a real network use its interface (for example
  `eth0`) and subnet, and set `NETGUARD_PROMISCUOUS=true` only on a mirror/SPAN port or bridge.
- Stop a development monitor first (Ctrl-C in its terminal), or the installer will not start the service.

## Install
```bash
make deploy-install        # = sudo deploy/install.sh   (options: --api-port N, --no-monitor)
```
It migrates the database, builds the dashboard and wheels as you, then as root: creates the users
`netguard-api` and `netguard-monitor`, installs `/opt/netguard`, writes `/etc/netguard/{api,monitor}.env`
(only if absent), issues a self-signed certificate in `/etc/netguard/tls/`, installs the nginx site and the
two systemd units, starts them, and runs the checks below. Re-run it to upgrade; `/etc/netguard` is kept.

Open `https://<this machine>/` (or `https://kali.local/`). The browser warns about the self-signed
certificate: compare the SHA-256 fingerprint the installer printed with the one the browser shows before
continuing. Sign in with an existing dashboard account; create one with `make create-admin USERNAME=name`.

## Check it
```bash
make deploy-verify         # = sudo deploy/verify.sh
```
It checks: the three services run; the API listens on loopback only; readiness through nginx; the dashboard's
security headers; client-side routes; TLS 1.1 refused; the monitor runs non-root with exactly CAP_NET_RAW and
CAP_NET_ADMIN and the API with none; secrets files and the TLS key are root-only and each holds only its own
service's secrets; and that a forged `X-Forwarded-For` is not what the audit log records (this makes one
failed sign-in for a made-up user name, visible in the audit log as `verify-...`).

## Operate
| task | command |
|---|---|
| status / logs | `systemctl status netguard-monitor netguard-api`, `journalctl -u netguard-monitor -f` |
| change monitor settings | `sudo nano /etc/netguard/monitor.env`, then `sudo systemctl restart netguard-monitor` |
| restart / stop | `sudo systemctl restart netguard-api`, `sudo systemctl stop netguard-monitor` |
| sign everybody out | replace `NETGUARD_SECRET_KEY` in `/etc/netguard/api.env`, restart the API |
| upgrade | `git pull` (or copy), `make deploy-install` |
| remove | `make deploy-remove` (keeps `/etc/netguard`, users, database); `sudo deploy/uninstall.sh --purge` removes those too, except the database |

Stopping the monitor drains its queues first (up to 60 s). If the monitor refuses its configuration (exit
status 2: interface missing, no subnet, ...) systemd does not retry; `journalctl -u netguard-monitor` says why.
The dashboard header shows "no packets" when the monitor runs but its packet count has not moved for two
minutes: on a real network that usually means the wrong interface or promiscuous mode is off.

## Auth-log rule (optional)
The `auth_failures` rule reads the sshd log (ADR 0014). Kali has no `/var/log/auth.log` unless rsyslog is
installed. With it: set `NETGUARD_AUTH_LOG_PATH="/var/log/auth.log"` in `/etc/netguard/monitor.env`, uncomment
`SupplementaryGroups=adm` with `sudo systemctl edit --full netguard-monitor`, and restart.

## A certificate the browsers trust
Replace `/etc/netguard/tls/netguard.crt` and `netguard.key` (key mode 600, root), then
`sudo systemctl reload nginx`. Only then consider adding
`add_header Strict-Transport-Security "max-age=31536000" always;` to the site.

## Files
| path | what | owner, mode |
|---|---|---|
| `/opt/netguard/venv`, `/opt/netguard/www` | installed code and dashboard | root, read-only to services |
| `/etc/netguard/api.env`, `monitor.env` | per-service settings and secrets | root, 600 |
| `/etc/netguard/tls/` | certificate and key | root, key 600 |
| `/var/lib/netguard-monitor/spill` | spill files during a database outage | netguard-monitor, 700 |
| `/etc/nginx/sites-available/netguard` | the HTTPS site | root |
| `/etc/systemd/system/netguard-*.service` | the units | root |

## Known limits
- The firewall is not configured: the dashboard is reachable on 443 from every network this machine is on.
- A local process can talk to the API port directly and claim any client address (ADR 0020).
- One machine: the database, API, monitor and nginx are on the same host. Remote PostgreSQL is possible
  through the `NETGUARD_DB_*` settings but untested.
- No automatic database backups; use `pg_dump netguard` from cron if the data matters.
