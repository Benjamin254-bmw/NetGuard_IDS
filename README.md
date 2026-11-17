# NetGuard IDS

Lightweight network monitoring and rule-based intrusion detection for small networks
(fourth-year Computer Technology project). Defensive tool: monitor only networks you own or are
explicitly authorised to monitor.

**Status: Phases 1-4 built; the evaluation (Phase 4B) was reproduced on Kali and Gate A passed on 2026-11-11 (see docs/evaluation.md). Phase 5 (API, authentication, WebSocket) is built and verified on Kali. The dashboard (Phase 6) is built and verified on Kali (`docs/dashboard.md`). Phase 7 measurement tools (end-to-end latency, whole-stack cost, API at scale, accessibility audit, parser benchmark) are built and run in the sandbox; on Kali the parser benchmark is recorded and the other runs are pending (`docs/evaluation.md`). Phase 8 (deployment as systemd services behind nginx on HTTPS, `docs/deployment.md`) is built; its install on Kali is pending.**
See `docs/CHECKLIST.md` for exactly what is and is not done.

## Layout
| Path | Purpose |
|---|---|
| `shared/netguard_common` | Settings, logging, DB engine/diagnostics shared by API and monitor |
| `backend/app` | FastAPI API: auth, users, monitoring data, rules, WebSocket (`docs/api.md`) |
| `monitor/netguard_monitor` | Monitoring service: capture, discovery, detection rules (`docs/monitor.md`) |
| `frontend` | React + TypeScript dashboard (`docs/dashboard.md`) |
| `lab/` | Isolated test lab (`setup_lab.sh`), evaluation and measurement harnesses |
| `deploy/` | Production install: systemd units, nginx HTTPS site, install/verify/remove scripts (`docs/deployment.md`) |
| `scripts/` | `init_env.sh`, `db_init.sh`, `run-with-caps.sh` |
| `docs/adr` | Architecture decision records |

## Setup on Kali / Debian
```bash
sudo apt install -y make iputils-ping iproute2 tcpdump   # normally already present on Kali
sudo apt install -y nmap sshpass openssh-server          # detection demo: real scans and a real sshd
sudo systemctl disable --now ssh                         # the lab runs its OWN sshd inside the namespace; keep the system one off
sudo apt install -y iperf3 hping3 bind9-dnsutils         # used by the evaluation harness (Phase 4B)
# iperf3 asks 'Start Iperf3 as a daemon automatically?' -> answer NO (the lab runs it inside a namespace).
# Do NOT run a bare 'apt install python3-venv' on a stale Kali: it can trigger a large partial upgrade
# (python3 -> 3.14). Only install it if 'python3 -m venv' fails.
make setup            # creates .venv, installs Python dependencies
make init-env         # creates .env (mode 600) with generated secrets; never overwrites
make db-init          # creates DBs 'netguard' and 'netguard_test' + 3 least-privilege roles (sudo -u postgres)
make check-db         # each role connects; shows locale provider and collation status
make test             # unit tests
make migrate          # create tables, triggers and grants in the development database
make migrate-check    # fails if the models and migrations have drifted apart
make test-integration # schema, trigger and privilege tests against the '_test' database (needs make db-init)
make lab-up && make lab-verify   # build the 10.10.10.0/24 lab and verify it end to end
make lab-down
make frontend-install && make frontend-build
```
Requires PostgreSQL >= 15 running locally (developed against 18) and internet access for pip/npm.

## Monitor (Phase 3)
Operations guide: `docs/monitor.md`. Design decisions: ADRs 0011 (capture) and 0012 (delivery guarantees).
```bash
make lab-up                  # isolated lab; then set NETGUARD_MONITOR_INTERFACE=br-lab,
                             # NETGUARD_AUTHORIZED_SUBNET=10.10.10.0/24 and NETGUARD_PROMISCUOUS=true in .env
                             # (the bridge only delivers lab-to-lab traffic to a promiscuous listener)
make monitor-check           # what would be refused, and why (needs sudo; runs as you, not root)
make monitor-run             # start monitoring; Ctrl-C drains everything before stopping
make test-capture            # capture + service tests under CAP_NET_RAW/NET_ADMIN only
make verify-capture          # THE GATE: monitor vs tcpdump vs known counts vs nmap (needs lab-up)
make verify-capture-active   # same, with active ARP discovery
```
The monitor refuses to start unless the interface and authorised subnet are set explicitly.
Do not monitor `lo` outside tests (it would capture its own database connection).

## Evaluation (Phase 4B)
`make eval-plan`, `eval-reset`, `eval-smoke`, `eval-tuning`, then `lab/evaluate.py freeze --tuning-run DIR`, `eval-evaluation`, `eval-capacity`. Method and results: `docs/evaluation.md`, ADR 0015.

## Detection (Phase 4A)
Rule specifications and known limits: `docs/detection-rules.md`. Decisions: ADRs 0013 (event lifecycle),
0014 (auth log source). Five rules (port scan, excessive connections, repeated auth failures,
abnormal traffic volume, suspicious DNS) write deduplicated events and alerts; thresholds live in the
`detection_rules` table and changes apply to the running monitor within `NETGUARD_RULES_RELOAD_SECONDS`.
```bash
make verify-detection            # THE DEMO: benign traffic -> 0 events; real nmap/flood/DNS/volume/ssh attacks
                                 # -> exactly 7 events, alerts, escalation, rule versions, latency, 0 drops
make verify-detection-standin    # same, but failed-login lines are appended to the log (labelled stand-in)
```
For `auth_failures` set `NETGUARD_AUTH_LOG_PATH` (e.g. `/var/log/auth.log`); the monitor user must be
able to read it. Without it that rule is idle and the monitor reports `auth_log_unavailable` only if a
path is set but unreadable.

## Database
Schema reference (generated): `docs/database-schema.md`. Decisions: ADRs 0003, 0007-0010.
Integration tests only ever touch `<name>_test`; they empty its tables between tests. To change the
schema: edit `shared/netguard_common/models.py`, run `make migration m="what changed"`, review the
generated file, add grants for new tables in `grants.py`, then `make migrate` and `make test-integration`.

## Roles and privileges
Three DB roles: `netguard_migrator` (owns schema, runs migrations), `netguard_monitor`,
`netguard_api`. The monitor must never run as root. Use capabilities:
```bash
sudo scripts/run-with-caps.sh .venv/bin/python -m netguard_monitor.main check
```
This runs the command as **your** user holding only `CAP_NET_RAW` and `CAP_NET_ADMIN`.
For deployment `make deploy-install` creates a dedicated user and a systemd unit with `AmbientCapabilities` (Phase 8, `docs/deployment.md`).
Lab setup (`lab/setup_lab.sh`) needs root once to create interfaces; the monitor does not.

## Lab safety
The lab is a local bridge (`br-lab`, 10.10.10.0/24) with three namespaces (`ng-victim` .10,
`ng-normal` .20, `ng-attacker` .30). It has no uplink, no NAT and no routing to other networks.
Never run test tools against anything outside it. Do not enable the system `ssh` service for lab
use; the victim sshd (Phase 4) runs inside the namespace only.

## Deployment (Phase 8)
Run NetGuard as system services with the dashboard on HTTPS. Guide: `docs/deployment.md`; decisions: ADR 0020.
```bash
make deploy-install    # sudo: users, /opt/netguard, /etc/netguard (secrets, self-signed cert), nginx site, systemd units
make deploy-verify     # sudo: services, loopback-only API, headers, TLS, process privileges, secret files
make deploy-remove     # sudo: removes services and code; keeps /etc/netguard and the database
```

## Troubleshooting
**First, run `make doctor`.** It checks, read-only: the real working directory (not the Trash), that the
virtualenv belongs to this directory, `.env`, exported `NETGUARD_*` variables, and migration state.

**`make: .venv/bin/<tool>: No such file or directory` although the file exists.** The virtualenv was
moved or copied: its scripts record the absolute path of their original interpreter. `make setup`
detects this and rebuilds `.venv` automatically; the Makefile itself calls tools as `python -m`, so
it does not depend on those scripts. Never copy `.venv` between directories or machines.

**The prompt shows the right folder but commands act on another one.** If a folder is moved or
replaced while a terminal is open in it, the shell keeps working in the old (possibly Trash) copy.
Open a new terminal, `cd` into the real folder, and run `make doctor`.

**"database ... has a collation version mismatch"** (after a glibc upgrade). Applies to databases
created before the upgrade; the `netguard` database is immune (builtin C.UTF-8 provider on
PostgreSQL >= 17). To clear it for a database `X`:
```bash
sudo -u postgres psql -X -d X -c "REINDEX DATABASE X;" -c "REINDEX SYSTEM X;" \
  -c "ALTER DATABASE X REFRESH COLLATION VERSION;"
```
Back up non-trivial databases first. Check with:
`SELECT datname, datcollversion, pg_database_collation_actual_version(oid) FROM pg_database;`

## Configuration precedence (a common source of confusing failures)
Settings come from, highest priority first: **variables already exported in your shell**, then `.env`.
Do not `source .env` or `export` the NETGUARD_* values into your shell: a stale exported value silently
overrides a regenerated `.env` and shows up as authentication failures. List what is exported
(names only, so no secrets are printed) with `env | grep -o '^NETGUARD_[A-Z_]*'`, and clear it with
`for v in $(env | grep -o '^NETGUARD_[A-Z_]*'); do unset "$v"; done`.
Unit tests ignore NETGUARD_* variables; integration tests use your real configuration.

## apt on Kali (read before upgrading)
If `sudo apt install` proposes upgrading hundreds of packages, your package index is behind the
mirror. Do not run `apt autoremove` while python3.13 is listed as removable: `.venv` points at
`/usr/bin/python3.13`. If the system Python changes, rebuild the environment with
`rm -rf .venv && make setup`.

## Known limitations
- Tested on **Python 3.12 and 3.13** (3.13 matters: it added private `Thread` attributes that broke an earlier version of the writer, invisible on 3.12) with PostgreSQL 18. Always run `make test-integration` on your own machine.
- `requirements.lock` pins the versions the deployment installs (`make freeze` after changing dependencies).
- Starlette's TestClient prints a deprecation warning about `httpx`; harmless.
