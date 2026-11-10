# Monitor operations guide

## What it does
Reads IPv4/ARP metadata from one explicitly chosen interface, keeps only traffic where the source
or destination is inside the explicitly authorised subnet, aggregates it (per second and per flow
per minute), discovers devices, and writes everything to PostgreSQL. No payloads are stored.
Detection rules (Phase 4A, `docs/detection-rules.md`) consume the same pipeline in the analyzer thread and write events and alerts through the same exactly-once writer.

## Configuration (all in `.env`; environment variables override)
Required, with no defaults (the monitor refuses to start without them):
`NETGUARD_MONITOR_INTERFACE` (e.g. `br-lab`) and `NETGUARD_AUTHORIZED_SUBNET` (e.g. `10.10.10.0/24`).
It also refuses an interface whose own network does not overlap the authorised subnet.
Optional, bounded in code: see `.env.example` (queue sizes, flow cap, inactivity timeout,
`NETGUARD_PROMISCUOUS`, `NETGUARD_ACTIVE_DISCOVERY`, retention, spill location and size).

## Running
    make lab-up                                   # build the isolated lab
    # set NETGUARD_MONITOR_INTERFACE=br-lab and NETGUARD_AUTHORIZED_SUBNET=10.10.10.0/24 in .env
    make monitor-check                            # shows what would be refused, and why
    make monitor-run                              # runs as YOU with only CAP_NET_RAW/NET_ADMIN
Stop with Ctrl-C: it drains the kernel buffer and every queue before writing `stopped`.
Do not use `lo` outside tests: the monitor would capture its own PostgreSQL connection.

## Discovery
Passive (always on): ARP senders and traffic sources inside the subnet. Destinations are never
treated as evidence of a device (a scan of empty addresses must not invent devices).
Active (off by default): an ARP sweep of the overlap between the authorised subnet and the
interface's network, never larger than /22 and never outside the authorised range. Hostnames are
not resolved in Phase 3 (no resolver policy yet); the column stays empty.
Known limits: a spoofed source address inside the subnet creates a device row (bounded by a
4096-device cap); inactivity is judged by `NETGUARD_INACTIVE_AFTER_SECONDS` since last evidence.

## Reading the heartbeat
`SELECT state, heartbeat_at, packets_captured, packets_dropped, spill_backlog, degraded_reasons
FROM monitor_status;`  State `degraded` lists reasons (ADR 0012). A `heartbeat_at` older than ~15 s
means the monitor is not running.

## Verifying it (the Phase 3 gate)
    make verify-capture            # passive discovery
    make verify-capture-active     # with active ARP discovery
Runs the real monitor against tcpdump (independent oracle) and known send counts, and checks
discovery against `nmap -sn`. It waits for the lab bridge to go quiet first, starts the oracle
only after the monitor is capturing and stops it before the monitor, and compares totals over
tcp/udp/icmp (background chatter such as IGMP is reported separately, not hidden). Evidence is written to `lab/results/phase3-capture-*.json`.
Capability-limited tests: `make test-capture`. Parser benchmark: `.venv/bin/python lab/bench_parser.py`.

## Limitations
IPv4 and ARP only; timestamps are user-space read times; a host sensor sees only what its interface
sees (use a bridge, gateway, or mirror port; set NETGUARD_PROMISCUOUS=true for mirror ports);
kernel drops before the socket are invisible; ICMP error rate limiting by the sender is not ours
to count. TCP "new connections" means SYN without ACK.

## Detection (Phase 4A)
`NETGUARD_AUTH_LOG_PATH` (optional) enables the auth-failure rule; `NETGUARD_RULES_RELOAD_SECONDS`
(default 10) is how often the running monitor re-reads `detection_rules`. Degraded reasons added:
`auth_log_unavailable` (a path is set but cannot be read; the monitor keeps running and retries).
Disabling a rule stops new detections; its open events close after their cooldown.
