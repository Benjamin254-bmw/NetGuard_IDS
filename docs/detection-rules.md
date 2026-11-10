# Detection rules (Phase 4A)

Five rules, all **metadata-based** (headers, DNS query names, and sshd log lines; no payload is
read or stored). Every rule has a stable `key`, a version tracked in the database (ADR 0007), and
administrator-tunable `severity`, `threshold`, `window_seconds`, `cooldown_seconds`, `params`.
Changes made through the database are picked up by the running monitor within
`NETGUARD_RULES_RELOAD_SECONDS` (default 10) and recorded as a new rule version; every event keeps
the version that produced it.

Defaults below are *starting points chosen for a small network*, not tuned results. They are tuned
and evaluated against ground truth in Phase 4B, on a tuning set that is separate from the
evaluation set.

| Key | Detects | Condition (defaults) | Severity | Dedup key |
|---|---|---|---|---|
| `port_scan` | one source probing many ports of one host | >= 15 distinct dst ports with SYN-without-ACK in 10 s, per (src, dst) | high; critical at >= 10x | `port_scan\|src\|dst` |
| `excessive_connections` | connection flood / brute-force client | >= 100 SYN-without-ACK in 10 s, per (src, dst, port) | medium; high at >= 10x | `excessive_connections\|src\|dst\|port` |
| `auth_failures` | repeated failed SSH logins | >= 5 failed logins in 60 s, per source (from the auth log) | high | `auth_failures\|src` |
| `abnormal_traffic` | a local host sending far more than the limit | average sent bytes/s over 10 s >= 5,000,000, per local source | medium; high at >= 4x | `abnormal_traffic\|src` |
| `suspicious_dns` | DNS behaviour unusual for a small LAN | see below | low (watchlist: medium) | `suspicious_dns\|src\|indicator` |

`suspicious_dns` indicators (each is its own event so the analyst sees which fired): `query_rate`
(>= 100 queries in 60 s), `distinct_names` (>= `params.distinct_names`, 50, different names in 60 s),
`long_label` (any label longer than `params.max_label_length`, 52 characters), `watchlist`
(name equals or is a subdomain of an entry in `params.watchlist`; severity `params.watchlist_severity`).

## Evidence stored on every event
`crossed_at` (epoch seconds of the moment the threshold was first reached in this window),
`threshold`, `window_seconds`, plus rule-specific measurements (`distinct_ports`, `connections`,
`failures`, `avg_bytes_per_second`, `indicator`, ...). Latency in the lab gate is measured from
`crossed_at` to the database commit time of the event (`created_at`).

## Event lifecycle (ADR 0013)
One *open* event per dedup key. Repeated detections update it (`hit_count`, `last_seen_at`,
`evidence`) instead of creating rows or alerts. An escalation (higher severity) raises one more
alert immediately. The event closes after `cooldown_seconds` without a detection; a later
detection opens a new event and a new alert.

## Bounded state
Every rule caps its tracked keys at 10,000 (`capped` counter exposed by the engine) and prunes by
window; port scan tracks at most 4,096 recent ports per (src, dst). Memory cannot be exhausted by
varying source addresses.

## Known limitations (documented, not hidden)
- `port_scan` and `excessive_connections` look at **SYN without ACK**: they detect `nmap -sS` and
  `-sT` scans. They do **not** detect UDP scans (`-sU`) or FIN/NULL/Xmas scans (`-sF/-sN/-sX`), and a
  scan slower than one new port per (window / threshold) escapes. Phase 4B reports these as misses.
- `abnormal_traffic` is an absolute limit set by the administrator, not a learned baseline.
- `auth_failures` needs the sshd log (`NETGUARD_AUTH_LOG_PATH`); without it the rule is idle and the
  monitor says so. IPv4 sources only; the username is never stored.
- Windows use the host wall clock (`ts_utc`); a large clock step during a window can distort it.
- Capacity: a 1.3 Gbit/s burst (115,000 packets/s of 1,400-byte frames) in the 2-vCPU sandbox
  overran the 16 MB kernel buffer and was reported as `kernel_drops` (3,135 of ~17,800 packets);
  the same volume paced at 3,000 packets/s dropped nothing. Maximum sustainable rate is a Phase 4B/7
  measurement, not a claim.
