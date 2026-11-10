# Development checklist
Legend: [x] done and verified (where stated) · [ ] not done · (K) still to be verified on the target Kali machine

## Phase 1: Foundation
- [x] Repository structure, .gitignore, Makefile, pyproject files
- [x] Typed settings with validation (explicit interface/subnet required, IPv4 only, placeholders rejected)
- [x] Logging (text/JSON, UTC) — unit tested
- [x] DB engine + diagnostics + `check-db` CLI — integration tested on PostgreSQL 18.6
- [x] `init_env.sh` (mode 600, generated secrets, never overwrites) — tested
- [x] `db_init.sh` idempotent; roles, UTC timezone, builtin C.UTF-8 DB — tested twice on PG 18.6
- [x] Role separation: monitor/api cannot CREATE TABLE; migrator can — integration tested
- [x] Least-privilege capture: non-root user with only CAP_NET_RAW/NET_ADMIN can open AF_PACKET socket; without caps it cannot — tested
- [x] Lab script `up/down/status/verify` — tested (bridge, 3 namespaces, sniffer sees traffic, isolation)
- [x] Backend health/readiness endpoints; readiness does not leak internals — tested
- [x] Monitor `check` command (imports, DB role, privileges)
- [x] Frontend scaffold builds and lints
- [x] ruff and mypy --strict clean
- [x] (K) `make setup`, `make check-db`, `make test`, `make test-integration`, `make lab-verify`, `make frontend-build` verified on the Kali machine (Python 3.13.12, PostgreSQL 18.3, kernel 6.19)
- [x] (K) `sudo scripts/run-with-caps.sh .venv/bin/python -m netguard_monitor.main check` on Kali: root=False, CAP_NET_RAW and CAP_NET_ADMIN present, DB role OK
- [ ] (K) Collation fix for `postgres` and `template1` confirmed (REFRESH step not reproducible off-target)
- [x] (K) iperf3 not running or listening on Kali (checked)
- [ ] `requirements.lock` (after K verification)

## Phase 2: Database schema and migrations
- [x] 11 tables: users, devices, traffic_stats_1s, connection_aggregates_1m, detection_rules, detection_rule_versions, security_events, alerts, settings, audit_logs, monitor_status
- [x] Alembic migration 0001; upgrade, downgrade and re-upgrade tested; `alembic check` shows no drift
- [x] Types and constraints: inet/macaddr/timestamptz, IPv4-only checks, enum CHECKs, ranges, singleton monitor row — 28 tests, each asserting the exact constraint that fired
- [x] Rule versioning trigger, immutable history, events reference the rule version that fired them — tested
- [x] Open-window dedup via partial unique index; replay-safe event UUIDs — tested
- [x] Privilege matrix verified against the live database; behavioural tests; audit log append-only — tested
- [x] Mutation-checked: a widened grant, an extra DELETE right and a missing trigger are each caught
- [x] Generated schema reference (`docs/database-schema.md`), ADRs 0007-0010
- [x] (K) `make migrate` and `make migrate-check` on Kali (PostgreSQL 18.3): applied, no drift
- [ ] (K) `make db-init` (creates `netguard_test`) then `make test-integration` on Kali
- [x] Test defect found on Kali and fixed: two config tests depended on NETGUARD_* variables exported in the shell; now isolated (`clean_env`) and verified under a hostile environment
- [ ] Not implemented yet by design: retention job (monitor, Phase 3), rule rows (rule registry, Phase 4), DNS counters (Phase 4), login lockout columns (Phase 5)

## Phase 3: Network monitor
- [x] Interface listing and capture safeguards: explicit interface and subnet required; refuses down/missing interface or one on another network — tested
- [x] AF_PACKET capture: kernel BPF filter, truncated reads with real length, kernel drop counter (verified under real overflow), loopback de-duplication, promiscuous mode released on close — tested, mutation-checked
- [x] Frame parser (Ethernet/VLAN, IPv4, TCP/UDP/ICMP, DNS query names, ARP) checked against Scapy as oracle, all truncations, 40,000 random inputs — 23 tests; DNS header bug found and fixed
- [x] Aggregation (per-second protocol totals, per-flow per-minute with a key cap) and passive device tracker — 12 tests
- [x] Exactly-once persistence via batch ledger; spill to disk on outage or full queue; replay idempotent; retention pruning; heartbeat — 23 tests, mutation-checked
- [x] Service: bounded queues, drop accounting, degradation reasons, capture-error recovery, drain-on-stop (found and fixed: shutdown lost ~99% of a burst)
- [x] Active ARP discovery, off by default, limited to the authorised subnet and /22 — guard tests; verified against real hosts in the lab
- [x] Gate (sandbox): 6/6 back-to-back runs (3 passive, 3 active), each from a fresh lab, exact against tcpdump and sent counts; devices equal `nmap -sn`; monitor ran as non-root with only CAP_NET_RAW/NET_ADMIN; gate proven to fail on a 2% undercount. Two harness races were found and fixed on the way (oracle window not nested inside the monitor's; IGMP chatter at lab bring-up) - neither was a monitor defect
- [x] Parser benchmark: 397,129 vs Scapy 8,395 frames/s (47x), sandbox figures — ADR 0011
- [x] Found on Kali: the writer failed on Python 3.13 (Thread subclass collided with Thread._handle); fixed by composition, regression-tested; the whole suite, capability-limited tests and both gates now pass on Python 3.12 AND 3.13
- [ ] (K) re-run on Kali after copying the fix: `make doctor`, `make setup`, `make migrate` (revision 0002 was never applied there), `make test`, `make test-integration`, `make test-capture`
- [ ] (K) `make lab-up && make verify-capture && make verify-capture-active` on Kali (the gate on your hardware)
- [ ] (K) `lab/bench_parser.py` on your laptop
- [ ] Not in this phase by design: hostname resolution, IPv6, detection rules (Phase 4), high-rate performance and CPU/memory evaluation (Phase 7)

## Phase 4A: Detection rules and event pipeline
- [x] Rule framework with bounded state; five rules (port scan, excessive connections, auth failures, abnormal traffic, suspicious DNS) — specs in `docs/detection-rules.md`
- [x] Engine: one open event per dedup key, coalesced hits, immediate escalation, cooldown close, restore after restart — ADR 0013
- [x] Exactly-once event/alert persistence; alert + `pg_notify` in the same transaction (no notify on rollback); late hits cannot modify closed events — 13 DB tests
- [x] Rule registry: defaults inserted once, administrator changes never overwritten, live reload into the running monitor, rule version recorded on each event
- [x] Auth log tailer (EOF start, rotation, truncation, rewrite, partial lines, missing file) — ADR 0014. Found by the lab demo: a real `sshd -E` writes lines without the `sshd[pid]:` prefix; the first parser saw nothing. Fixed and tested
- [x] 21 rule tests + 17 engine/log-source tests + 13 persistence tests + 4 end-to-end tests (real sockets on loopback → capture → DB)
- [x] Mutation check: 20 mutants across rules, engine, tailer, writer SQL and service wiring; 2 survived at first (auth window width; late hit on closed event), tests added, both now caught
- [x] Lab demo (`make verify-detection`): benign traffic = 0 events; nmap -sS, 150-connection flood, DNS burst + 60-char label, paced 21 MB UDP volume, 6 real failed SSH logins against a real sshd → exactly 7 events (one per dedup key), port scan critical with 2 alerts and agreeing with tcpdump, abnormal_traffic under live-changed rule v2, latency <= 3 s, 0 dropped packets. Passed on Python 3.13 (root and non-root capability-limited) and 3.12, and with the stand-in auth mode
- [x] Capture-path guard in the demo (monitor saw at least every packet tcpdump saw) and a per-command exit-status log, so an attack that silently failed cannot look like "no detection"
- [x] Finding: a 1.3 Gbit/s burst (115k pps) overran the 16 MB kernel buffer in the 2-vCPU sandbox: 3,135 drops, correctly reported. Paced at 3,000 pps: 0 drops. Real capacity is a Phase 4B/7 measurement
- [ ] An earlier demo run in the previous sandbox produced no events (`captured=3 parsed=0`). That harness was lost in a sandbox reset and the symptom did NOT reproduce with the rewritten harness over 7 runs; root cause unconfirmed (suspected harness race). The capture-alive check above would flag it explicitly
- [ ] (K) Run on Kali: `make test`, `make test-integration`, `make test-capture`, `make lab-up`, `make verify-detection` (needs `nmap sshpass openssh-server`)
- [ ] Not in 4A by design: evaluation harness with ground truth, tuning/evaluation split, recall/precision/FPR/latency per category (4B); UDP and FIN/NULL/Xmas scan detection (documented miss); performance and resource tests (4B/7)

## Phase 4B: Evaluation harness and Gate A: not started
Monitor: capture, discovery (3, done) · detection rules (4A, done) · evaluation harness (4B) · **Gate A** · API/WebSocket (5) · Dashboard (6) · Evaluation (7) · Docs (8)
