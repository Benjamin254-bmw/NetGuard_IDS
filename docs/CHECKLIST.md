# Development checklist
Legend: [x] done and verified (where stated) · [ ] open task that still blocks its phase · (K) verified on the target Kali machine · *Deferred* = decided to do later, with the phase that owns it · *Out of scope* = not intended for that phase. Only real open tasks carry an empty box.

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
- *Deferred (cosmetic, Gate A disposition):* collation fix for `postgres` and `template1`. It does not affect the netguard databases. Not reproducible off-target
- [x] (K) iperf3 not running or listening on Kali (checked)
- *Deferred to Phase 8:* `requirements.lock`, frozen after the last dependency change

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
- [x] (K) `make db-init` and `make test-integration` on Kali: passed (191 passed at Gate A; 439 passed, 13 skipped in Phase 5, see the dispositions under Phase 4 and Phase 5)
- [x] Test defect found on Kali and fixed: two config tests depended on NETGUARD_* variables exported in the shell; now isolated (`clean_env`) and verified under a hostile environment
- Items this phase left to later phases, all since delivered: retention pruning (Phase 3, `persistence/retention.py`), rule rows and the rule registry (Phase 4), login lockout and session-version columns (migration 0003, Phase 5). There are no DNS counter columns: the `suspicious_dns` rule keeps its counters in the engine's bounded memory (Phase 4)

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
- [x] (K) re-run on Kali after copying the fix: `make doctor`, `make setup`, `make migrate` (database is at 0003, so 0002 was applied), `make test`, `make test-integration`, `make test-capture` (19 passed): see the Phase 1-4 dispositions below
- [x] (K) `make lab-up && make verify-capture` on Kali, 2026-11-11: ALL CHECKS PASSED (the gate on your hardware). *Optional, not run on Kali:* `make verify-capture-active`
- [x] (K) Parser benchmark on the Kali laptop (Phase 7, 2026-11-17, three runs): 234,013-249,860 vs Scapy 4,270-4,313 frames/s (55-58x) — ADR 0011
- *Out of scope for Phase 3:* hostname resolution, IPv6, detection rules (Phase 4), high-rate performance and CPU/memory evaluation (Phase 7)

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
- [x] An earlier demo run produced no events (`captured=3 parsed=0`). Probable cause, found in 4B: promiscuous mode was off and only the tcpdump oracle's side effect made the bridge deliver frames (reproduced: 5 packets captured vs 165,782 with it on). Not proven for that specific run. Demos now set NETGUARD_PROMISCUOUS=true explicitly
- [x] (K) Run on Kali (Python 3.13.12, OpenSSH 10.6): `make doctor` OK, `make test` 115 passed, `make test-integration` 191 passed (13 skipped = need capabilities), `make test-capture` 19 passed, demo 6 of 7 events. The 7th (`auth_failures`) was missing because OpenSSH 10's PerSourcePenalties refused ssh attempts 5 and 6; fixed in the demo (r2) with a precondition check, see docs/detection-rules.md. Also: a stale `shared/tests/conftest.py` left over from Phase 2 broke `make lint`; remove it
- [x] (K) `make verify-detection` re-run on Kali with the r2 demo: ALL CHECKS PASSED, non-root monitor (user-reported output)
- *Out of scope for 4A (delivered in 4B or documented as a limitation):* evaluation harness with ground truth, tuning/evaluation split, recall/precision/FPR/latency per category (4B); UDP and FIN/NULL/Xmas scan detection (documented miss); performance and resource tests (4B/7)

## Phase 4B: Evaluation harness (run in sandbox and on Kali)
- [x] Seeded plan of 375 trials written first (`lab/eval/ground_truth.jsonl`, hash-checked): 5 categories x (attacks, near-threshold hard negatives), normal traffic, known-evasion attacks; tuning and evaluation trials disjoint
- [x] Scoring: independent per-category confusion matrices, Wilson 95% CIs, FP breakdown by negative type, latency two ways; invalid trials listed not dropped. 22 unit tests, scorer mutation-checked (all mutants caught after adding an edge test)
- [x] Runner with freeze enforcement (rules and plan hash must match; evaluation split refuses smoke runs, missing freeze, changed rules, changed plan; each evaluation run logged); re-scoring reproduces stored metrics
- [x] Tuning run (125 trials) and evaluation run (250 trials) on real lab traffic, non-root capability-limited monitor: 30/30 recall, 0 false positives for all five rules; 0/20 known-evasion scans detected (documented miss). No threshold changed. See `docs/evaluation.md`
- [x] Capacity sweep: lossless to 32 MB/s UDP and 3,000 conn/s (2-vCPU sandbox); 12% loss at 64 MB/s, 42% at 128 MB/s, reported by the monitor's own counter
- [x] Defect found on Kali: `make verify-capture` run straight after the evaluation failed its discovery check (monitor listed 4 devices, nmap 131). Cause: the evaluation runner left ~131 extra source addresses on the lab interfaces and the device table is keyed by MAC. Reproduced in the sandbox, clean lab passes. Fixed: runner removes its addresses on exit; verify scripts refuse a lab with extra addresses
- [x] Defect found: promiscuous mode (see ADR 0015 and `docs/evaluation.md`); fixed in lab scripts, documented
- [x] (K) Reproduced on Kali 2026-11-10 (user-reported output): tuning 15/15 per category, 0 FP; evaluation 30/30 per category, 0 FP, 0 kernel drops, non-root; capacity lossless to 32 MB/s UDP and 3,000 conn/s, 44% loss at 64 MB/s. Figures in `docs/evaluation.md` (Kali section) are the ones to quote
- [x] **Gate A PASSED 2026-11-11** (all five criteria met on the Kali machine; evidence: evaluation run `eval-evaluation-20261110T161321`, `verify-capture` evidence `phase3-capture-20261111T174645`; no criterion was widened). Criteria as approved: **approved by Benjamin on 2026-11-10 (kept as proposed; not to be widened to fit results)**. Gate A passes only if ALL hold, on the evaluation split run on the Kali machine with the rules frozen from a Kali tuning run:
  - every rule has 30/30 evaluation attacks detected (no misses); the Wilson 95% lower bound for 30/30 is 88.65%, so "recall >= 89%" as first worded is satisfiable only as "no misses"
  - zero false positives in every category (0/200 or 0/220 negatives; Wilson 95% upper bound 1.88% for port_scan and 1.72% for the others, i.e. within the 2% limit; a single false positive would give 2.5-2.8% and FAIL)
  - zero kernel-dropped packets during the evaluation run; monitor non-root with only CAP_NET_RAW and CAP_NET_ADMIN
  - the documented misses (UDP/FIN/NULL/Xmas/slow scans) listed in the report, not hidden or removed from the plan
  - checklist items for Phases 1-4 done or explicitly deferred
  - If any criterion fails: report the failure as is. Do not change thresholds and re-run the evaluation split to get a pass; fixes go through the tuning split, with a new frozen set and a new, separately logged evaluation run, and the earlier failed run stays in `lab/eval/evaluation_runs.log`
- [x] (K) Kali smoke run (16 trials): all 5 categories detected, 165,950 packets captured, 0 kernel drops, non-root capability-limited monitor (user-reported). Kali `make test`: 136 passed, 89 skipped (sandbox: 141 / 84; skip counts depend on capabilities available, to be checked)
### Phase 1-4 dispositions (for Gate A criterion 5)
- Done on Kali (reported earlier in this project): `make test`, `make test-integration` (191 passed), `make test-capture` (19 passed), `make doctor`, `make lint`/`typecheck` clean, demo, smoke, tuning, evaluation, capacity. Covers the Phase 2 "(K) db-init/test-integration" and Phase 3 "(K) re-run on Kali" items
- Done 2026-11-11: `make lab-down && make lab-up && make verify-capture` on Kali (fresh lab, patched scripts): ALL CHECKS PASSED incl. discovery 4/4 (user-reported) with the patched script (the Phase 3 gate on your hardware; the script changed in 4B to set promiscuous mode explicitly). `make verify-capture-active` optional
- Deferred explicitly (do not block Gate A): `(K) collation fix for postgres/template1` (cosmetic, does not affect the netguard databases); `requirements.lock` (to Phase 8, freeze after the last dependency change); `lab/bench_parser.py` on the laptop (to Phase 7 performance evaluation); IPv6, hostname resolution, UDP/FIN/NULL/Xmas/slow-scan detection (documented limitations, reported in the evaluation)
- *Next:* Phase 7 final evaluation and Phase 8 documentation and deployment

## Phase 5: API, authentication, WebSocket (verified in sandbox and on Kali)
- [x] Migration 0003: login throttling and session-version columns on `users` (models and migration agree: drift test passes)
- [x] Authentication: Argon2id, JWT in HttpOnly SameSite=Strict cookie, CSRF double-submit plus Origin check, role/active/session version read from the database on every request, sliding renewal, account lockout, per-address failure limiter, identical login failures, audit trail (see ADR 0016)
- [x] User administration (admin only) with last-active-admin protection, tested with a 20-round concurrent-demotion race; CLI `make create-admin` (password prompted, never in argv)
- [x] Read endpoints: overview, monitor status (stale heartbeat reported as `stale`), devices, traffic series/protocols/top talkers (bounded ranges and bucket sizes), events (filters, keyset pagination, rule snapshot), alerts, rules with version history, audit logs (admin)
- [x] Write endpoints, all audited: event status, alert acknowledge/dismiss/reopen, rule changes (admin; bounds; params keys and types must match the rule's current params; no-op patch creates no version)
- [x] WebSocket `/api/ws` (see ADR 0017): cookie auth and Origin check at handshake, LISTEN/NOTIFY fan-out reading the alert from the database, bounded per-client queues, 5 s monitor status, `resync` after the LISTEN connection is re-established, session re-check every 15 s
- [x] RBAC matrix test enumerates the live route table: every route must be classified public/admin/any-user, anonymous 401, analyst 403 on admin routes, CSRF and foreign Origin refused on every unsafe route; production exposes no docs
- [x] Mutation checks on the new code (removing admin guard on rules/audit, pagination boundary, stale detection, params key/type checks, no-op detection, WebSocket origin check, session-version check, message-size limit, overflow disconnect, resync broadcast, alert reopen): all mutants caught; the session-version and revocation test originally hung on regression and was bounded
- [x] Docs: `docs/api.md`, ADR 0016, ADR 0017; dependencies declared in `backend/pyproject.toml`
- [x] Sandbox results 2026-11-11: lint and mypy clean; full suite with integration 451 passed, 1 skipped on Python 3.13; backend+shared 286 passed, 1 skipped on Python 3.12; real uvicorn server walk-through (login, overview, CSRF refusal, anonymous 401, WebSocket hello) worked, test data removed afterwards
- [x] (K) Kali 2026-11-11 (user-reported output): migrations at 0003; `make lint` clean; `make typecheck` 58 files clean; `make test` 172 passed, 280 skipped; `make test-integration` 439 passed, 13 skipped (the CAP_NET_RAW tests only). Real server (`make run-api`, `make create-admin`): login, overview, anonymous 401, PATCH without CSRF 403, WebSocket `hello` and a `monitor` status every 5 s from the live non-root monitor on `br-lab`
- [x] (K) End to end on Kali with the monitor writing to the development database: a port scan from the lab attacker produced event 1 and two alerts (high, then the escalated critical) visible through `GET /api/alerts`; `GET /api/rules` listed the registered rules; `PATCH /api/rules/1` with the CSRF token returned 200 and left version 1 (no change, no new version)
- [x] (K) WebSocket on Kali (user-reported listener output): `hello`, `monitor` status every 5 s, then `alert` messages for alert 1 (high) and alert 2 (critical, escalated) immediately after the scan, identical to `GET /api/alerts`; monitor counted 808 packets, 0 dropped; the socket was closed with code 4401 when the 30-minute session expired (intended). A rule change (`threshold` 15 to 20) returned 200, created version 2 with `updated_by` set, and the history listed both versions
- [x] **Phase 5 verified on Kali 2026-11-11.** Remaining limitations are listed above (no MFA, per-process limiter, no proxy support)
- *Known limitations (documented, not tasks):* no MFA; no email reset; failure limiter and lockout are per-process; X-Forwarded-For is not trusted (no reverse proxy yet); Secure cookies need https (set `NETGUARD_COOKIE_SECURE`)

## Phase 6: Dashboard (verified in sandbox and on Kali 2026-11-12)
- [x] Navigation as agreed: Overview, Events, Rules, Users (with Audit log tab), Settings (read-only); header status always visible
- [x] Header status with eight states; green only when the live feed is open, a monitor status arrived within 20 s and the heartbeat is under 15 s old; otherwise banner, tint and a flat pulse line (`live/status.ts`, 9 unit tests)
- [x] Live feed: reconnect with backoff, REST catch-up after any gap (resync, newer alerts on hello), no retry after session end (`live/feed.ts`, 13 unit tests)
- [x] Pages: Overview, Events + detail (acknowledge, dismiss, reopen, status, rule snapshot, evidence as text), Rules + detail (admin edit, version history), Users (create, role, disable, reset, unlock) + audit, Settings (system info, change password, sign out everywhere)
- [x] Backend addition: `GET /api/system/info` (no secrets; tested; in the access-control matrix). Finding: the API role cannot read `alembic_version`, so the schema revision is deliberately not shown
- [x] ADR 0018 (stack: no Tailwind/Zustand/Recharts, self-hosted fonts, same origin); `docs/dashboard.md`
- [x] Frontend: 55 unit/component tests, typecheck and production build clean; mutation checks on status, feed, client and rule-patch logic (13 mutants, all caught after adding API-client tests for a surviving CSRF-header mutant)
- [x] Browser verification in the sandbox (real API, PostgreSQL, lab traffic): login, all pages, live alert arrival with highlight, monitor killed (header to "not responding" in under 5 s, banner and tint) and restarted (live again), API killed ("Live feed disconnected"), analyst cannot see or open Users, 390 px phone viewport without horizontal scroll
- [x] Defects found and fixed during verification: tabular-number font feature spread punctuation ("3 . 2 MB"); "Nothing needs attention" shown while not live
- [x] Kali 2026-11-12: `make frontend-install`, `make frontend-test` (55 passed), `make frontend-build`, `make frontend-lint` (7 warnings, same as sandbox) ok; header shows live with the monitor running
- [x] (K) Kali 2026-11-12, user-reported: after setting `NETGUARD_PROMISCUOUS=true` the lab port scan appears in Events and Overview, next to last night's event 1
- [x] Defect found on Kali: first walk-through produced no event because `.env` lacked `NETGUARD_PROMISCUOUS=true`; the monitor on `br-lab` captured 5 packets in 24 minutes (the failure documented in `docs/evaluation.md`) while the header still said live, since the heartbeat does not depend on capture. README and `docs/monitor.md` now list the setting in the lab steps
- [x] (K) Kali 2026-11-12, user-confirmed: a new alert arrives without a page refresh, and stopping then restarting the monitor turns the header to "Monitor is not responding" and back to live
- *Not built (deferred, not blocking Phase 6):* custom chart ranges and a dark-mode toggle (nice to have); a tool-based accessibility audit (Phase 7 or 8); production serving and HTTPS (Phase 8). Open question for Phase 8: a monitor that is running but captures nothing (as in the promiscuous case above) still shows live; a visible captured-packets signal in the header would catch it

## Phase 7: final measurements (done; Kali figures recorded 2026-11-17/18)
Scope chosen with the user 2026-11-12: end-to-end latency, full-stack resource use and API response times, the
deferred parser benchmark, and an accessibility check. Design: ADR 0019. Write-up: `docs/evaluation.md` (Phase 7).
- [x] Latency harness `lab/e2e_latency.py` (scan start to alert on `/api/ws`): sandbox 30/30 detected, median 0.702 s, p95 0.722 s, max 0.747 s; WebSocket delivery about 7 ms. Refuses to run without a working capture (warm-up check names the missing `NETGUARD_PROMISCUOUS=true`; the refusal was exercised)
- [x] Resource harness `lab/stack_resources.py`: monitor, API and PostgreSQL CPU and PSS memory idle, with 5 dashboard clients, and with 8 MB/s UDP; API response times per endpoint; refuses to run with a second monitor or API process (that guard was added after the harness double-counted one)
- [x] Scale test (`scripts/scale_db.sh`, `lab/seed_scale.py`, `--api-only`): API answered the dashboard's queries in 3-16 ms with 432,000 + 864,000 synthetic rows; seed refuses non-scratch databases (both refusals exercised). The seed rows are synthetic and never used for detection figures
- [x] Defect found and fixed: top talkers over 30 days took 1,538 ms (median) at that size; rewritten (same results, tested against the original query, 3 mutants caught), now 223 ms
- [x] Accessibility (`lab/a11y_audit.py`, axe-core, 36 views): 30 views failed at first (landmark, three contrast problems); fixed; now 0 violations. Chart-label contrast checked by computed colour (7.5:1 / 9.0:1)
- [x] Unit tests for the harness helpers (`lab/tests/test_e2e_helpers.py`, `test_stack_helpers.py`); full suite with integration tests: 466 passed, 1 skipped; ruff, mypy clean; frontend 55 tests pass
- [x] (K) `make bench-parser` on Kali 2026-11-17: 234,013-249,860 vs Scapy 4,270-4,313 frames/s (55-58x), `docs/evaluation.md` section 5
- [x] (K) `make e2e-latency` on Kali 2026-11-17: 30/30, scan start to alert on the WebSocket median 0.561 s, p95 0.776 s, max 0.988 s (`docs/evaluation.md`)
- [x] (K) `make stack-resources` on Kali 2026-11-17: idle about 183 MB total; at 8 MB/s the monitor uses 52% of a core, 0 drops; every dashboard endpoint under 20 ms (`docs/evaluation.md`)
- [x] (K) Scale test on Kali 2026-11-18 (432,375 + 864,020 synthetic rows): dashboard queries p95 5.5-15.5 ms, max 20.3 ms; widest ranges p50 253 / 128 / 378 ms (24 h series, 24 h protocols, 30 d top talkers), max 766 ms; all 200 (`docs/evaluation.md`)
- [x] **Phase 7 complete on Kali (2026-11-18).**
- *Not measured (stated limits):* latency under heavy load; more than 5 simultaneous dashboard clients; runs of hours (growth, retention behaviour, stability); events and alerts tables at scale; detection under packet loss; behaviour on a real network
- *Not checked by hand:* keyboard-only walkthrough, screen reader, 200%/400% zoom reflow, reduced motion, forced colours (automated axe checks do not cover these)


## Phase 8: deployment and documentation (installed and verified on Kali 2026-11-18)
Design: ADR 0020. Guide: `docs/deployment.md`.
- [x] systemd units: `netguard-monitor` (own user, only CAP_NET_RAW + CAP_NET_ADMIN, read-only filesystem, spill in `StateDirectory`, no retry on a configuration refusal) and `netguard-api` (own user, no capabilities); `systemd-analyze verify` clean apart from the not-yet-installed binary path
- [x] Per-service secrets files, root 600, read by systemd (`deploy/render_env.py`): API file holds only the API role and a new session secret, monitor file only the monitor role; no migrator password in either — 6 tests, quoting checked against real systemd parsing (`systemd-run --user`)
- [x] nginx site: dashboard and `/api` + WebSocket on one HTTPS origin, CSP without inline script or style, TLS 1.2+, `X-Forwarded-For` overwritten; checked with a non-root nginx on Kali (headers, caching, client-side routes, `/api` 404/401 from the API, TLS 1.1 refused)
- [x] Self-signed certificate script (P-256, host name, `.local`, localhost, the machine's addresses; prints the fingerprint; never overwrites) — tested
- [x] Finding: uvicorn already trusted `X-Forwarded-For` from 127.0.0.1 by default while the code said it was ignored. Now pinned in `app/__main__.py` (`forwarded_allow_ips="127.0.0.1,::1"`, an environment variable cannot widen it); 4 tests with the real uvicorn middleware (local proxy believed, remote peer cannot claim an address or https, foreign origin refused)
- [x] Header "no packets" state: a live monitor whose packet count has not moved for 2 minutes is shown amber with a hint about the interface and promiscuous mode (the open question from Phase 6); the feed records when the counter last moved — 4 new unit tests; frontend 59 tests pass, lint back to the 7 earlier warnings
- [x] `deploy/install.sh` (builds as the user, installs root-owned code, keeps `/etc/netguard`, refuses to start a second monitor), `deploy/verify.sh`, `deploy/uninstall.sh`; Makefile `deploy-install`, `deploy-verify`, `deploy-remove`
- [x] `requirements.lock` generated (`make freeze`); the installer constrains versions with it
- [x] Production-mode API (`NETGUARD_ENV=production`, empty allowed origins) behind the test nginx on Kali, against `netguard_test`: 12/12 checks — sign-in over https, session cookie `Secure; HttpOnly; SameSite=strict; Path=/api`, no API docs or schema, unsafe request without CSRF token 403, foreign origin 403, WebSocket `hello` over `wss://`, foreign-origin WebSocket refused, audit log recorded 127.0.0.1 for a request claiming 203.0.113.66, same-origin request with token 204. Mutation: with nginx appending instead of overwriting `X-Forwarded-For` the forged address reached the audit log and the check failed
- [x] Full suite on Kali after Phase 8: `make lint` clean, `make typecheck` 58 files clean, `make test-integration` 466 passed (including the 10 new Phase 8 tests), 13 skipped (need CAP_NET_RAW); frontend tests, lint, build clean
- [x] (K) `make deploy-install && make deploy-verify` on Kali 2026-11-18 (user-reported): ALL CHECKS PASSED, 21/21 — nginx, API and monitor services running; API on 127.0.0.1:8100 only; dashboard headers and routes; TLS 1.1 refused; monitor as `netguard-monitor` with only CAP_NET_RAW + CAP_NET_ADMIN, API as `netguard-api` with none; secrets files and key root-only, each holding only its own secrets; forged `X-Forwarded-For` not recorded
- [x] (K) Signed in at `https://<host>/` on the installed system; a live alert arrived without a page refresh (user-confirmed 2026-11-18)
- [x] **Phase 8 complete on Kali (2026-11-18). All phases complete.**

Monitor: capture, discovery (3, done) · detection rules (4A, done) · evaluation harness (4B, done) · **Gate A (passed)** · API/WebSocket (5, done) · Dashboard (6, done, verified on Kali) · Final measurements (7, done on Kali) · Deployment and docs (8, installed and verified on Kali)
