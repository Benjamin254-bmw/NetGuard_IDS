# Evaluation (Phase 4B)

All numbers below come from the stored runs in `lab/results/`; re-compute them with
`.venv/bin/python lab/evaluate.py score lab/results/<run>` (no lab needed). Design and its limits: ADR 0015.

## How to reproduce
```
make lab-up
python lab/evaluate.py plan                  # ground truth -> lab/eval/ (already committed; hash-checked)
python lab/evaluate.py reset-rules           # code defaults + DNS watch list "malware-eval.test"
sudo python lab/evaluate.py run --split tuning [--limit-per-group 1]   # 1 = quick smoke run
python lab/evaluate.py freeze --tuning-run lab/results/<tuning run>
sudo python lab/evaluate.py run --split evaluation                     # once, in full
sudo python lab/capacity.py                  # resource / capacity sweep
```
The runner adds one source address per trial to the lab interfaces and removes them on exit. (Versions before 2026-11-10 left them behind; run `make lab-down && make lab-up` before `verify-capture`/`verify-detection`, which now refuse a lab with extra addresses.)
Run with `sudo` from your normal user: the monitor itself then runs non-root with only
CAP_NET_RAW and CAP_NET_ADMIN. The full tuning run takes about 20 min, the evaluation split about 40 min.

## Kali results (Lenovo ThinkPad S1 Yoga, Intel Core i7-4500U, 2 cores / 4 threads, 8 GB; non-root monitor): THE FIGURES TO QUOTE
Source: output of `make eval-reset && make eval-tuning`, `evaluate.py freeze`, `make eval-evaluation`, `make eval-capacity`
on 2026-11-10; run directories on the Kali machine: `lab/results/eval-tuning-20261110T155001`,
`eval-evaluation-20261110T161321`, `capacity-20261110T165613.json`. Same plan hash `fdf34579bc5f...`, same frozen
rules (code defaults + DNS watch list, suspicious_dns v2). The sandbox figures further down corroborate them.

Tuning split (125 trials, all valid): 15/15 per category, 0 false positives. No threshold changed.

Evaluation split (250 trials, none invalid):
| category | recall | precision | false-positive rate | latency attack start to event (median / p95 / max, s) | threshold crossing to commit (median / max, s) |
|---|---|---|---|---|---|
| port_scan | 30/30 (95% CI 89-100%) | 30/30 | 0/200 (0-2%) | 0.76 / 3.80 / 4.00 | 0.31 / 0.62 |
| excessive_connections | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 1.62 / 3.75 / 7.01 | 0.21 / 0.49 |
| auth_failures | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 1.81 / 5.42 / 5.52 | 0.32 / 0.56 |
| abnormal_traffic | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 4.91 / 6.60 / 6.84 | 0.003 / 0.015 |
| suspicious_dns | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 1.54 / 4.31 / 4.83 | 0.35 / 0.60 |

0 false positives on 30 normal-traffic trials, 10 hard negatives per category, and other categories' attacks.
Known misses: UDP, FIN, NULL, Xmas and slow scans, 0 of 20 detected (4 trials each; 95% CI 0-49% per technique).
Resources during the evaluation: 3,209,576 packets captured, **0 kernel drops**; monitor CPU median 1%, p95 69%,
max 88% (of one core; higher than in the sandbox, driven by the 6-16 MB/s UDP trials); memory 72-73 MB.

Capacity on the ThinkPad S1 Yoga (sustained = 0 kernel drops and >= 99.9% captured):
| load | packets sent | captured | kernel drops | captured | CPU % median / max | RSS MB max | sustained |
|---|---|---|---|---|---|---|---|
| UDP 1 MB/s | 10,402 | 10,404 | 0 | 100.0% | 10 / 11 | 68.6 | yes |
| UDP 2 MB/s | 20,804 | 20,804 | 0 | 100.0% | 18 / 20 | 68.7 | yes |
| UDP 4 MB/s | 41,608 | 41,610 | 0 | 100.0% | 35 / 39 | 68.7 | yes |
| UDP 8 MB/s | 83,217 | 83,217 | 0 | 100.0% | 65 / 74 | 68.7 | yes |
| UDP 16 MB/s | 166,435 | 166,435 | 0 | 100.0% | 59 / 74 | 68.7 | yes |
| UDP 32 MB/s | 332,871 | 332,873 | 0 | 100.0% | 107 / 109 | 68.8 | yes |
| UDP 64 MB/s | 665,742 | 370,286 | 295,456 | 55.6% | 113 / 114 | 69.1 | NO |
| UDP 128 MB/s | 1,331,484 | 334,872 | 996,614 | 25.2% | 112 / 113 | 69.2 | NO |
| TCP 100 conn/s | 2,000 | 2,002 | 0 | 100.0% | 6 / 7 | 69.4 | yes |
| TCP 300 conn/s | 6,000 | 6,002 | 0 | 100.0% | 15 / 18 | 70.9 | yes |
| TCP 1000 conn/s | 20,000 | 20,002 | 0 | 100.0% | 38 / 41 | 74.4 | yes |
| TCP 3000 conn/s | 60,000 | 60,002 | 0 | 100.0% | 62 / 77 | 79.6 | yes |

Highest tested lossless load on the ThinkPad S1 Yoga: **32 MB/s UDP (about 22,000 packets/s) and 3,000 new TCP connections/s**.
At 64 MB/s it loses 44% of packets and at 128 MB/s 75%, all counted by the kernel drop counter. CPU over 100% means
more than one core is in use. The laptop handles less than the sandbox at the same rate (sandbox lost 12% at 64 MB/s).
The 250 evaluation trials never exceeded 16 MB/s. Detection quality under packet loss was not evaluated.

## Sandbox lab results (corroborating run, 2-vCPU cloud sandbox)
## Trials
375 planned trials (seed 20261110, plan SHA-256 `fdf34579bc5f...`): per category 45 attacks (15 tuning +
30 evaluation) and 15 near-threshold "hard negatives" (5 + 10); 45 normal-traffic trials (15 + 30);
30 known-evasion attacks (10 + 20). Attack parameters vary (e.g. 16 to 1,000 ports, 105 to 2,500
connections, 5 to 12 failed logins, 6 to 16 MB/s, four DNS indicators) and the first few positives of each
category sit just above the threshold on purpose.

### Sandbox evaluation split (rules frozen, 250 trials, none invalid)
| category | recall | precision | false-positive rate | latency attack start to event (median / p95 / max, s) |
|---|---|---|---|---|
| port_scan | 30/30 (95% CI 89-100%) | 30/30 | 0/200 (0-2%) | 0.82 / 3.78 / 3.99 |
| excessive_connections | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 1.60 / 3.87 / 7.00 |
| auth_failures | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 2.14 / 5.62 / 5.66 |
| abnormal_traffic | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 5.06 / 6.52 / 6.64 |
| suspicious_dns | 30/30 (89-100%) | 30/30 | 0/220 (0-2%) | 1.57 / 4.47 / 4.83 |

False positives: 0 on 30 normal-traffic trials, 0 on 10 hard negatives per category, 0 on other categories' attacks.
Threshold crossing to committed event: median 0.25-0.34 s, max 0.62 s (abnormal_traffic: about 0.002 s, because
its crossing is stamped at the evaluation tick; its 5 s latency is the 10 s averaging window filling).
Tuning split (125 trials): the same, 15/15 per category, 0 false positives. **No threshold was changed**
(nothing to correct); frozen set = code defaults plus the DNS watch list (suspicious_dns v2).

### What these numbers do and do not say
- 30/30 means "at least about 89% at 95% confidence", not "perfect".
- The positives and hard negatives were written by the same person who knows the thresholds. The test shows
  the rules behave as specified on real packets, including just above and just below threshold. It does not
  show how they behave on attacks nobody anticipated. Normal traffic is synthetic.
- **Known misses (documented, 0 of 20 detected):** UDP scan, FIN scan, NULL scan, Xmas scan and a slow scan
  (one port per 2 s) are not detected: the port-scan rule counts SYN-without-ACK ports in a 10 s window.
  Real nmap -sU/-sF/-sN/-sX scans are common, so this is a real coverage gap, not a corner case.
- Latency for auth_failures includes the log poll interval (0.5 s) and sshd's own timing.
- Single lab, single victim, one traffic generator (Python and nmap); not a statement about other networks.

### Sandbox resource use during the 250-trial evaluation
3,200,576 packets captured, 0 kernel drops; monitor CPU median 1%, p95 15%, max 31%; memory 70-71 MB.

### Sandbox capacity sweep (`lab/capacity.py`, 2-vCPU sandbox, 15 s per UDP step, 10 s per TCP step)
Sustained = no kernel drops and at least 99.9% of packets captured. Only these tested rates are reported.
| load | packets sent | captured | kernel drops | captured | CPU % median / max | RSS MB max | sustained |
|---|---|---|---|---|---|---|---|
| UDP 1 MB/s | 10,402 | 10,404 | 0 | 100.0% | 2 / 2 | 66.1 | yes |
| UDP 2 MB/s | 20,804 | 20,806 | 0 | 100.0% | 3 / 4 | 66.1 | yes |
| UDP 4 MB/s | 41,608 | 41,610 | 0 | 100.0% | 5 / 9 | 66.1 | yes |
| UDP 8 MB/s | 83,217 | 83,219 | 0 | 100.0% | 12 / 16 | 66.2 | yes |
| UDP 16 MB/s | 166,435 | 166,437 | 0 | 100.0% | 26 / 34 | 66.2 | yes |
| UDP 32 MB/s | 332,871 | 332,873 | 0 | 100.0% | 43 / 48 | 66.2 | yes |
| UDP 64 MB/s | 665,742 | 585,708 | 80,036 | 88.0% | 89 / 93 | 67.3 | NO |
| UDP 128 MB/s | 1,331,484 | 777,335 | 554,151 | 58.4% | 87 / 93 | 67.3 | NO |
| TCP 100 conn/s | 2,000 | 2,002 | 0 | 100.1% | 3 / 4 | 67.4 | yes |
| TCP 300 conn/s | 6,000 | 6,004 | 0 | 100.1% | 7 / 9 | 68.5 | yes |
| TCP 1000 conn/s | 20,000 | 20,002 | 0 | 100.0% | 19 / 21 | 72.5 | yes |
| TCP 3000 conn/s | 60,000 | 60,004 | 0 | 100.0% | 43 / 49 | 73.3 | yes |

Highest tested sustained load: **32 MB/s of UDP (about 22,000 packets/s) and 3,000 new TCP connections/s**,
no loss. At 64 MB/s the single capture process saturates one core (about 89%) and the kernel drops 12% of
packets (counted and reported by the monitor, not hidden); at 128 MB/s it drops 42%. Detection under packet
loss is not evaluated. These figures are for this sandbox's CPU; **rerun `sudo python lab/capacity.py` on
the ThinkPad S1 Yoga before quoting capacity for it.** The sender is Python, which is why very high rates
were not tested.

## Defect found while building the harness
With `NETGUARD_PROMISCUOUS=false` the monitor on the lab bridge captured 5 packets where 165,782 were
captured with it on (frames between other bridge ports are not addressed to the bridge). The Phase 3/4A
demos had passed only because their tcpdump oracle switched promiscuous mode on. Fixed in all lab scripts
(explicit setting) and documented in `docs/monitor.md`. Probable (not proven) cause of the unreproduced
"captured=3 parsed=0" run noted in the 4A checklist.


## Phase 7: end-to-end latency, whole-stack cost, API at scale, accessibility
Design and definitions: ADR 0019. Raw results: `lab/results/`. **The Kali figures (next subsection) are the
ones to quote**; the numbered sandbox sections after them are real runs of the same software in the 2-vCPU,
8 GB cloud sandbox (kernel 6.18) and corroborate them.

### Kali figures (ThinkPad S1 Yoga, i7-4500U, Kali kernel 6.19.14, Python 3.13.12, 2026-11-17): THE ONES TO QUOTE
Monitor non-root with only CAP_NET_RAW and CAP_NET_ADMIN on `br-lab` (promiscuous), API and PostgreSQL 18 on
the same laptop, the dashboard dev server and one browser session open during the runs.

**Alert latency** (`lab/e2e_latency.py`; 30 trials, 40-port `nmap -sS` from a fresh source address each time;
source `e2e-20261117T193022.json`). 30/30 alerts received on the WebSocket, 0 invalid. Seconds:

| step | median | p95 | max |
|---|---|---|---|
| scan process itself (included in the total) | 0.189 | 0.224 | 0.231 |
| scan start -> alert row written | 0.534 | 0.741 | 0.745 |
| alert row -> received on the WebSocket | 0.024 | 0.246 | 0.249 |
| **scan start -> alert on the WebSocket** | **0.561** | **0.776** | **0.988** |

Reading: a scan reaches a connected dashboard in about half a second, under one second in every trial. The
"alert row written" times fall in three groups (about 0.34, 0.53 and 0.74 s; 3, 21 and 6 trials). The steps of
about 0.2 s match the monitor's main loop on an idle lab: it waits up to 0.2 s for a packet and evaluates rules
every 0.5 s (`service.py`), so detection lands on one of a few ticks after the threshold is crossed. Delivery
from the database to the browser socket took 19-28 ms in 27 trials and about 0.245 s in 3; the cause of those
three was not investigated (the step is again about 0.2 s). Compared with the sandbox (median 0.702 s), the
laptop is faster end to end but has a wider spread.

**What the whole stack costs** (`lab/stack_resources.py`, 60 s per phase; source `stack-20261117T193413.json`).
CPU is percent of ONE core (median / p95 / max); memory is PSS in MB (median).

| phase | monitor CPU | monitor MB | API CPU | API MB | PostgreSQL CPU | PostgreSQL MB |
|---|---|---|---|---|---|---|
| idle (no dashboard clients, no lab traffic) | 0 / 1 / 1 | 51.9 | 0 / 1 / 1 | 69.8 | 0 / 1 / 1.9 | 61.4 |
| 5 dashboard clients | 0 / 1 / 1 | 51.9 | 1 / 4 / 5.7 | 70.2 | 0 / 2.2 / 3.9 | 62.3 |
| clients + 8 MB/s UDP | 52.4 / 59.9 / 62.5 | 51.9 | 1 / 4.7 / 5.7 | 70.1 | 0.9 / 2.0 / 3.6 | 62.5 |

455,163 packets captured during the run, 0 dropped. NetGuard's total memory is about 185 MB in the busiest
phase and does not grow between phases. At 8 MB/s the monitor needs about half of one core on this CPU (the
sandbox needed 11%; Phase 4B measured 65% at the same rate on this laptop with a different traffic mix). CPU
per packet depends on packet size and mix, so this figure does not by itself predict the 32 MB/s lossless limit
measured in Phase 4B with large UDP packets.

**API response times** (same run; 50 requests per endpoint; small tables: 148 per-second rows, 6,714 per-minute
rows, 130 events, 132 alerts). Milliseconds, p50 / p95 / max:

| endpoint | idle | under 8 MB/s UDP |
|---|---|---|
| /api/overview | 9.2 / 13.2 / 19.7 | 7.2 / 13.4 / 18.6 |
| /api/monitor/status | 4.7 / 5.6 / 6.2 | 4.8 / 6.1 / 7.7 |
| /api/traffic/series | 5.9 / 6.8 / 7.2 | 5.5 / 6.7 / 7.1 |
| /api/traffic/protocols | 6.3 / 8.6 / 9.0 | 5.3 / 6.1 / 7.3 |
| /api/traffic/top-talkers | 8.3 / 14.1 / 14.5 | 7.8 / 10.0 / 11.7 |
| /api/devices | 7.8 / 8.8 / 9.3 | 5.5 / 6.7 / 7.3 |
| /api/events | 7.3 / 13.6 / 15.0 | 5.9 / 7.2 / 7.5 |
| /api/alerts | 6.1 / 8.6 / 9.3 | 5.7 / 6.5 / 6.9 |
| /api/rules | 4.9 / 7.8 / 8.1 | 5.1 / 6.5 / 7.1 |

Every endpoint the dashboard uses answered within 20 ms, also while the monitor was capturing 8 MB/s.
**API at retention-sized tables on Kali** (`make stack-api-scale`, scratch database `netguard_scale` seeded
with 432,375 per-second and 864,020 per-minute synthetic rows and 20 devices, events and alerts empty; scratch
API only, no monitor or traffic; source `stack-apionly-20261118T050651.json`). Milliseconds, p50 / p95 / max:

| endpoint | p50 | p95 | max |
|---|---|---|---|
| /api/overview | 9.8 | 11.4 | 17.2 |
| /api/monitor/status | 4.2 | 5.5 | 6.0 |
| /api/traffic/series (15 min, as the dashboard asks) | 8.1 | 9.4 | 15.7 |
| /api/traffic/protocols | 10.6 | 12.7 | 20.3 |
| /api/traffic/top-talkers (1 h) | 9.5 | 12.2 | 13.7 |
| /api/devices | 7.2 | 15.5 | 16.3 |
| /api/events | 6.0 | 7.6 | 15.4 |
| /api/alerts | 6.6 | 8.7 | 10.8 |
| /api/rules | 5.9 | 14.3 | 16.7 |
| traffic series, 24 h, 60 s buckets (widest allowed) | 253.2 | 274.8 | 285.8 |
| protocols, 24 h | 128.1 | 133.5 | 139.1 |
| top talkers, 30 days (widest allowed) | 378.3 | 722.6 | 766.3 |

Every request returned 200. What the dashboard asks for stays within about 20 ms with the tables at their
retention limits; the widest ranges the API allows take up to about 0.3 s (24 h) and 0.77 s (30-day top
talkers). The laptop is about 1.2-1.7x slower than the sandbox on the wide ranges (sandbox: 208 / 89 / 223 ms
p50). Same limits as the sandbox scale test: synthetic counters, empty events and alerts tables.
Limits as for the sandbox runs: minutes, not hours; one lab; one victim; at most 5 simulated clients.

### 1. Alert latency, scan start to the dashboard feed (`lab/e2e_latency.py`, sandbox)
30 trials, each a 40-port `nmap -sS` from a fresh source address, alert received on `/api/ws`.
30/30 detected (high), 0 invalid. Seconds:

| step | median | p95 | max |
|---|---|---|---|
| scan process itself (included in the total) | 0.140 | 0.166 | 0.173 |
| scan start -> alert row written | 0.693 | 0.716 | 0.740 |
| alert row -> received on the WebSocket | 0.007 | 0.011 | 0.012 |
| **scan start -> alert on the WebSocket** | **0.702** | **0.722** | **0.747** |

Reading: pushing an alert to a connected dashboard takes about 10 ms; almost all of the 0.7 s is the monitor
noticing and committing the detection (it agrees with the 0.76 s median attack-start-to-event measured on Kali
in Phase 4B). The alert row timestamp is the start of the committing transaction, so the last step includes the
commit. Source: `lab/results/e2e-20261112T194914.json`.
Limits: one scan type, one victim, an otherwise idle lab, one clock. Latency under heavy load was not measured.

### 2. What the whole stack costs (`lab/stack_resources.py`, sandbox, 60 s per phase)
CPU is percent of ONE core (median / p95 / max); memory is PSS in MB (median). 5 simulated dashboard clients
(a WebSocket plus the Overview page's polling) and, in the last phase, UDP at 8 MB/s (332,871 packets sent,
achieved 8.0 MB/s).

| phase | monitor CPU | monitor MB | API CPU | API MB | PostgreSQL CPU | PostgreSQL MB |
|---|---|---|---|---|---|---|
| idle (no dashboard, no lab traffic) | 0 / 1 / 1 | 51.7 | 0 / 1 / 1 | 68.7 | 0 / 1 / 1 | 44.4 |
| 5 dashboard clients | 0 / 1 / 1 | 51.6 | 1 / 3 / 4 | 71.4 | 0 / 2 / 2 | 56.0 |
| clients + 8 MB/s UDP | 10.9 / 14.8 / 20.6 | 51.6 | 1 / 3 / 3.9 | 71.0 | 0 / 2 / 2 | 57.1 |

469,477 packets captured during the run, 0 dropped. Total NetGuard memory is about 180 MB in the busiest phase.
CPU is sampled once a second, so small values are coarse. Source: `lab/results/stack-20261112T194618.json`.
Limits: a short run (minutes, not hours); no growth-over-time measurement; the sandbox CPU is not the laptop's
(on the laptop the monitor needed 65% of a core at 8 MB/s in Phase 4B, far more than here).

### 3. API response times (`lab/stack_resources.py`, sandbox)
Milliseconds, 50 requests per endpoint, p50 / p95 / max. With small tables (about 300 and 2,000 rows) and with
the same 8 MB/s UDP load running at the same time, every endpoint the dashboard uses answered in under 11 ms at
p95 and under 16 ms at the worst request (`stack-20261112T194618.json`).

**At retention-sized tables.** A fresh database says little, so a scratch database was filled with synthetic rows
to the monitor's retention limits: 432,000 per-second rows (24 h x 5 protocols) and 864,000 per-minute rows
(30 days x 20 flows per minute). The rows are random counters, not detection data (ADR 0019).

| endpoint (range) | p50 | p95 | max |
|---|---|---|---|
| overview, monitor status, series (15 min), protocols, top talkers (1 h), devices, events, alerts, rules: what the dashboard asks for | 2.8 - 7.2 | 3.3 - 11.7 | 3.5 - 16.3 |
| traffic series, 24 h range, 60 s buckets (widest allowed) | 208 | 282 | 290 |
| protocols, 24 h range | 89 | 120 | 131 |
| top talkers, 30 days (widest allowed), after the fix below | 223 | 578 | 623 |

Sources: `stack-apionly-20261112T193112.json` (after the fix), `stack-apionly-20261112T192846.json` (before it).
Widest-range rows used 15 requests each, the others 30.

**Finding and fix.** Before the fix, top talkers over 30 days took 1,538 ms at the median and up to 3,388 ms,
because `count(DISTINCT (dst_ip, dst_port, transport))` was computed over 864,000 rows. The query now groups by
flow first and counts the groups: same results (a test compares it with the original query on the same rows,
for both directions and both orderings, and three deliberate breaks of the new query are each caught), and the
database time on this data fell from 1,251 ms to 152 ms. The dashboard never asks for 30 days today, so no page
was slow, but the API allows it.
Limits: the events and alerts tables were empty in the scale database (they are small in practice and are read
by primary-key pagination, but that was not measured at size); more than 5 simultaneous clients was not tested.

### 4. Accessibility, automated (`lab/a11y_audit.py`, axe-core 4.10.2, sandbox)
Every page signed in plus the login page, the add-user dialog, light and dark, 1280 px and 390 px: 36 views,
WCAG 2.0/2.1 A and AA and axe best-practice rules.
First run: **30 of 36 views had violations**: (a) the brand sat outside any landmark (28 views); (b) text contrast
too low (20 views): secondary grey text 3.5:1 in light theme, white text on the light-teal primary button 2.1:1
in dark theme, and, found on the second run, teal text in the "Active" tag 4.3:1. Fixed by moving the brand into the header
landmark and by new colour tokens (`--ink-faint` and `--ink-soft` darkened, `--on-sea`, `--sea-text`). After the
fixes: **0 violations in 36 views** (`a11y-20261112T193653.json`; first run `a11y-20261112T193333.json`).
axe could not decide the contrast of the chart's axis labels (it cannot read the background behind SVG text);
their computed colours were checked directly: 7.5:1 in light theme and 9.0:1 in dark theme (minimum 4.5:1).
**Not checked** (automated tools miss these): keyboard-only operation and focus order by hand, a screen reader,
200% and 400% zoom reflow, reduced-motion behaviour, forced-colours mode. The dialog is the native `<dialog>`
element (focus trap and Escape come from the browser) but was not tested with assistive technology.

### 5. Parser throughput on the Kali laptop (`lab/bench_parser.py`, Kali, 2026-11-17)
Same frames for both parsers, 20,000 frames per measurement, three runs, Python 3.13.12, Intel i7-4500U
(the monitor was running but idle).

| parser | frames/s (three runs) | relative |
|---|---|---|
| netguard parser | 249,860 / 234,013 / 249,729 | 1x |
| Scapy `Ether(b)[IP].src` | 4,313 / 4,278 / 4,270 | 55-58x slower |
| Scapy src/dst/port | 3,960 / 4,025 / 3,998 | 58-63x slower |

The sandbox measured 397,129 vs 8,395 (47x, ADR 0011): the laptop is slower in absolute terms, the gap is
wider. Parsing alone is about 4 microseconds a frame; the monitor's limit at high rates is elsewhere (the
Phase 4B capacity sweep found loss starting above 32 MB/s on this laptop).

### Defects found by the Phase 7 work
- The latency harness first reused a source address that still had an open event, so the scan merged into the
  old event and raised no alert (counted as a miss). It now only uses addresses without an open event.
- The resource harness counted a second API process (a scale-test API on another port) as NetGuard's cost and
  doubled the API memory figure. It now refuses to run with more than one monitor or API process.
- Top talkers over 30 days was slow (above); the dashboard's own ranges were never affected.
- Four accessibility defects (above).
- (Earlier, same cause as Phase 4B) a monitor without `NETGUARD_PROMISCUOUS=true` captured 5 packets in 24 minutes
  on Kali while the dashboard header still said "live". Both harnesses now stop with a message pointing at it.

### Re-running the Phase 7 measurements on Kali
```
make lab-up; set NETGUARD_PROMISCUOUS=true in .env; make monitor-run   # terminal 1
make run-api                                                          # terminal 2
make e2e-latency ADMIN=<admin>        # about 3 minutes; prompts for the password
make stack-resources ADMIN=<admin>    # about 5 minutes
# API at retention-sized tables (stop the normal API first, so only the scratch one runs):
make scale-db-up && make seed-scale
NETGUARD_DB_NAME=netguard_scale make create-admin USERNAME=<admin>
NETGUARD_DB_NAME=netguard_scale NETGUARD_API_PORT=8001 make run-api   # separate terminal
make stack-api-scale ADMIN=<admin>
make scale-db-down
make bench-parser                     # the deferred parser benchmark
```
