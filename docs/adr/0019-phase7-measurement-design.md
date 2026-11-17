# ADR 0019: How Phase 7 measures the finished system

Status: accepted, 2026-11-12

## Context
Phase 4B already measured detection quality (250 trials) and capture capacity on the Kali machine. What was
still unmeasured: how long an alert takes to reach the dashboard, what the whole stack costs, how fast the API
answers when the tables are full, and whether the dashboard is usable with assistive technology.

## Decisions
1. **Measure the system as it is run, not a copy of it.** The harnesses (`lab/e2e_latency.py`,
   `lab/stack_resources.py`) start nothing. They need the real monitor, API and PostgreSQL already running and
   refuse to run otherwise. `stack_resources.py` also refuses when it finds a second monitor or API process,
   because it would be counted as NetGuard's own cost (this happened once in the sandbox and inflated the API
   figure from 70 MB to 145 MB).
2. **End-to-end latency means: scan process started -> alert received on `/api/ws`**, the same socket the
   dashboard uses. Every trial uses a fresh source address, because an address with an open event would merge
   the scan into that event and raise no alert (ADR 0013). The harness picks only addresses without an open event.
   A trial with no alert in 15 s is a miss and is reported; a scan that fails to run is invalid and listed.
   Timestamps come from one machine's clock. `alert.created_at` is the database `now()`, the start of the
   committing transaction, so the "delivery" step includes the commit.
3. **Resource figures are CPU % of one core and PSS memory** (RSS if PSS is unreadable, and the output says
   which). Only NetGuard's processes are counted; the load generator, browsers and the harness are not.
4. **Table size is controlled with a clearly labelled synthetic seed.** A fresh database cannot show how queries
   behave at retention limits, so `lab/seed_scale.py` fills a scratch database (`netguard_scale`) with random
   counters on documented key patterns (24 h of per-second rows, 30 days of per-minute rows). It refuses to run on
   any database that is not named `*scale*` or that is the development database. These rows are not detection
   results and are never mixed into any detection figure. The scratch database is created and dropped by
   `scripts/scale_db.sh`.
5. **Accessibility: automated axe-core audit, with its limits stated.** It runs every page in light and dark at
   desktop and phone width plus one dialog, and fails the run on any violation. Automated tools find only part of
   the problems; the checklist lists what was not checked by hand.
6. **Sandbox figures corroborate; Kali figures are the ones to quote** (same rule as ADR 0015).

## Consequences
- Re-running a harness within about 5 minutes needs enough free addresses; the harness says so and stops.
- The scale test needs `sudo` to the postgres OS user (to create and drop the scratch database).
- Results are single-machine, single-lab figures and say nothing about other networks.
