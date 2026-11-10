# ADR 0013: Event lifecycle in the detection engine
Status: accepted.

**Rules detect; the engine decides what is an event.** A rule returns a `Detection` every time its
condition holds. The engine turns the stream of detections into persistence *ops*:

- `open`: first detection for a dedup key. Carries the rule id **and version**, evidence, title.
- `hit`: further detections, coalesced and flushed at most every 2 s (a scan produces thousands
  of detections per second; one row update per detection would be the bottleneck).
- `hit` with `escalate`: a higher severity is sent immediately and raises one more alert.
- `close`: no detection for `cooldown_seconds`. Pending hits are flushed first.

**Cooldown means "quiet period that ends a window".** An attack that pauses for less than the
cooldown stays one event; a new burst after it is a new event and a new alert. (Alternative
rejected: suppressing detections for N seconds after a close - it would hide a real second attack.)

**Ops travel in the existing exactly-once batches** (`ingest_batches` ledger, spill-to-disk,
idempotent replay). The alert and its `pg_notify('ids_alerts', id)` are written in the same
transaction as the event, so a rolled-back write sends no notification (tested). NOTIFY stays
transient: a consumer that was not listening re-queries the table by cursor (Phase 5).

**Database arbitration.** `open` uses `INSERT ... ON CONFLICT (dedup_key) WHERE is_open DO UPDATE`;
if the key is already open (monitor restarted, or two ops raced) the rows merge and **no second
alert is raised**. `hit` and `close` address the open row by dedup key (`AND is_open`), so a late
hit can never modify a closed event (tested, mutation-checked). Severity can only rise within a
window (enforced in SQL).

**Restart.** Events still open in the database are loaded at start-up (`restore_open`) so they
continue to coalesce and close normally. In-memory detection windows are *not* restored: a restart
forgets partial counts (a documented, bounded loss of at most one window).

**Shutdown.** Pending hits are flushed, open events are left open (they resume or are closed by the
next run's cooldown).
