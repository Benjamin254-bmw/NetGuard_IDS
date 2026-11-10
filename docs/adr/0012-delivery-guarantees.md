# ADR 0012: Delivery guarantees of the monitor pipeline
Status: accepted.

Capture never waits on analysis or the database: capture -> bounded queue -> analyzer -> bounded
write queue -> writer. Every place data can be lost is counted and surfaced in the heartbeat.

| Stage | Failure | Behaviour | Visible as |
|---|---|---|---|
| Kernel buffer | reader too slow | kernel drops, counted via PACKET_STATISTICS | `kernel_drops` |
| Capture queue | analyzer too slow | frame dropped, counted | `capture_queue_drops`, `capture_queue_saturated` |
| Flow table | scan creates unbounded keys | per-minute key cap; per-second totals stay exact | `flow_cap_reached` |
| Write queue | database too slow | batch spills to disk instead of being dropped | `spill_backlog` |
| Database | outage | retry with backoff, then spill; fail fast while known down; replay on recovery | `database_unavailable` |
| Spill | size cap reached | batch lost, counted | `data_loss_spill_full` (permanent flag) |
| Shutdown | stop requested | kernel buffer drained (2 s bound), final flush, queues drained | none lost (tested) |

Exactly-once: each batch has a UUID recorded in `ingest_batches` in the same transaction as its
data. Replaying a spilled batch, retrying, or re-applying after a crash between commit and file
deletion cannot double count (tested, including by mutation). A batch that fails part-way leaves no
ledger row, so it can be retried whole.

Heartbeat: one row updated every 5 s. If the monitor dies, `heartbeat_at` goes stale; consumers
must treat a stale heartbeat as "not monitoring" regardless of the last state written.

Not guaranteed: packets dropped by the kernel before the socket sees them (e.g. NIC overruns) and
anything on a switched LAN the sensor port cannot see. These are documented limitations, not
silent ones.
