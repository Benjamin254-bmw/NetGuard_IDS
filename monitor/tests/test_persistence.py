"""Database-backed tests for the monitor's persistence layer (exactly-once, outage, replay)."""

import threading
import time
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError, OperationalError

from dbhelpers import needs_db, run
from netguard_monitor.persistence.retention import prune
from netguard_monitor.persistence.spill import Batch, SpillStore
from netguard_monitor.persistence.status import StatusSnapshot, write_status
from netguard_monitor.persistence.writer import (
    BatchWriter,
    WriteQueue,
    WriterState,
    apply_batch,
    new_batch,
)

pytestmark = needs_db
MINUTE = 1_700_000_040


def traffic(
    packets: int = 10, nbytes: int = 1000, proto: str = "tcp", sec: int = MINUTE + 5
) -> dict[str, Any]:
    return {
        "traffic_1s": [[sec, proto, packets, nbytes, 2]],
        "flows_1m": [[MINUTE, "10.10.10.30", "10.10.10.10", 80, "tcp", "http", packets, nbytes, 2]],
    }


def totals(db: dict[str, Engine]) -> tuple[int, int, int, int]:
    one = run(
        db["migrator"],
        "SELECT coalesce(sum(packets),0), coalesce(sum(bytes),0) FROM traffic_stats_1s",
    )[0]
    flow = run(
        db["migrator"],
        "SELECT coalesce(sum(packets),0), coalesce(sum(syn_count),0) FROM connection_aggregates_1m",
    )[0]
    return int(one[0]), int(one[1]), int(flow[0]), int(flow[1])


def apply(db: dict[str, Engine], b: Batch) -> bool:
    with db["monitor"].begin() as conn:
        return apply_batch(conn, b)


def test_distinct_batches_accumulate(db: dict[str, Engine]) -> None:
    assert apply(db, new_batch("traffic", traffic(10, 1000)))
    assert apply(db, new_batch("traffic", traffic(5, 400)))
    assert totals(db) == (15, 1400, 15, 4)


def test_the_same_batch_is_applied_exactly_once(db: dict[str, Engine]) -> None:
    b = new_batch("traffic", traffic(10, 1000))
    assert apply(db, b) is True
    assert apply(db, b) is False  # a replay of an already-applied batch
    assert apply(db, b) is False
    assert totals(db) == (10, 1000, 10, 2)


def test_a_failing_batch_leaves_no_ledger_entry_so_it_can_be_retried(db: dict[str, Engine]) -> None:
    bad = new_batch("traffic", traffic(proto="not_a_protocol"))
    with pytest.raises(IntegrityError):
        apply(db, bad)
    assert run(db["migrator"], "SELECT count(*) FROM ingest_batches")[0][0] == 0
    assert totals(db) == (0, 0, 0, 0)  # nothing partially applied


def test_unknown_batch_kind_is_rejected_atomically(db: dict[str, Engine]) -> None:
    with pytest.raises(ValueError, match="unknown batch kind"):
        apply(db, new_batch("bogus", {}))
    assert run(db["migrator"], "SELECT count(*) FROM ingest_batches")[0][0] == 0


def dev(
    ip: str,
    mac: str | None,
    first: float,
    last: float,
    status: str = "active",
    src: str = "traffic",
) -> dict[str, Any]:
    return {
        "ip": ip,
        "mac": mac,
        "first_seen": first,
        "last_seen": last,
        "status": status,
        "source": src,
    }


def devices(db: dict[str, Engine]) -> list[tuple[str, str | None, str]]:
    rows = run(db["migrator"], "SELECT host(ip), mac::text, status FROM devices ORDER BY ip, mac")
    return [(r[0], r[1], r[2]) for r in rows]


def test_device_lifecycle_through_the_database(db: dict[str, Engine]) -> None:
    apply(db, new_batch("devices", [dev("10.10.10.30", None, 100, 100)]))
    assert devices(db) == [("10.10.10.30", None, "active")]
    apply(db, new_batch("devices", [dev("10.10.10.30", None, 100, 200)]))  # refresh: no duplicate
    assert len(devices(db)) == 1
    apply(
        db,
        new_batch(
            "devices", [dev("10.10.10.30", "aa:bb:cc:00:00:30", 100, 210, src="passive_arp")]
        ),
    )
    assert devices(db) == [
        ("10.10.10.30", "aa:bb:cc:00:00:30", "active")
    ]  # MAC adopted, still one row
    apply(
        db,
        new_batch(
            "devices",
            [dev("10.10.10.30", "aa:bb:cc:00:00:30", 100, 500, "inactive", "passive_arp")],
        ),
    )
    assert devices(db)[0][2] == "inactive"
    first, last = run(db["migrator"], "SELECT first_seen, last_seen FROM devices")[0]
    assert (last - first).total_seconds() == 400  # first_seen kept, last_seen advanced


def test_ip_reassigned_to_other_hardware_keeps_history(db: dict[str, Engine]) -> None:
    apply(
        db,
        new_batch("devices", [dev("10.10.10.50", "aa:aa:aa:aa:aa:01", 1, 10, src="passive_arp")]),
    )
    apply(
        db,
        new_batch(
            "devices",
            [
                dev("10.10.10.50", "aa:aa:aa:aa:aa:01", 1, 50, "inactive", "passive_arp"),
                dev("10.10.10.50", "bb:bb:bb:bb:bb:02", 50, 50, src="passive_arp"),
            ],
        ),
    )
    assert devices(db) == [
        ("10.10.10.50", "aa:aa:aa:aa:aa:01", "inactive"),
        ("10.10.10.50", "bb:bb:bb:bb:bb:02", "active"),
    ]


class FlakyEngine:
    """Delegates to a real engine but fails `fail_next` calls first, or always while `down`."""

    def __init__(self, real: Engine) -> None:
        self.real, self.down, self.fail_next, self.calls = real, False, 0, 0

    def begin(self) -> Any:
        self.calls += 1
        if self.down or self.fail_next > 0:
            self.fail_next = max(0, self.fail_next - 1)
            raise OperationalError("stmt", {}, Exception("connection refused"))
        return self.real.begin()


def start_writer(
    db: dict[str, Engine], tmp: Path, *, queue_size: int = 50, cap: int = 10**7
) -> tuple[FlakyEngine, WriteQueue, BatchWriter, SpillStore, WriterState]:
    engine = FlakyEngine(db["monitor"])
    spill = SpillStore(tmp / "spill", cap)
    state = WriterState()
    wq = WriteQueue(queue_size, spill, state)
    writer = BatchWriter(engine, wq, spill, state, retries=3, backoff=0.0)  # type: ignore[arg-type]
    return engine, wq, writer, spill, state


def run_to_completion(wq: WriteQueue, writer: BatchWriter) -> None:
    writer.start()
    wq.close()
    writer.join(timeout=15)
    assert not writer.is_alive()


def test_transient_failure_is_retried_without_spilling(
    db: dict[str, Engine], tmp_path: Path
) -> None:
    engine, wq, writer, spill, state = start_writer(db, tmp_path)
    engine.fail_next = 2
    wq.submit(new_batch("traffic", traffic(7, 700)))
    run_to_completion(wq, writer)
    assert (state.written, state.spilled, spill.backlog, state.db_ok) == (1, 0, 0, True)
    assert totals(db) == (7, 700, 7, 2)


def test_outage_spills_and_recovery_replays_everything_exactly_once(
    db: dict[str, Engine], tmp_path: Path
) -> None:
    engine, wq, writer, spill, state = start_writer(db, tmp_path)
    engine.down = True
    for n in (1, 2, 3):
        wq.submit(new_batch("traffic", traffic(n, n * 100, sec=MINUTE + n)))
    writer.start()
    deadline = time.time() + 15
    while state.spilled < 3 and time.time() < deadline:
        time.sleep(0.05)
    assert (state.spilled, spill.backlog, state.db_ok, state.last_error) == (
        3,
        3,
        False,
        "OperationalError",
    )
    assert totals(db) == (0, 0, 0, 0)  # nothing reached the database during the outage
    engine.down = False  # the database comes back
    deadline = time.time() + 15
    while spill.backlog and time.time() < deadline:
        time.sleep(0.1)
    wq.close()
    writer.join(timeout=15)
    assert (spill.backlog, state.replayed, state.db_ok, state.spill_dropped) == (0, 3, True, 0)
    assert totals(db) == (6, 600, 6, 6)  # (1+2+3) packets, no loss, no duplicates


def test_first_failure_is_retried_but_later_ones_fail_fast_while_the_db_is_down(
    db: dict[str, Engine], tmp_path: Path
) -> None:
    engine, _wq, writer, spill, state = start_writer(db, tmp_path)
    engine.down = True
    writer.process(new_batch("traffic", traffic(1)))  # deterministic: no thread
    assert (engine.calls, state.db_ok, spill.backlog) == (3, False, 1)  # 3 attempts, then spilled
    writer.process(new_batch("traffic", traffic(2)))
    writer.process(new_batch("traffic", traffic(3)))
    assert (engine.calls, spill.backlog) == (5, 3)  # one attempt each: the queue is not stalled


def test_replaying_a_batch_that_was_already_committed_does_not_double_count(
    db: dict[str, Engine], tmp_path: Path
) -> None:
    """Simulates a crash after the database commit but before the spill file was deleted."""
    engine, wq, writer, spill, state = start_writer(db, tmp_path)
    b = new_batch("traffic", traffic(10, 1000))
    apply(db, b)  # committed...
    spill.write(b)  # ...but the spill copy survived the crash
    run_to_completion(wq, writer)
    assert (spill.backlog, state.replayed) == (0, 1)
    assert totals(db) == (10, 1000, 10, 2)


def test_full_write_queue_spills_instead_of_dropping(db: dict[str, Engine], tmp_path: Path) -> None:
    _engine, wq, _writer, spill, state = start_writer(db, tmp_path, queue_size=1)
    for n in range(4):
        wq.submit(new_batch("traffic", traffic(n + 1)))
    assert (wq.depth, state.spilled, spill.backlog, state.spill_dropped) == (1, 3, 3, 0)


def test_losing_data_is_counted_when_the_spill_cap_is_reached(
    db: dict[str, Engine], tmp_path: Path
) -> None:
    _engine, wq, _writer, spill, state = start_writer(db, tmp_path, queue_size=1, cap=300)
    for n in range(5):
        wq.submit(new_batch("traffic", traffic(n + 1)))
    assert state.spill_dropped >= 1 and spill.bytes_used() <= 300


def test_writer_drains_the_queue_before_stopping(db: dict[str, Engine], tmp_path: Path) -> None:
    _engine, wq, writer, _spill, state = start_writer(db, tmp_path)
    for n in range(1, 21):
        wq.submit(new_batch("traffic", traffic(n, n, sec=MINUTE + n)))
    run_to_completion(wq, writer)
    assert state.written == 20 and totals(db)[0] == sum(range(1, 21))


def test_retention_deletes_only_expired_rows_in_batches(db: dict[str, Engine]) -> None:
    now = float(MINUTE + 10 * 86400)
    day = 86400
    for age_days, minute_off in ((2, 0), (0, 1)):  # 1s table: keep 24h, so the 2-day-old row goes
        sec = int(now - age_days * day) + minute_off
        run(
            db["monitor"],
            "INSERT INTO traffic_stats_1s (bucket_start, protocol, packets, bytes) VALUES (to_timestamp(:s), 'tcp', 1, 1)",
            s=sec,
        )
    for age_days in (40, 35, 31, 29, 1):  # 1m table: keep 30 days: three expired rows
        minute = int((now - age_days * day) // 60) * 60
        run(
            db["monitor"],
            "INSERT INTO connection_aggregates_1m (bucket_start, src_ip, dst_ip, dst_port, transport, packets, bytes) "
            "VALUES (to_timestamp(:m), '10.10.10.30', '10.10.10.10', 80, 'tcp', 1, 1)",
            m=minute,
        )
    run(
        db["migrator"],
        "INSERT INTO ingest_batches (batch_id, applied_at) VALUES (gen_random_uuid(), to_timestamp(:t))",
        t=now - 8 * day,
    )
    run(
        db["migrator"],
        "INSERT INTO ingest_batches (batch_id, applied_at) VALUES (gen_random_uuid(), to_timestamp(:t))",
        t=now - 1 * day,
    )
    out = prune(db["monitor"], now, retention_1s_hours=24, retention_1m_days=30, batch_size=2)
    assert out == {"traffic_stats_1s": 1, "connection_aggregates_1m": 3, "ingest_batches": 1}
    left = {t: run(db["migrator"], f"SELECT count(*) FROM {t}")[0][0] for t in out}
    assert left == {"traffic_stats_1s": 1, "connection_aggregates_1m": 2, "ingest_batches": 1}
    assert prune(db["monitor"], now, 24, 30) == {
        "traffic_stats_1s": 0,
        "connection_aggregates_1m": 0,
        "ingest_batches": 0,
    }


def test_heartbeat_is_a_single_row_that_advances(db: dict[str, Engine]) -> None:
    snap = StatusSnapshot("running", "br-lab", time.time(), packets_captured=10, version="0.1.0")
    write_status(db["monitor"], snap)
    t1 = run(db["migrator"], "SELECT heartbeat_at FROM monitor_status")[0][0]
    time.sleep(0.05)
    snap.state, snap.packets_dropped, snap.degraded_reasons = "degraded", 4, ["kernel_drops"]
    write_status(db["monitor"], snap)
    rows = run(
        db["migrator"],
        "SELECT state, packets_dropped, degraded_reasons, heartbeat_at, interface FROM monitor_status",
    )
    assert len(rows) == 1
    assert (rows[0][0], rows[0][1], rows[0][2], rows[0][4]) == (
        "degraded",
        4,
        ["kernel_drops"],
        "br-lab",
    )
    assert rows[0][3] > t1


def test_heartbeat_rejects_nonsense(db: dict[str, Engine]) -> None:
    with pytest.raises(IntegrityError):
        write_status(db["monitor"], StatusSnapshot("running", "x", None, packets_captured=-1))


def test_threads_do_not_corrupt_counts_under_concurrent_batches(db: dict[str, Engine]) -> None:
    errors: list[BaseException] = []

    def worker(k: int) -> None:
        try:
            for i in range(10):
                apply(db, new_batch("traffic", traffic(1, 10, sec=MINUTE + k * 100 + i)))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == [] and totals(db)[0] == 40 and totals(db)[2] == 40
