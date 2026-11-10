"""Batch application and the writer thread.

apply_batch() records the batch id in the ledger and applies the data in ONE transaction, so a
batch takes effect at most once no matter how often it is retried or replayed from the spill.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import SQLAlchemyError

from netguard_monitor.persistence.spill import Batch, SpillStore

log = logging.getLogger(__name__)

_LEDGER = text(
    "INSERT INTO ingest_batches (batch_id) VALUES (CAST(:b AS uuid)) ON CONFLICT DO NOTHING"
)
_TRAFFIC_1S = text(
    """
    INSERT INTO traffic_stats_1s (bucket_start, protocol, packets, bytes, new_connections)
    VALUES (to_timestamp(:sec), :protocol, :packets, :bytes, :new)
    ON CONFLICT (bucket_start, protocol) DO UPDATE SET
      packets = traffic_stats_1s.packets + EXCLUDED.packets,
      bytes = traffic_stats_1s.bytes + EXCLUDED.bytes,
      new_connections = traffic_stats_1s.new_connections + EXCLUDED.new_connections
    """
)
_FLOWS_1M = text(
    """
    INSERT INTO connection_aggregates_1m
      (bucket_start, src_ip, dst_ip, dst_port, transport, app_protocol, packets, bytes, syn_count)
    VALUES (to_timestamp(:minute), CAST(:src AS inet), CAST(:dst AS inet), :port, :transport,
            :app, :packets, :bytes, :syn)
    ON CONFLICT (bucket_start, src_ip, dst_ip, dst_port, transport) DO UPDATE SET
      packets = connection_aggregates_1m.packets + EXCLUDED.packets,
      bytes = connection_aggregates_1m.bytes + EXCLUDED.bytes,
      syn_count = connection_aggregates_1m.syn_count + EXCLUDED.syn_count,
      app_protocol = COALESCE(EXCLUDED.app_protocol, connection_aggregates_1m.app_protocol)
    """
)
_ADOPT_MAC = text(
    """
    UPDATE devices SET mac = CAST(:mac AS macaddr)
    WHERE ip = CAST(:ip AS inet) AND mac IS NULL
      AND NOT EXISTS (SELECT 1 FROM devices d2 WHERE d2.mac = CAST(:mac AS macaddr))
    """
)
_UPSERT_BY_MAC = text(
    """
    INSERT INTO devices (ip, mac, status, discovery_source, first_seen, last_seen)
    VALUES (CAST(:ip AS inet), CAST(:mac AS macaddr), :status, :source,
            to_timestamp(:first), to_timestamp(:last))
    ON CONFLICT (mac) WHERE mac IS NOT NULL DO UPDATE SET
      ip = EXCLUDED.ip, status = EXCLUDED.status,
      first_seen = LEAST(devices.first_seen, EXCLUDED.first_seen),
      last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen)
    """
)
_TOUCH_BY_IP = text(
    """
    UPDATE devices SET status = :status, last_seen = GREATEST(last_seen, to_timestamp(:last))
    WHERE id = (SELECT id FROM devices WHERE ip = CAST(:ip AS inet) ORDER BY last_seen DESC LIMIT 1)
    """
)
_INSERT_NO_MAC = text(
    """
    INSERT INTO devices (ip, status, discovery_source, first_seen, last_seen)
    VALUES (CAST(:ip AS inet), :status, :source, to_timestamp(:first), to_timestamp(:last))
    """
)


_RANK = "ARRAY['informational','low','medium','high','critical']"
_EV_OPEN = text(
    """
    INSERT INTO security_events
      (event_uuid, category, rule_id, rule_version, severity, src_ip, dst_ip, dst_port, protocol,
       description, evidence, dedup_key, hit_count, detected_at, last_seen_at)
    VALUES (CAST(:uuid AS uuid), :category, :rule_id, :rule_version, :severity,
            CAST(:src AS inet), CAST(:dst AS inet), :port, :protocol, :description,
            CAST(:evidence AS jsonb), :dedup_key, :hits, to_timestamp(:detected),
            to_timestamp(:detected))
    ON CONFLICT (dedup_key) WHERE is_open DO UPDATE SET
      hit_count = security_events.hit_count + EXCLUDED.hit_count,
      last_seen_at = GREATEST(security_events.last_seen_at, EXCLUDED.last_seen_at),
      evidence = EXCLUDED.evidence,
      severity = CASE WHEN array_position(@RANK@, EXCLUDED.severity::text)
                           > array_position(@RANK@, security_events.severity::text)
                      THEN EXCLUDED.severity ELSE security_events.severity END
    RETURNING id, (xmax = 0) AS inserted
    """.replace("@RANK@", _RANK)
)
_EV_HIT = text(
    """
    UPDATE security_events SET
      hit_count = hit_count + :hits,
      last_seen_at = GREATEST(last_seen_at, to_timestamp(:last_seen)),
      evidence = CAST(:evidence AS jsonb),
      severity = CASE WHEN array_position(@RANK@, CAST(:severity AS text))
                           > array_position(@RANK@, severity::text)
                      THEN CAST(:severity AS text) ELSE severity::text END
    WHERE dedup_key = :dedup_key AND is_open
    RETURNING id
    """.replace("@RANK@", _RANK)
)
_EV_CLOSE = text(
    "UPDATE security_events SET is_open = false WHERE dedup_key = :dedup_key AND is_open"
)
_ALERT = text(
    """
    INSERT INTO alerts (event_id, severity, title) VALUES (:event_id, :severity, :title)
    RETURNING id
    """
)
_NOTIFY = text("SELECT pg_notify('ids_alerts', CAST(:id AS text))")


def _alert(conn: Connection, event_id: int, severity: str, title: str) -> None:
    alert_id = conn.execute(
        _ALERT, {"event_id": event_id, "severity": severity, "title": title}
    ).scalar_one()
    conn.execute(_NOTIFY, {"id": alert_id})  # delivered only if this transaction commits


def _apply_events(conn: Connection, ops: list[dict[str, Any]]) -> None:
    for op in ops:
        kind = op["op"]
        if kind == "open":
            row = conn.execute(
                _EV_OPEN,
                {
                    "uuid": op["event_uuid"],
                    "category": op["category"],
                    "rule_id": op["rule_id"],
                    "rule_version": op["rule_version"],
                    "severity": op["severity"],
                    "src": op["src_ip"],
                    "dst": op["dst_ip"],
                    "port": op["dst_port"],
                    "protocol": op["protocol"],
                    "description": op["description"],
                    "evidence": json.dumps(op["evidence"]),
                    "dedup_key": op["dedup_key"],
                    "hits": op["hits"],
                    "detected": op["detected_at"],
                },
            ).one()
            if row.inserted:  # a merge into an already-open event does not raise a second alert
                _alert(conn, row.id, op["severity"], op["title"])
        elif kind == "hit":
            row2 = conn.execute(
                _EV_HIT,
                {
                    "hits": op["hits"],
                    "last_seen": op["last_seen"],
                    "evidence": json.dumps(op["evidence"]),
                    "severity": op["severity"],
                    "dedup_key": op["dedup_key"],
                },
            ).first()
            if row2 is not None and op["escalate"]:
                _alert(conn, row2.id, op["severity"], f"{op['title']} (escalated)")
        elif kind == "close":
            conn.execute(_EV_CLOSE, {"dedup_key": op["dedup_key"]})
        else:
            raise ValueError(f"unknown event op {kind!r}")


def _apply_traffic(conn: Connection, payload: dict[str, list[list[Any]]]) -> None:
    if payload.get("traffic_1s"):
        conn.execute(
            _TRAFFIC_1S,
            [
                {"sec": r[0], "protocol": r[1], "packets": r[2], "bytes": r[3], "new": r[4]}
                for r in payload["traffic_1s"]
            ],
        )
    if payload.get("flows_1m"):
        conn.execute(
            _FLOWS_1M,
            [
                {
                    "minute": r[0],
                    "src": r[1],
                    "dst": r[2],
                    "port": r[3],
                    "transport": r[4],
                    "app": r[5],
                    "packets": r[6],
                    "bytes": r[7],
                    "syn": r[8],
                }
                for r in payload["flows_1m"]
            ],
        )


def _apply_devices(conn: Connection, updates: list[dict[str, Any]]) -> None:
    for u in updates:
        p = {
            "ip": u["ip"],
            "mac": u["mac"],
            "status": u["status"],
            "source": u["source"],
            "first": u["first_seen"],
            "last": u["last_seen"],
        }
        if u["mac"]:
            conn.execute(_ADOPT_MAC, p)  # a MAC-less row for this IP learns its hardware address
            conn.execute(_UPSERT_BY_MAC, p)
        elif conn.execute(_TOUCH_BY_IP, p).rowcount == 0:
            conn.execute(_INSERT_NO_MAC, p)


def apply_batch(conn: Connection, batch: Batch) -> bool:
    """Apply a batch exactly once. Returns False if its id is already in the ledger."""
    if conn.execute(_LEDGER, {"b": batch.batch_id}).rowcount == 0:
        return False
    if batch.kind == "traffic":
        _apply_traffic(conn, batch.payload)
    elif batch.kind == "devices":
        _apply_devices(conn, batch.payload)
    elif batch.kind == "events":
        _apply_events(conn, batch.payload)
    else:
        raise ValueError(f"unknown batch kind {batch.kind!r}")
    return True


def new_batch(kind: str, payload: Any) -> Batch:
    return Batch(str(uuid.uuid4()), kind, time.time(), payload)


@dataclass
class WriterState:
    db_ok: bool = True
    last_error: str | None = None
    written: int = 0
    spilled: int = 0
    replayed: int = 0
    spill_dropped: int = 0  # batches lost because the spill cap was reached: a data-loss signal
    last_failure_at: float = 0.0


class WriteQueue:
    """Bounded queue in front of the database. When it is full the batch goes to disk instead of
    being dropped, so a slow database cannot silently lose data."""

    def __init__(self, size: int, spill: SpillStore, state: WriterState) -> None:
        self.q: queue.Queue[Batch | None] = queue.Queue(maxsize=size)
        self._spill = spill
        self._state = state

    def submit(self, batch: Batch) -> None:
        try:
            self.q.put_nowait(batch)
        except queue.Full:
            if self._spill.write(batch):
                self._state.spilled += 1
            else:
                self._state.spill_dropped += 1
                log.error("write queue full and spill cap reached: batch %s lost", batch.batch_id)

    def close(self) -> None:
        self.q.put(None)  # sentinel: the writer stops after everything queued before it

    @property
    def depth(self) -> int:
        return self.q.qsize()


class BatchWriter:
    """Owns a writer thread (composition, not a Thread subclass: a subclass can collide with
    private names that newer Python versions add, e.g. Thread._handle in 3.13)."""

    def __init__(
        self,
        engine: Engine,
        wq: WriteQueue,
        spill: SpillStore,
        state: WriterState,
        *,
        retries: int = 3,
        backoff: float = 0.5,
        replay_per_loop: int = 20,
    ) -> None:
        self._thread = threading.Thread(target=self._run, name="writer", daemon=True)
        self._engine = engine
        self._wq = wq
        self._spill = spill
        self._state = state
        self._retries = retries
        self._backoff = backoff
        self._replay_per_loop = replay_per_loop

    def _write(self, batch: Batch) -> bool:
        with self._engine.begin() as conn:
            return apply_batch(conn, batch)

    def process(self, batch: Batch) -> None:
        attempts = self._retries if self._state.db_ok else 1  # fail fast while the DB is known down
        for attempt in range(attempts):
            try:
                self._write(batch)
            except SQLAlchemyError as exc:
                self._fail(exc)
                if attempt + 1 < attempts:
                    time.sleep(self._backoff * 2**attempt)
            else:
                self._state.db_ok, self._state.last_error = True, None
                self._state.written += 1
                return
        if self._spill.write(batch):
            self._state.spilled += 1
        else:
            self._state.spill_dropped += 1
            log.error("database unavailable and spill cap reached: batch %s lost", batch.batch_id)

    def _fail(self, exc: Exception) -> None:
        self._state.db_ok = False
        self._state.last_error = type(exc).__name__  # class only: driver text can echo credentials
        self._state.last_failure_at = time.time()
        log.warning("database write failed: %s", type(exc).__name__)

    def _replay(self) -> None:
        for path in self._spill.pending()[: self._replay_per_loop]:
            batch = self._spill.read(path)
            if batch is None:
                continue
            try:
                self._write(batch)  # False means "already applied": still safe to delete the file
            except SQLAlchemyError as exc:
                self._fail(exc)
                return
            self._spill.delete(path)
            self._state.db_ok, self._state.last_error = True, None
            self._state.replayed += 1

    def _replay_when_idle(self) -> None:
        if self._wq.q.empty():  # live data first; the backlog drains when there is nothing newer
            self._replay()

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        self._replay()  # a backlog left by a previous run is retried immediately, not after a delay
        while True:
            try:
                item = self._wq.q.get(timeout=1.0)
            except queue.Empty:
                self._replay_when_idle()
                continue
            if item is None:  # sentinel from WriteQueue.close(): everything before it is done
                return
            self.process(item)
            self._replay_when_idle()
