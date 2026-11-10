"""The monitoring service: capture -> parse/aggregate -> batched, exactly-once persistence.

Threads and bounded queues (nothing blocks capture, nothing grows without limit):

  capture --(cq, bounded)--> analyzer --(WriteQueue, bounded, spills to disk)--> writer
  housekeeping: heartbeat, retention, kernel drop accounting; discovery: optional ARP sweep
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError

from netguard_common import __version__
from netguard_common.config import Settings
from netguard_common.db import check_connection, make_engine
from netguard_common.enums import DiscoverySource
from netguard_monitor.analysis.aggregator import Aggregator
from netguard_monitor.capture.interfaces import capture_problems, get_interface
from netguard_monitor.capture.parser import ArpObservation, Packet, ParseStats, Scope, parse_frame
from netguard_monitor.capture.socket_capture import CaptureSocket
from netguard_monitor.discovery.arp import arp_sweep, sweep_target
from netguard_monitor.discovery.tracker import DeviceTracker
from netguard_monitor.ids.base import AuthFailure, RuleConfig
from netguard_monitor.ids.engine import IdsEngine
from netguard_monitor.ids.logsource import LogTailer
from netguard_monitor.ids.registry import build_engine, load_configs, sync_rules
from netguard_monitor.persistence.retention import prune
from netguard_monitor.persistence.spill import SpillStore
from netguard_monitor.persistence.status import StatusSnapshot, write_status
from netguard_monitor.persistence.writer import (
    BatchWriter,
    WriteQueue,
    WriterState,
    new_batch,
)
from netguard_monitor.privileges import current_privileges

log = logging.getLogger(__name__)

FLUSH_INTERVAL = 2.0
HEARTBEAT_INTERVAL = 5.0
RETENTION_INTERVAL = 600.0
DRAIN_TIMEOUT = 2.0  # on stop, keep reading the kernel buffer this long at most
IDS_TICK = 0.5  # how often the engine evaluates time-driven rules and emits event ops
LOGTAIL_POLL = 0.5
RECENT = 60.0  # a drop within this many seconds keeps the monitor flagged as degraded


class PreflightError(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


class MonitorService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.scope = (
            Scope.from_network(settings.authorized_subnet) if settings.authorized_subnet else None
        )
        self.stop_event = threading.Event()
        self._stop_capture = threading.Event()
        self._stop_analyzer = threading.Event()
        self._stop_housekeeping = threading.Event()
        self.started_at: float | None = None

        self.captured = 0
        self.queue_drops = 0
        self.kernel_drops = 0
        self.capture_error: str | None = None
        self._last_queue_drop_at = 0.0
        self._last_kernel_drop_at = 0.0
        self._last_cap_flow_at = 0.0
        self._pps = 0.0

        self.parse_stats = ParseStats()
        self._cq: queue.Queue[tuple[float, float, int, bytes]] = queue.Queue(
            maxsize=settings.capture_queue_size
        )
        self._discovered: queue.SimpleQueue[tuple[str, str, float]] = queue.SimpleQueue()
        self._threads: list[threading.Thread] = []
        self._cap: CaptureSocket | None = None
        self._engine: Engine | None = None
        self.writer_state = WriterState()
        self._spill: SpillStore | None = None
        self._wq: WriteQueue | None = None
        self._writer: BatchWriter | None = None
        self.aggregator = Aggregator(settings.flow_cap_per_minute)
        self.tracker: DeviceTracker | None = None
        self.ids: IdsEngine | None = None
        self.auth_log_error: str | None = None
        self._auth_q: queue.SimpleQueue[AuthFailure] = queue.SimpleQueue()
        self._cfg_q: queue.SimpleQueue[list[RuleConfig]] = queue.SimpleQueue()

    # ------------------------------------------------------------------ startup

    def preflight(self) -> list[str]:
        s = self.settings
        info = get_interface(s.monitor_interface) if s.monitor_interface else None
        problems = capture_problems(info, s.monitor_interface, s.authorized_subnet)
        if not current_privileges().net_raw:
            problems.append("no CAP_NET_RAW: run via scripts/run-with-caps.sh or a systemd unit")
        return problems

    def start(self) -> None:
        problems = self.preflight()
        if problems:
            raise PreflightError(problems)
        s = self.settings
        assert self.scope is not None and s.monitor_interface is not None  # noqa: S101 - preflight
        priv = current_privileges()
        if priv.is_root:
            log.warning(
                "running as root; prefer a non-root user holding only CAP_NET_RAW/NET_ADMIN"
            )

        self._engine = make_engine(s, "monitor", pool_size=4)
        try:
            check_connection(self._engine)
        except SQLAlchemyError as exc:
            raise PreflightError([f"database unreachable ({type(exc).__name__})"]) from exc

        info = get_interface(s.monitor_interface)
        self._cap = CaptureSocket(
            s.monitor_interface,
            is_loopback=bool(info and info.is_loopback),
            promiscuous=s.promiscuous,
        )
        self._cap.open()
        log.info(
            "capturing on %s (authorised %s, rcvbuf %d bytes, promiscuous=%s)",
            s.monitor_interface,
            s.authorized_subnet,
            self._cap.effective_rcvbuf,
            s.promiscuous,
        )

        self._spill = SpillStore(Path(s.spill_dir), s.spill_max_mb * 1024 * 1024)
        self._wq = WriteQueue(s.write_queue_size, self._spill, self.writer_state)
        self._writer = BatchWriter(self._engine, self._wq, self._spill, self.writer_state)
        self.tracker = DeviceTracker(self.scope, inactive_after=float(s.inactive_after_seconds))
        try:
            sync_rules(self._engine)
            self.ids = build_engine(self._engine)
        except SQLAlchemyError as exc:
            raise PreflightError([f"cannot load detection rules ({type(exc).__name__})"]) from exc
        log.info(
            "detection rules loaded: %s",
            {k: ("on" if r.cfg.enabled else "off") for k, r in self.ids.rules.items()},
        )

        self.started_at = time.time()
        self._publish("starting")
        self._writer.start()
        self._spawn("analyzer", self._analyze_loop)
        self._spawn("capture", self._capture_loop)
        self._spawn("housekeeping", self._housekeeping_loop)
        if s.active_discovery:
            self._spawn("discovery", self._discovery_loop)
        if s.auth_log_path is not None:
            self._spawn("logtail", self._logtail_loop)
        self._publish("running")

    def _spawn(self, name: str, target: object) -> None:
        t = threading.Thread(target=target, name=name, daemon=True)  # type: ignore[arg-type]
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------------ threads

    def _capture_loop(self) -> None:
        assert self._cap is not None  # noqa: S101
        cap = self._cap
        drain_until: float | None = None
        while True:
            if self._stop_capture.is_set() and drain_until is None:
                drain_until = time.monotonic() + DRAIN_TIMEOUT  # bound: a flood must not block exit
            if drain_until is not None and time.monotonic() > drain_until:
                break
            try:
                item = cap.recv()
            except OSError as exc:  # interface vanished or went down: keep trying, loudly
                self.capture_error = type(exc).__name__
                log.error("capture error: %s; retrying", self.capture_error)
                cap.close()
                if self._stop_capture.wait(2.0):
                    break
                try:
                    cap.open()
                    self.capture_error = None
                except OSError:
                    continue
                continue
            if item is None:
                if drain_until is not None:
                    break  # stop requested and the socket is idle: everything has been read
                continue
            real_len, data = item
            self.captured += 1
            try:
                self._cq.put_nowait((time.monotonic(), time.time(), real_len, data))
            except queue.Full:
                self.queue_drops += 1
                self._last_queue_drop_at = time.monotonic()

    def _analyze_loop(self) -> None:
        assert self.scope is not None and self.tracker is not None  # noqa: S101
        assert self.ids is not None  # noqa: S101
        scope, tracker, ids = self.scope, self.tracker, self.ids
        last_flush = last_tick = time.monotonic()
        while True:
            try:
                ts_mono, ts_utc, real_len, data = self._cq.get(timeout=0.2)
            except queue.Empty:
                if self._stop_analyzer.is_set():
                    break
            else:
                parsed = parse_frame(data, real_len, ts_mono, ts_utc, scope, self.parse_stats)
                if isinstance(parsed, Packet):
                    self.aggregator.add(parsed)
                    ids.on_packet(parsed)
                    if parsed.direction != "inbound":  # source is inside the authorised subnet
                        tracker.observe_ip(parsed.src_ip, parsed.ts_utc)
                elif isinstance(parsed, ArpObservation):
                    tracker.observe_arp(parsed)
            while True:
                try:
                    ip, mac, ts = self._discovered.get_nowait()
                except queue.Empty:
                    break
                tracker.observe_mac(ip, mac, ts, DiscoverySource.ACTIVE_ARP)
            self._drain_side_queues(ids)
            if time.monotonic() - last_tick >= IDS_TICK:
                self._ids_tick(ids, final=False)
                last_tick = time.monotonic()
            if time.monotonic() - last_flush >= FLUSH_INTERVAL:
                self._flush()
                last_flush = time.monotonic()
        self._drain_side_queues(ids)
        self._ids_tick(ids, final=True)
        self._flush()

    def _drain_side_queues(self, ids: IdsEngine) -> None:
        while True:
            try:
                ids.on_auth_failure(self._auth_q.get_nowait())
            except queue.Empty:
                break
        while True:
            try:
                ids.reconfigure(self._cfg_q.get_nowait())
            except queue.Empty:
                break

    def _ids_tick(self, ids: IdsEngine, *, final: bool) -> None:
        assert self._wq is not None  # noqa: S101
        ids.tick(time.time())
        if final:
            ids.flush()  # pending hits are written; open events resume after a restart
        ops = ids.drain_ops()
        if ops:
            self._wq.submit(new_batch("events", ops))

    def _logtail_loop(self) -> None:
        assert self.settings.auth_log_path is not None  # noqa: S101
        tailer = LogTailer(self.settings.auth_log_path)
        try:
            while not self._stop_housekeeping.is_set():
                for failure in tailer.poll():
                    self._auth_q.put(failure)
                self.auth_log_error = tailer.error
                if self._stop_housekeeping.wait(LOGTAIL_POLL):
                    break
        finally:
            tailer.close()

    def _flush(self) -> None:
        assert self._wq is not None and self.tracker is not None  # noqa: S101
        before = self.aggregator.capped_keys
        payload = self.aggregator.drain()
        if self.aggregator.capped_keys > before:
            self._last_cap_flow_at = time.monotonic()
        if payload:
            self._wq.submit(new_batch("traffic", payload))
        now = time.time()
        self.tracker.sweep(now)
        updates = self.tracker.drain_updates(now)
        if updates:
            self._wq.submit(new_batch("devices", list(updates)))

    def _discovery_loop(self) -> None:
        s = self.settings
        info = get_interface(s.monitor_interface or "")
        assert info is not None and s.authorized_subnet is not None  # noqa: S101
        target = sweep_target(s.authorized_subnet, [a.network for a in info.ipv4])
        if target is None:
            log.warning("active discovery enabled but no safe sweep target; staying passive")
            return
        while not self.stop_event.wait(0):
            try:
                found = arp_sweep(info.name, target, s.authorized_subnet)
            except (OSError, ValueError) as exc:
                log.warning("ARP sweep failed: %s", type(exc).__name__)
                found = []
            now = time.time()
            for ip, mac in found:
                self._discovered.put((ip, mac, now))
            if self._stop_housekeeping.wait(float(s.active_discovery_interval_seconds)):
                return

    def _housekeeping_loop(self) -> None:
        assert self._cap is not None and self._engine is not None  # noqa: S101
        last_hb = last_ret = last_rules = time.monotonic()
        last_count, last_t = 0, time.monotonic()
        while not self._stop_housekeeping.wait(1.0):
            now = time.monotonic()
            try:
                drops = self._cap.kernel_drops()
            except (OSError, RuntimeError):
                drops = 0
            if drops:
                self.kernel_drops += drops
                self._last_kernel_drop_at = now
            self._pps = (self.captured - last_count) / max(now - last_t, 1e-6)
            last_count, last_t = self.captured, now
            if now - last_hb >= HEARTBEAT_INTERVAL:
                self._publish("degraded" if self.degraded_reasons() else "running")
                last_hb = now
            if now - last_rules >= self.settings.rules_reload_seconds:
                last_rules = now
                try:
                    self._cfg_q.put(load_configs(self._engine))
                except SQLAlchemyError as exc:
                    log.warning("rule reload failed: %s", type(exc).__name__)
            if now - last_ret >= RETENTION_INTERVAL:
                last_ret = now
                try:
                    s = self.settings
                    deleted = prune(
                        self._engine, time.time(), s.retention_1s_hours, s.retention_1m_days
                    )
                    if any(deleted.values()):
                        log.info("retention pruned %s", deleted)
                except SQLAlchemyError as exc:
                    log.warning("retention failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------ status

    def degraded_reasons(self) -> list[str]:
        now = time.monotonic()
        reasons: list[str] = []
        if self.capture_error:
            reasons.append("capture_error")
        if self._last_kernel_drop_at and now - self._last_kernel_drop_at < RECENT:
            reasons.append("kernel_drops")
        if self._last_queue_drop_at and now - self._last_queue_drop_at < RECENT:
            reasons.append("capture_queue_drops")
        if self._cq.qsize() > 0.8 * self.settings.capture_queue_size:
            reasons.append("capture_queue_saturated")
        if self._last_cap_flow_at and now - self._last_cap_flow_at < RECENT:
            reasons.append("flow_cap_reached")
        if not self.writer_state.db_ok:
            reasons.append("database_unavailable")
        if self._spill is not None and self._spill.backlog > 0:
            reasons.append("spill_backlog")
        if self.settings.auth_log_path is not None and self.auth_log_error:
            reasons.append("auth_log_unavailable")
        if self.writer_state.spill_dropped > 0:
            reasons.append("data_loss_spill_full")
        if not self.stop_event.is_set():
            for name, thread in (("analyzer", None), ("writer", self._writer)):
                if thread is not None and not thread.is_alive():
                    reasons.append(f"{name}_stopped")
        return reasons

    def snapshot(self, state: str) -> StatusSnapshot:
        return StatusSnapshot(
            state=state,
            interface=self.settings.monitor_interface,
            started_at=self.started_at,
            packets_captured=self.captured,
            packets_dropped=self.kernel_drops + self.queue_drops,
            packets_per_second=round(self._pps, 2),
            capture_queue_depth=self._cq.qsize(),
            write_queue_depth=self._wq.depth if self._wq else 0,
            spill_backlog=self._spill.backlog if self._spill else 0,
            degraded_reasons=self.degraded_reasons(),
            last_error=self.writer_state.last_error or self.capture_error,
            version=__version__,
        )

    def _publish(self, state: str) -> None:
        if self._engine is None:
            return
        try:
            write_status(self._engine, self.snapshot(state))
        except SQLAlchemyError as exc:
            log.warning("heartbeat failed: %s", type(exc).__name__)

    # ------------------------------------------------------------------ shutdown

    def request_stop(self) -> None:
        self.stop_event.set()

    def stop(self) -> None:
        """Orderly shutdown: stop capture, drain every stage, then record 'stopped'."""
        self.stop_event.set()
        self._stop_capture.set()
        self._join("capture")
        if self._cap is not None:
            self._cap.close()
        self._stop_analyzer.set()
        self._join("analyzer")
        if self._wq is not None:
            self._wq.close()
        if self._writer is not None:
            self._writer.join(timeout=30)
        self._stop_housekeeping.set()
        self._join("housekeeping")
        self._join("discovery")
        self._join("logtail")
        self._publish("stopped")
        log.info(
            "stopped: captured=%d kernel_drops=%d queue_drops=%d written=%d spilled=%d parse=%s",
            self.captured,
            self.kernel_drops,
            self.queue_drops,
            self.writer_state.written,
            self.writer_state.spilled,
            {k: getattr(self.parse_stats, k) for k in ParseStats.__slots__},
        )

    def _join(self, name: str) -> None:
        for t in self._threads:
            if t.name == name:
                t.join(timeout=30)

    def run(self, duration: float | None = None) -> None:
        self.start()
        try:
            self.stop_event.wait(duration)
        finally:
            self.stop()
