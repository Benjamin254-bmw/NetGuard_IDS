"""Service-level tests: end-to-end exactness on loopback, queue accounting, degradation, recovery."""

import queue
import socket
import threading
import time
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from sqlalchemy import Engine

from dbhelpers import needs_db, run
from netguard_common.config import Settings
from netguard_monitor.privileges import current_privileges
from netguard_monitor.service import MonitorService, PreflightError

needs_caps = pytest.mark.skipif(not current_privileges().net_raw, reason="needs CAP_NET_RAW")
PAYLOAD, N = 100, 500


def settings_for(base: Settings, tmp: Path, **over: object) -> Settings:
    return base.model_copy(
        update={
            "monitor_interface": "lo",
            "authorized_subnet": IPv4Network("127.0.0.0/8"),
            "spill_dir": tmp / "spill",
            **over,
        }
    )


def send(n: int, port: int = 9999) -> None:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(n):
        u.sendto(b"x" * PAYLOAD, ("127.0.0.1", port))
    u.close()


@needs_db
@needs_caps
def test_end_to_end_counts_match_what_was_sent_exactly(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    svc = MonitorService(settings_for(test_settings, tmp_path))
    svc.start()
    time.sleep(0.5)
    send(N)
    time.sleep(3.0)  # let at least one flush happen
    svc.stop()

    udp = run(
        db["migrator"],
        """
        SELECT packets, bytes, app_protocol FROM connection_aggregates_1m
        WHERE host(src_ip)='127.0.0.1' AND host(dst_ip)='127.0.0.1' AND dst_port=9999 AND transport='udp'""",
    )
    assert [(sum(r[0] for r in udp), sum(r[1] for r in udp))] == [(N, N * (14 + 20 + 8 + PAYLOAD))]
    icmp = run(
        db["migrator"], "SELECT sum(packets) FROM connection_aggregates_1m WHERE transport='icmp'"
    )
    assert icmp[0][0] == N  # the port-unreachable replies, each counted once
    per_second = run(
        db["migrator"],
        "SELECT protocol, sum(packets) FROM traffic_stats_1s "
        "WHERE protocol IN ('udp', 'icmp') GROUP BY protocol",
    )
    assert {r[0]: int(r[1]) for r in per_second} == {"udp": N, "icmp": N}
    # Loopback also carries the monitor's own PostgreSQL connection (tcp), which is why `lo` is
    # for tests only: on a real interface the database traffic is not part of the capture.

    assert (
        run(db["migrator"], "SELECT count(*) FROM devices WHERE host(ip) = '127.0.0.1'")[0][0] == 1
    )
    hb = run(
        db["migrator"],
        "SELECT state, packets_captured, packets_dropped, interface FROM monitor_status",
    )[0]
    assert hb[0] == "stopped" and hb[1] >= 2 * N and hb[2] == 0 and hb[3] == "lo"
    assert svc.writer_state.spill_dropped == 0 and svc.queue_drops == 0


@needs_db
@needs_caps
def test_service_stops_cleanly_and_leaves_no_threads(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    before = {t.name for t in threading.enumerate()}
    svc = MonitorService(settings_for(test_settings, tmp_path))
    svc.run(duration=1.0)
    time.sleep(0.2)
    assert {t.name for t in threading.enumerate()} - before == set()


def test_start_refused_without_explicit_configuration(
    test_settings: Settings, tmp_path: Path
) -> None:
    unconfigured = test_settings.model_copy(
        update={"monitor_interface": None, "authorized_subnet": None, "spill_dir": tmp_path}
    )
    with pytest.raises(PreflightError) as ei:
        MonitorService(unconfigured).start()
    assert len(ei.value.problems) >= 2


def test_start_refused_on_an_interface_outside_the_authorised_network(
    test_settings: Settings, tmp_path: Path
) -> None:
    wrong = settings_for(test_settings, tmp_path, authorized_subnet=IPv4Network("10.10.10.0/24"))
    with pytest.raises(PreflightError, match="does not overlap"):
        MonitorService(wrong).start()


class FakeCap:
    def __init__(self, frames: list[tuple[int, bytes]], fail_first: bool = False) -> None:
        self.frames, self.fail_first, self.opens, self.closed = list(frames), fail_first, 0, 0

    def recv(self) -> tuple[int, bytes] | None:
        if self.fail_first:
            self.fail_first = False
            raise OSError("interface went down")
        return self.frames.pop(0) if self.frames else None

    def open(self) -> None:
        self.opens += 1

    def close(self) -> None:
        self.closed += 1


def capture_only(svc: MonitorService, cap: FakeCap, until: float = 1.0) -> None:
    svc._cap = cap  # type: ignore[assignment]  # noqa: SLF001
    t = threading.Thread(target=svc._capture_loop)  # noqa: SLF001
    t.start()
    time.sleep(until)
    svc._stop_capture.set()  # noqa: SLF001
    t.join(timeout=5)
    assert not t.is_alive()


def test_full_capture_queue_counts_every_dropped_packet(
    test_settings: Settings, tmp_path: Path
) -> None:
    svc = MonitorService(settings_for(test_settings, tmp_path, capture_queue_size=1000))
    capture_only(svc, FakeCap([(60, b"x" * 60)] * 1500))  # no analyzer running: the queue must fill
    assert svc.captured == 1500
    assert svc._cq.qsize() == 1000 and svc.queue_drops == 500  # noqa: SLF001
    assert "capture_queue_drops" in svc.degraded_reasons()
    assert "capture_queue_saturated" in svc.degraded_reasons()


def test_capture_survives_an_interface_error_and_reports_it(
    test_settings: Settings, tmp_path: Path
) -> None:
    svc = MonitorService(settings_for(test_settings, tmp_path))
    cap = FakeCap([(60, b"y" * 60)] * 3, fail_first=True)
    capture_only(svc, cap, until=3.0)
    assert (
        cap.closed >= 1 and cap.opens == 1 and svc.capture_error is None
    )  # reopened, error cleared
    assert svc.captured == 3  # traffic resumed


def test_degradation_reasons_reflect_each_failure_mode(
    test_settings: Settings, tmp_path: Path
) -> None:
    svc = MonitorService(settings_for(test_settings, tmp_path))
    assert svc.degraded_reasons() == []
    svc.writer_state.db_ok = False
    svc.writer_state.spill_dropped = 2
    svc.capture_error = "OSError"
    now = time.monotonic()
    svc._last_kernel_drop_at = now  # noqa: SLF001
    svc._last_cap_flow_at = now  # noqa: SLF001
    assert set(svc.degraded_reasons()) == {
        "database_unavailable",
        "data_loss_spill_full",
        "capture_error",
        "kernel_drops",
        "flow_cap_reached",
    }
    svc._last_kernel_drop_at = now - 120  # noqa: SLF001  (old drops no longer count)
    assert "kernel_drops" not in svc.degraded_reasons()


def test_snapshot_reports_drops_and_depths(test_settings: Settings, tmp_path: Path) -> None:
    svc = MonitorService(settings_for(test_settings, tmp_path))
    svc.captured, svc.kernel_drops, svc.queue_drops = 100, 3, 4
    svc._cq.put_nowait((0.0, 0.0, 1, b"x"))  # noqa: SLF001
    snap = svc.snapshot("running")
    assert (snap.packets_captured, snap.packets_dropped, snap.capture_queue_depth) == (100, 7, 1)
    assert snap.interface == "lo" and isinstance(queue.Queue(), queue.Queue)


@needs_db
@needs_caps
def test_stopping_right_after_traffic_loses_nothing(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    """Shutdown must drain the kernel buffer and the in-memory aggregates, not abandon them."""
    svc = MonitorService(settings_for(test_settings, tmp_path))
    svc.start()
    time.sleep(0.3)
    send(N)
    svc.stop()  # immediately: well before the periodic 2 s flush
    rows = run(
        db["migrator"],
        """
        SELECT sum(packets) FROM connection_aggregates_1m
        WHERE dst_port = 9999 AND transport = 'udp'""",
    )
    assert rows[0][0] == N
