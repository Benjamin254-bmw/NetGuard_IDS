"""End-to-end detection on loopback: real sockets -> real capture -> engine -> PostgreSQL."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import Engine
from test_service import settings_for

from dbhelpers import needs_db, run
from netguard_common.config import Settings
from netguard_monitor.ids.registry import sync_rules
from netguard_monitor.privileges import current_privileges
from netguard_monitor.service import MonitorService

pytestmark = [
    needs_db,
    pytest.mark.skipif(not current_privileges().net_raw, reason="needs CAP_NET_RAW"),
]
LOCAL = "127.0.0.1"
FAIL_LINE = "Nov  8 12:00:01 h sshd[1]: Failed password for root from 127.0.0.1 port 5 ssh2\n"


@contextmanager
def tcp_sink() -> Iterator[int]:
    srv = socket.socket()
    srv.bind((LOCAL, 0))
    srv.listen(256)
    stop = threading.Event()

    def accept() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    try:
        yield int(srv.getsockname()[1])
    finally:
        stop.set()
        t.join()
        srv.close()


def connect(port: int, n: int) -> None:
    for _ in range(n):
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((LOCAL, port))
        except OSError:
            pass
        s.close()


def benign(port: int) -> None:
    connect(port, 20)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(30):
        u.sendto(b"x" * 64, (LOCAL, 9999))
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03lab\x04test\x00\x00\x01\x00\x01"
    for _ in range(10):
        u.sendto(q, (LOCAL, 53))
    u.close()


def dns_name(name: str) -> bytes:
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


def keys(db: dict[str, Engine]) -> set[str]:
    return {r[0] for r in run(db["migrator"], "SELECT dedup_key FROM security_events")}


def wait_for(db: dict[str, Engine], want: int, limit: float = 15.0) -> None:
    end = time.time() + limit
    while time.time() < end and len(keys(db)) < want:
        time.sleep(0.25)


def test_all_five_rules_fire_once_each_on_real_traffic(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    sync_rules(db["monitor"])
    run(db["api"], "UPDATE detection_rules SET threshold = 100000 WHERE key = 'abnormal_traffic'")
    log = tmp_path / "auth.log"
    log.write_text(FAIL_LINE * 20)  # history before the monitor starts: must not count
    svc = MonitorService(settings_for(test_settings, tmp_path, auth_log_path=log))
    svc.start()
    try:
        time.sleep(0.5)
        with tcp_sink() as port:
            benign(port)
            time.sleep(1.5)
            assert keys(db) == set(), "benign traffic must not raise anything"
            connect(1, 0)  # no-op, keeps the flow explicit
            for p in range(20000, 20040):  # port scan: 40 distinct closed ports
                connect(p, 1)
            connect(port, 150)  # connection flood to one service
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(120):  # DNS burst, 120 distinct names, plus one over-long label
                u.sendto(dns_name(f"h{i}.example.com"), (LOCAL, 53))
            u.sendto(dns_name("a" * 60 + ".example.com"), (LOCAL, 53))
            for _ in range(2000):  # about 2 MB of UDP volume
                u.sendto(b"y" * 1000, (LOCAL, 9998))
            u.close()
            with open(log, "a") as f:
                f.write(FAIL_LINE * 6)
            wait_for(db, 7)
    finally:
        svc.stop()

    assert keys(db) == {
        f"port_scan|{LOCAL}|{LOCAL}",
        f"excessive_connections|{LOCAL}|{LOCAL}|{port}",
        f"abnormal_traffic|{LOCAL}",
        f"suspicious_dns|{LOCAL}|query_rate",
        f"suspicious_dns|{LOCAL}|distinct_names",
        f"suspicious_dns|{LOCAL}|long_label",
        f"auth_failures|{LOCAL}",
    }
    rows = run(db["migrator"], "SELECT count(*), count(DISTINCT dedup_key) FROM security_events")[0]
    assert rows == (7, 7)  # exactly one event per key
    assert run(db["migrator"], "SELECT count(*) FROM alerts")[0][0] >= 7
    failures = run(
        db["migrator"],
        "SELECT evidence->>'failures' FROM security_events WHERE category='auth_failures'",
    )[0][0]
    assert failures == "6"  # the 20 historical lines were not counted
    assert svc.queue_drops == 0 and svc.writer_state.spill_dropped == 0


def test_a_disabled_rule_stays_silent(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    sync_rules(db["monitor"])
    run(db["api"], "UPDATE detection_rules SET enabled = false WHERE key = 'excessive_connections'")
    svc = MonitorService(settings_for(test_settings, tmp_path))
    svc.start()
    try:
        time.sleep(0.5)
        with tcp_sink() as port:
            connect(port, 200)
            time.sleep(2.5)
    finally:
        svc.stop()
    assert keys(db) == set()


def test_rule_changes_apply_live_without_restart(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    sync_rules(db["monitor"])
    svc = MonitorService(settings_for(test_settings, tmp_path, rules_reload_seconds=2))
    svc.start()
    try:
        time.sleep(0.5)
        with tcp_sink() as port:
            connect(port, 30)  # below the default of 100
            time.sleep(1.0)
            assert keys(db) == set()
            run(
                db["api"],
                "UPDATE detection_rules SET threshold = 20 WHERE key = 'excessive_connections'",
            )
            time.sleep(3.5)  # reload interval + a margin
            connect(port, 30)
            wait_for(db, 1)
    finally:
        svc.stop()
    row = run(db["migrator"], "SELECT rule_version FROM security_events")[0]
    assert row[0] == 2  # the event records the rule version that produced it


def test_unreadable_auth_log_degrades_the_monitor_but_does_not_stop_it(
    db: dict[str, Engine], test_settings: Settings, tmp_path: Path
) -> None:
    sync_rules(db["monitor"])
    svc = MonitorService(settings_for(test_settings, tmp_path, auth_log_path=tmp_path / "nope.log"))
    svc.start()
    try:
        time.sleep(1.5)
        assert "auth_log_unavailable" in svc.degraded_reasons()
        (tmp_path / "nope.log").write_text("")
        time.sleep(1.5)
        assert "auth_log_unavailable" not in svc.degraded_reasons()
    finally:
        svc.stop()
