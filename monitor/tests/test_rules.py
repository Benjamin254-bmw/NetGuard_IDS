"""Unit tests for the five detection rules (pure logic, no I/O)."""

from __future__ import annotations

from ids_helpers import ACK, ATT, SYN, VIC, T, bulk, cfg, tcp, udp_dns

from netguard_common.enums import Transport
from netguard_monitor.capture.parser import Packet
from netguard_monitor.ids.base import MAX_STATE_KEYS, AuthFailure, bump, int_param
from netguard_monitor.ids.rules.abnormal_traffic import AbnormalTraffic
from netguard_monitor.ids.rules.auth_failures import AuthFailures
from netguard_monitor.ids.rules.excessive_connections import ExcessiveConnections
from netguard_monitor.ids.rules.port_scan import MAX_PORTS_PER_TARGET, PortScan
from netguard_monitor.ids.rules.suspicious_dns import SuspiciousDns


def feed(rule: object, packets: list[Packet]) -> list:  # type: ignore[type-arg]
    out = []
    for p in packets:
        out += rule.on_packet(p)  # type: ignore[attr-defined]
    return out


# ------------------------------------------------------------------ helpers
def test_bump_caps_at_critical_and_int_param_is_clamped() -> None:
    assert bump("low") == "medium" and bump("high") == "critical" and bump("critical") == "critical"
    assert int_param({"x": 5}, "x", 1, 2, 3) == 3
    assert int_param({"x": -5}, "x", 1, 2, 3) == 2
    assert int_param({"x": "9"}, "x", 7, 2, 10) == 7  # wrong type -> default
    assert int_param({"x": True}, "x", 7, 2, 10) == 7  # bool is not an int here
    assert int_param({}, "x", 4, 2, 10) == 4


# ------------------------------------------------------------------ R1 port scan
def scan(
    n: int, start: float = T, step: float = 0.01, src: str = ATT, dst: str = VIC
) -> list[Packet]:
    return [tcp(start + i * step, src, dst, 1000 + i) for i in range(n)]


def test_port_scan_fires_exactly_at_the_threshold() -> None:
    r = PortScan(cfg("port_scan"))  # 15 distinct ports in 10 s
    assert feed(r, scan(14)) == []
    dets = feed(r, scan(15)[14:])
    assert len(dets) == 1
    d = dets[0]
    assert (d.src_ip, d.dst_ip, d.severity) == (ATT, VIC, "high")
    assert d.evidence["distinct_ports"] == 15 and d.evidence["threshold"] == 15
    assert d.evidence["crossed_at"] == T + 14 * 0.01  # time of the 15th distinct port
    assert d.evidence["sample_ports"] == list(range(1000, 1015))
    assert d.dedup_key == f"port_scan|{ATT}|{VIC}"


def test_port_scan_repeated_attempts_on_one_port_are_not_a_scan() -> None:
    r = PortScan(cfg("port_scan"))
    assert feed(r, [tcp(T + i * 0.01, ATT, VIC, 80) for i in range(500)]) == []


def test_port_scan_only_counts_connection_attempts() -> None:
    r = PortScan(cfg("port_scan"))
    other = [tcp(T + i * 0.01, ATT, VIC, 1000 + i, flags=SYN | ACK) for i in range(50)] + [
        tcp(T + i * 0.01, ATT, VIC, 2000 + i, flags=ACK) for i in range(50)
    ]
    assert feed(r, other) == []
    udp = Packet(T, T, ATT, VIC, 1, 5, Transport.UDP, Transport.UDP, 60, SYN, "internal", None)  # type: ignore[arg-type]
    assert r.on_packet(udp) == []


def test_port_scan_window_expiry_and_separate_targets() -> None:
    r = PortScan(cfg("port_scan"))
    assert feed(r, scan(10, start=T)) == []
    assert feed(r, scan(10, start=T + 11, step=0.01)) == []  # first ten have aged out
    assert feed(r, scan(14, dst="10.10.10.20")) == []  # other target has its own window
    assert feed(r, scan(14, src="10.10.10.40")) == []  # other source too


def test_port_scan_escalates_at_ten_times_the_threshold() -> None:
    r = PortScan(cfg("port_scan"))
    dets = feed(r, scan(150))
    assert dets[0].severity == "high" and dets[-1].severity == "critical"
    first_critical = next(i for i, d in enumerate(dets) if d.severity == "critical")
    assert dets[first_critical].evidence["distinct_ports"] == 150


def test_port_scan_respects_configuration_and_bounds_memory() -> None:
    r = PortScan(cfg("port_scan", threshold=3, severity="low"))
    assert len(feed(r, scan(3))) == 1 and r.on_packet(scan(4)[3])[0].severity == "low"
    r2 = PortScan(cfg("port_scan", threshold=10**6))
    feed(r2, [tcp(T, ATT, VIC, p % 65536 or 1) for p in range(MAX_PORTS_PER_TARGET + 500)])
    assert len(r2._w[(ATT, VIC)].q) <= MAX_PORTS_PER_TARGET
    r3 = PortScan(cfg("port_scan"))
    for i in range(MAX_STATE_KEYS + 25):
        r3.on_packet(tcp(T, f"11.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}", VIC, 80))
    assert len(r3._w) == MAX_STATE_KEYS and r3.capped == 25


def test_port_scan_idle_state_is_swept() -> None:
    r = PortScan(cfg("port_scan"))
    feed(r, scan(5))
    r.evaluate(T + 100)
    assert r._w == {}


# ------------------------------------------------------------------ R2 excessive connections
def flood(n: int, start: float = T, step: float = 0.001, port: int = 9002) -> list[Packet]:
    return [tcp(start + i * step, ATT, VIC, port, sport=30000 + i) for i in range(n)]


def test_excessive_connections_threshold_and_fields() -> None:
    r = ExcessiveConnections(cfg("excessive_connections"))  # 100 in 10 s
    assert feed(r, flood(99)) == []
    d = feed(r, flood(100)[99:])[0]
    assert (d.dst_port, d.severity) == (9002, "medium")
    assert d.evidence["connections"] == 100 and d.evidence["crossed_at"] == T + 99 * 0.001
    assert d.dedup_key == f"excessive_connections|{ATT}|{VIC}|9002"


def test_excessive_connections_is_per_service_and_windowed() -> None:
    r = ExcessiveConnections(cfg("excessive_connections"))
    mixed = [tcp(T + i * 0.001, ATT, VIC, 9000 + i % 2, sport=30000 + i) for i in range(150)]
    assert feed(r, mixed) == []  # 75 per port
    r2 = ExcessiveConnections(cfg("excessive_connections"))
    slow = [tcp(T + i * 0.2, ATT, VIC, 9002, sport=30000 + i) for i in range(150)]  # 5/s
    assert feed(r2, slow) == []


def test_excessive_connections_escalates_at_ten_times() -> None:
    r = ExcessiveConnections(cfg("excessive_connections"))
    dets = feed(r, flood(1000))
    assert dets[0].severity == "medium" and dets[-1].severity == "high"


# ------------------------------------------------------------------ R3 authentication failures
def fails(n: int, start: float = T, step: float = 1.0, ip: str = ATT) -> list[AuthFailure]:
    return [AuthFailure(start + i * step, ip) for i in range(n)]


def test_auth_failures_threshold_window_and_isolation() -> None:
    r = AuthFailures(cfg("auth_failures"))  # 5 in 60 s
    out = [d for f in fails(4) for d in r.on_auth_failure(f)]
    assert out == []
    d = r.on_auth_failure(AuthFailure(T + 4, ATT))[0]
    assert d.evidence["failures"] == 5 and d.severity == "high" and d.dst_port == 22
    assert d.dedup_key == f"auth_failures|{ATT}"
    r2 = AuthFailures(cfg("auth_failures"))
    assert [x for f in fails(4, step=20) for x in r2.on_auth_failure(f)] == []  # spread out
    r3 = AuthFailures(cfg("auth_failures"))
    mixed = [AuthFailure(T + i, f"10.10.10.{30 + i % 2}") for i in range(8)]
    assert [x for f in mixed for x in r3.on_auth_failure(f)] == []  # 4 each


def test_auth_failures_spread_wider_than_the_window_never_fire() -> None:
    r = AuthFailures(cfg("auth_failures"))  # 5 in 60 s; one every 20 s never has 5 inside 60 s
    assert [d for f in fails(12, step=20) for d in r.on_auth_failure(f)] == []
    r2 = AuthFailures(cfg("auth_failures"))
    assert len([d for f in fails(12, step=10) for d in r2.on_auth_failure(f)]) > 0  # 6 per minute


def test_auth_failure_record_keeps_no_username() -> None:
    assert AuthFailure._fields == ("ts_utc", "src_ip")


# ------------------------------------------------------------------ R4 abnormal traffic
def test_abnormal_traffic_uses_the_average_over_the_window() -> None:
    r = AbnormalTraffic(cfg("abnormal_traffic", threshold=1000, window_seconds=10))
    # 10_000 bytes within the window -> exactly 1000 B/s average
    for i in range(10):
        r.on_packet(bulk(T + i, ATT, VIC, 1000))
    dets = r.evaluate(T + 9.5)
    assert len(dets) == 1 and dets[0].evidence["avg_bytes_per_second"] == 1000
    assert dets[0].dedup_key == f"abnormal_traffic|{ATT}" and dets[0].severity == "medium"


def test_abnormal_traffic_ignores_short_spikes_and_inbound_sources() -> None:
    r = AbnormalTraffic(cfg("abnormal_traffic", threshold=1000, window_seconds=10))
    r.on_packet(bulk(T, ATT, VIC, 9_000))  # 900 B/s average: below the limit
    assert r.evaluate(T + 1) == []
    r.on_packet(bulk(T + 1, "8.8.8.8", VIC, 10**9, direction="inbound"))
    assert r.evaluate(T + 2) == []


def test_abnormal_traffic_window_slides_and_escalates() -> None:
    r = AbnormalTraffic(cfg("abnormal_traffic", threshold=1000, window_seconds=10))
    r.on_packet(bulk(T, ATT, VIC, 100_000))
    assert r.evaluate(T + 1)[0].severity == "high"  # 10_000 B/s >= 4x
    assert r.evaluate(T + 11) == [] and r._b == {}  # aged out and state freed


# ------------------------------------------------------------------ R5 suspicious DNS
def queries(names: list[str], start: float = T, step: float = 0.01, src: str = ATT) -> list[Packet]:
    return [udp_dns(start + i * step, src, n) for i, n in enumerate(names)]


def indicators(dets: list) -> set[str]:  # type: ignore[type-arg]
    return {d.evidence["indicator"] for d in dets}


def test_dns_query_rate_and_distinct_names() -> None:
    r = SuspiciousDns(cfg("suspicious_dns"))  # 100 queries / 50 names in 60 s
    dets = feed(r, queries([f"h{i % 10}.example.com" for i in range(99)]))
    assert dets == []
    dets = feed(r, queries(["h1.example.com"], start=T + 1))
    assert indicators(dets) == {"query_rate"}
    r2 = SuspiciousDns(cfg("suspicious_dns"))
    dets2 = feed(r2, queries([f"n{i}.example.com" for i in range(50)]))
    assert indicators(dets2) == {"distinct_names"}


def test_dns_long_label_and_boundary() -> None:
    r = SuspiciousDns(cfg("suspicious_dns"))
    assert feed(r, queries(["a" * 52 + ".example.com"])) == []  # exactly at the limit: allowed
    d = feed(r, queries(["a" * 53 + ".example.com"]))[0]
    assert d.evidence["indicator"] == "long_label" and d.evidence["longest_label"] == 53
    assert d.dedup_key == f"suspicious_dns|{ATT}|long_label"


def test_dns_watchlist_matches_domain_and_subdomains_only() -> None:
    params = {"watchlist": ["Bad.Example"], "watchlist_severity": "high"}
    r = SuspiciousDns(cfg("suspicious_dns", params=params))
    assert indicators(feed(r, queries(["bad.example", "x.y.bad.example"]))) == {"watchlist"}
    assert feed(r, queries(["notbad.example", "bad.example.org"])) == []
    assert feed(r, queries(["bad.example"]))[0].severity == "high"


def test_dns_ignores_responses_other_protocols_and_bad_parameters() -> None:
    r = SuspiciousDns(cfg("suspicious_dns", params={"watchlist": "oops", "max_label_length": "x"}))
    assert r.on_packet(udp_dns(T, ATT, None)) == []
    assert r.on_packet(bulk(T, ATT, VIC, 100)) == []
    assert r._watch == ()
    r.reconfigure(cfg("suspicious_dns", params={"watchlist": ["a.test", 5, "  "]}))
    assert r._watch == ("a.test",)


def test_dns_state_is_bounded_per_source_and_swept() -> None:
    r = SuspiciousDns(cfg("suspicious_dns", threshold=10**6, params={"distinct_names": 100_000}))
    feed(r, queries([f"n{i}.example.com" for i in range(6000)], step=0.0001))
    assert len(r._s[ATT].q) <= 5000
    r.evaluate(T + 1000)
    assert r._s == {}
