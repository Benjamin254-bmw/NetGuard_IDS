from ipaddress import IPv4Network

from netguard_common.enums import DiscoverySource, Protocol, Transport
from netguard_monitor.analysis.aggregator import Aggregator
from netguard_monitor.capture.parser import ArpObservation, Packet, Scope
from netguard_monitor.discovery.tracker import DeviceTracker

SCOPE = Scope.from_network(IPv4Network("10.10.10.0/24"))
T = 1_700_000_040.0  # a minute boundary: 1_700_000_040 % 60 == 0


def pkt(
    ts: float = T,
    src: str = "10.10.10.30",
    dst: str = "10.10.10.10",
    dport: int = 80,
    transport: Transport = Transport.TCP,
    proto: Protocol = Protocol.HTTP,
    size: int = 100,
    flags: int = 0x02,
) -> Packet:
    return Packet(0.0, ts, src, dst, 40000, dport, transport, proto, size, flags, "internal", None)


def test_counts_bytes_and_syn_are_summed_per_second_and_per_flow() -> None:
    a = Aggregator()
    for _ in range(3):
        a.add(pkt(flags=0x02))  # SYN
    a.add(pkt(flags=0x12))  # SYN+ACK: not a new connection
    a.add(pkt(ts=T + 1, size=60, flags=0x10))
    out = a.drain()
    assert out is not None
    by_sec = {(r[0], r[1]): r[2:] for r in out["traffic_1s"]}
    assert by_sec[(int(T), "http")] == [4, 400, 3]
    assert by_sec[(int(T) + 1, "http")] == [1, 60, 0]
    (flow,) = out["flows_1m"]
    assert flow == [int(T), "10.10.10.30", "10.10.10.10", 80, "tcp", "http", 5, 460, 3]


def test_drain_clears_and_is_none_when_idle() -> None:
    a = Aggregator()
    assert a.drain() is None
    a.add(pkt())
    assert a.drain() is not None and a.drain() is None


def test_total_of_all_drains_equals_total_added() -> None:
    a = Aggregator()
    total = 0
    for i in range(1000):
        a.add(pkt(ts=T + i % 5, dport=1000 + i % 7))
        if i % 97 == 0:
            out = a.drain()
            total += sum(r[2] for r in out["traffic_1s"]) if out else 0
    out = a.drain()
    total += sum(r[2] for r in out["traffic_1s"]) if out else 0
    assert total == 1000 == a.packets_seen


def test_udp_flow_has_no_app_protocol_and_dns_keeps_it() -> None:
    a = Aggregator()
    a.add(pkt(transport=Transport.UDP, proto=Protocol.UDP, dport=9999, flags=0))
    a.add(pkt(transport=Transport.UDP, proto=Protocol.DNS, dport=53, flags=0))
    out = a.drain()
    assert out is not None
    apps = {r[3]: r[5] for r in out["flows_1m"]}
    assert apps == {9999: None, 53: "dns"}


def test_flow_key_cap_bounds_memory_during_a_scan_and_is_visible() -> None:
    a = Aggregator(flow_cap_per_minute=100)
    for port in range(1, 1001):  # a scan touching 1000 distinct ports in one minute
        a.add(pkt(dport=port))
    out = a.drain()
    assert out is not None
    assert len(out["flows_1m"]) == 100  # bounded
    assert a.capped_keys == 900 and a.capped_packets == 900
    assert sum(r[2] for r in out["traffic_1s"]) == 1000  # global per-second totals are still exact
    a.add(pkt(dport=5))  # an already-known key keeps counting after the cap
    assert a.capped_keys == 900


def test_cap_is_per_minute_not_global() -> None:
    a = Aggregator(flow_cap_per_minute=10)
    for port in range(20):
        a.add(pkt(ts=T, dport=port))
    for port in range(20):
        a.add(pkt(ts=T + 60, dport=port))
    out = a.drain()
    assert out is not None and len(out["flows_1m"]) == 20


def arp(ip: str, mac: str, ts: float) -> ArpObservation:
    return ArpObservation(ts, ip, mac, "10.10.10.1", 2)


def test_new_device_from_traffic_then_mac_adopted_from_arp() -> None:
    d = DeviceTracker(SCOPE)
    d.observe_ip("10.10.10.30", 100.0)
    (u,) = d.drain_updates(100.0)
    assert (u["ip"], u["mac"], u["source"]) == ("10.10.10.30", None, "traffic")
    d.observe_arp(arp("10.10.10.30", "aa:bb:cc:00:00:30", 110.0))
    (u,) = d.drain_updates(110.0)
    assert u["mac"] == "aa:bb:cc:00:00:30" and u["first_seen"] == 100.0 and u["last_seen"] == 110.0


def test_destinations_are_never_evidence_and_invalid_hosts_are_rejected() -> None:
    d = DeviceTracker(SCOPE)
    for ip in (
        "10.10.10.0",
        "10.10.10.255",
        "224.0.0.251",
        "255.255.255.255",
        "0.0.0.0",
        "192.168.1.5",
    ):
        d.observe_ip(ip, 1.0)
    assert d.drain_updates(1.0) == []  # network/broadcast/multicast/unspecified/out-of-scope


def test_inactive_after_timeout_and_reactivated_on_traffic() -> None:
    d = DeviceTracker(SCOPE, inactive_after=300)
    d.observe_ip("10.10.10.20", 0.0)
    d.drain_updates(0.0)
    d.sweep(299.0)
    assert d.drain_updates(299.0) == []
    d.sweep(301.0)
    (u,) = d.drain_updates(301.0)
    assert u["status"] == "inactive"
    d.observe_ip("10.10.10.20", 400.0)
    (u,) = d.drain_updates(400.0)
    assert u["status"] == "active" and d.active_count == 1


def test_ip_reassigned_to_new_hardware_retires_the_old_record() -> None:
    d = DeviceTracker(SCOPE)
    d.observe_arp(arp("10.10.10.50", "aa:aa:aa:aa:aa:01", 1.0))
    d.drain_updates(1.0)
    d.observe_arp(arp("10.10.10.50", "bb:bb:bb:bb:bb:02", 50.0))
    ups = {(u["mac"], u["status"]) for u in d.drain_updates(50.0)}
    assert ups == {("aa:aa:aa:aa:aa:01", "inactive"), ("bb:bb:bb:bb:bb:02", "active")}


def test_last_seen_refresh_is_throttled_to_the_persist_interval() -> None:
    d = DeviceTracker(SCOPE, persist_interval=30)
    d.observe_ip("10.10.10.20", 0.0)
    d.drain_updates(0.0)
    for t in range(1, 29):
        d.observe_ip("10.10.10.20", float(t))
        assert d.drain_updates(float(t)) == []  # no database write for every packet
    d.observe_ip("10.10.10.20", 31.0)
    assert len(d.drain_updates(31.0)) == 1


def test_device_table_is_bounded() -> None:
    d = DeviceTracker(SCOPE, max_devices=5)
    for i in range(1, 50):
        d.observe_ip(f"10.10.10.{i}", 1.0, DiscoverySource.TRAFFIC)
    assert len(d.drain_updates(1.0)) == 5 and d.capped == 44
