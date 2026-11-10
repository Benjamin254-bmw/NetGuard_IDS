"""Measure frame-parsing throughput: netguard parser vs Scapy dissection, same frames.
Usage: .venv/bin/python lab/bench_parser.py   (results depend on the machine; re-run on yours)"""

from __future__ import annotations

import platform
import time
from ipaddress import IPv4Network

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

from netguard_monitor.capture.parser import Scope, parse_frame

SCOPE = Scope.from_network(IPv4Network("10.10.10.0/24"))
E = Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
FRAMES = [
    bytes(E / IP(src="10.10.10.30", dst="10.10.10.10") / TCP(sport=40000, dport=80, flags="S")),
    bytes(
        E / IP(src="10.10.10.30", dst="10.10.10.10") / UDP(sport=5000, dport=9999) / Raw(b"x" * 200)
    ),
    bytes(
        E
        / IP(src="10.10.10.20", dst="10.10.10.10")
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.example.com"))
    ),
    bytes(E / IP(src="10.10.10.30", dst="10.10.10.10") / ICMP()),
]
N = 20_000


def rate(fn) -> float:  # type: ignore[no-untyped-def]
    t = time.perf_counter()
    for i in range(N):
        fn(FRAMES[i % len(FRAMES)])
    return N / (time.perf_counter() - t)


ours = rate(lambda b: parse_frame(b, len(b), 0.0, 0.0, SCOPE))
scapy_dissect = rate(lambda b: Ether(b)[IP].src)  # minimal field access forces IP dissection
scapy_full = rate(
    lambda b: (
        lambda p: (p[IP].src, p[IP].dst, p.sport if p.haslayer(TCP) or p.haslayer(UDP) else 0)
    )(Ether(b))
)
print(f"python {platform.python_version()} on {platform.machine()}, {N} frames per measurement")
print(f"netguard parser          : {ours:>10,.0f} frames/s")
print(
    f"scapy Ether(b)[IP].src   : {scapy_dissect:>10,.0f} frames/s  ({ours / scapy_dissect:.0f}x slower than ours)"
)
print(
    f"scapy src/dst/port       : {scapy_full:>10,.0f} frames/s  ({ours / scapy_full:.0f}x slower than ours)"
)
