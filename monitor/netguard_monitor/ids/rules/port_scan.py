"""R1 port scan: one source probes many distinct TCP ports on one target within a window.

Counts SYN-without-ACK packets (connection attempts) per (source, target) and the number of
*distinct* destination ports in the sliding window. Repeated attempts on one port count once,
so a busy client hammering a single service is not a scan.
"""

from __future__ import annotations

from collections import deque

from netguard_common.enums import DetectionCategory, Protocol, Severity, Transport
from netguard_monitor.capture.parser import TCP_ACK, TCP_SYN, Packet
from netguard_monitor.ids.base import MAX_STATE_KEYS, Detection, Rule, RuleDefaults, bump

MAX_PORTS_PER_TARGET = 4096
ESCALATE_FACTOR = 10


class _Win:
    __slots__ = ("counts", "crossed_at", "q")

    def __init__(self) -> None:
        self.q: deque[tuple[float, int]] = deque()
        self.counts: dict[int, int] = {}
        self.crossed_at: float | None = None

    def drop_oldest(self) -> None:
        _, port = self.q.popleft()
        n = self.counts[port] - 1
        if n:
            self.counts[port] = n
        else:
            del self.counts[port]


class PortScan(Rule):
    key = "port_scan"
    name = "Port scan"
    category = DetectionCategory.PORT_SCAN
    description = (
        "A single source attempted TCP connections to many distinct ports on one host "
        "within the window (SYN without ACK)."
    )
    defaults = RuleDefaults(Severity.HIGH, 15, 10, 60)

    def __init__(self, cfg):  # type: ignore[no-untyped-def]
        super().__init__(cfg)
        self._w: dict[tuple[str, str], _Win] = {}

    def on_packet(self, p: Packet) -> list[Detection]:
        if p.transport is not Transport.TCP or not (p.tcp_flags & TCP_SYN) or p.tcp_flags & TCP_ACK:
            return []
        c = self.cfg
        key = (p.src_ip, p.dst_ip)
        w = self._w.get(key)
        if w is None:
            if len(self._w) >= MAX_STATE_KEYS:
                self.capped += 1
                return []
            w = self._w[key] = _Win()
        ts = p.ts_utc
        cutoff = ts - c.window_seconds
        while w.q and w.q[0][0] < cutoff:
            w.drop_oldest()
        w.q.append((ts, p.dst_port))
        w.counts[p.dst_port] = w.counts.get(p.dst_port, 0) + 1
        while len(w.q) > MAX_PORTS_PER_TARGET:
            w.drop_oldest()
        distinct = len(w.counts)
        if distinct < c.threshold:
            w.crossed_at = None
            return []
        if w.crossed_at is None:
            w.crossed_at = ts
        sev = bump(c.severity) if distinct >= ESCALATE_FACTOR * c.threshold else c.severity
        evidence: dict[str, object] = {
            "distinct_ports": distinct,
            "window_seconds": c.window_seconds,
            "threshold": c.threshold,
            "crossed_at": w.crossed_at,
        }
        if distinct == c.threshold:
            evidence["sample_ports"] = sorted(w.counts)[:20]
        return [
            Detection(
                self.key,
                ts,
                p.src_ip,
                p.dst_ip,
                None,
                Protocol.TCP,
                sev,
                f"Port scan from {p.src_ip} against {p.dst_ip}",
                f"{p.src_ip} attempted connections to {distinct} distinct TCP ports on "
                f"{p.dst_ip} within {c.window_seconds}s.",
                evidence,
                f"{self.key}|{p.src_ip}|{p.dst_ip}",
            )
        ]

    def evaluate(self, now: float) -> list[Detection]:
        if self.sweep_due(now):
            cutoff = now - self.cfg.window_seconds
            for key in [k for k, w in self._w.items() if not w.q or w.q[-1][0] < cutoff]:
                del self._w[key]
        return []
