"""R2 excessive connections: many new TCP connections from one source to one service.

Counts SYN-without-ACK packets per (source, destination, port) in a sliding window. Unlike a
port scan, the port is fixed: this is a connection flood or a brute-force client.
"""

from __future__ import annotations

from collections import deque

from netguard_common.enums import DetectionCategory, Protocol, Severity, Transport
from netguard_monitor.capture.parser import TCP_ACK, TCP_SYN, Packet
from netguard_monitor.ids.base import MAX_STATE_KEYS, Detection, Rule, RuleDefaults, bump

ESCALATE_FACTOR = 10
MAX_TIMES_PER_KEY = 20_000


class ExcessiveConnections(Rule):
    key = "excessive_connections"
    name = "Excessive connection attempts"
    category = DetectionCategory.EXCESSIVE_CONNECTIONS
    description = (
        "A single source opened an unusually high number of new TCP connections to one "
        "service within the window."
    )
    defaults = RuleDefaults(Severity.MEDIUM, 100, 10, 60)

    def __init__(self, cfg):  # type: ignore[no-untyped-def]
        super().__init__(cfg)
        self._w: dict[tuple[str, str, int], deque[float]] = {}
        self._crossed: dict[tuple[str, str, int], float] = {}

    def on_packet(self, p: Packet) -> list[Detection]:
        if p.transport is not Transport.TCP or not (p.tcp_flags & TCP_SYN) or p.tcp_flags & TCP_ACK:
            return []
        c = self.cfg
        key = (p.src_ip, p.dst_ip, p.dst_port)
        q = self._w.get(key)
        if q is None:
            if len(self._w) >= MAX_STATE_KEYS:
                self.capped += 1
                return []
            q = self._w[key] = deque()
        ts = p.ts_utc
        cutoff = ts - c.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        q.append(ts)
        if len(q) > MAX_TIMES_PER_KEY:
            q.popleft()
        n = len(q)
        if n < c.threshold:
            self._crossed.pop(key, None)
            return []
        crossed = self._crossed.setdefault(key, ts)
        sev = bump(c.severity) if n >= ESCALATE_FACTOR * c.threshold else c.severity
        return [
            Detection(
                self.key,
                ts,
                p.src_ip,
                p.dst_ip,
                p.dst_port,
                Protocol.TCP,
                sev,
                f"Excessive connections from {p.src_ip} to {p.dst_ip}:{p.dst_port}",
                f"{p.src_ip} opened {n} new connections to {p.dst_ip}:{p.dst_port} "
                f"within {c.window_seconds}s.",
                {
                    "connections": n,
                    "window_seconds": c.window_seconds,
                    "threshold": c.threshold,
                    "crossed_at": crossed,
                },
                f"{self.key}|{p.src_ip}|{p.dst_ip}|{p.dst_port}",
            )
        ]

    def evaluate(self, now: float) -> list[Detection]:
        if self.sweep_due(now):
            cutoff = now - self.cfg.window_seconds
            for key in [k for k, q in self._w.items() if not q or q[-1] < cutoff]:
                del self._w[key]
                self._crossed.pop(key, None)
        return []
