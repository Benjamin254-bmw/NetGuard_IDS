"""In-memory traffic aggregation. Produces additive deltas that the writer upserts, so partial
buckets can be flushed at any time without double counting (each delta is applied once, guarded
by the batch ledger)."""

from __future__ import annotations

from typing import Any

from netguard_common.enums import Protocol, Transport
from netguard_monitor.capture.parser import TCP_ACK, TCP_SYN, Packet

APP_PROTOCOLS = {Protocol.DNS, Protocol.HTTP, Protocol.HTTPS, Protocol.SSH}
FlowKey = tuple[int, str, str, int, str]


class Aggregator:
    def __init__(self, flow_cap_per_minute: int = 5000) -> None:
        self._cap = flow_cap_per_minute
        self._sec: dict[tuple[int, str], list[int]] = {}
        self._flows: dict[FlowKey, list[Any]] = {}
        self._known: dict[int, set[FlowKey]] = {}
        self.packets_seen = 0
        self.capped_packets = 0  # packets not recorded per-flow because of the key cap
        self.capped_keys = 0

    def add(self, p: Packet) -> None:
        self.packets_seen += 1
        sec = int(p.ts_utc)
        syn = (
            1
            if p.transport is Transport.TCP and p.tcp_flags & TCP_SYN and not p.tcp_flags & TCP_ACK
            else 0
        )

        row = self._sec.get((sec, p.protocol.value))
        if row is None:
            self._sec[(sec, p.protocol.value)] = [1, p.size, syn]
        else:
            row[0] += 1
            row[1] += p.size
            row[2] += syn

        minute = sec - sec % 60
        key: FlowKey = (minute, p.src_ip, p.dst_ip, p.dst_port, p.transport.value)
        known = self._known.setdefault(minute, set())
        if key not in known:
            if len(known) >= self._cap:
                self.capped_keys += 1
                self.capped_packets += 1
                return
            known.add(key)
        app = p.protocol.value if p.protocol in APP_PROTOCOLS else None
        flow = self._flows.get(key)
        if flow is None:
            self._flows[key] = [1, p.size, syn, app]
        else:
            flow[0] += 1
            flow[1] += p.size
            flow[2] += syn
            if app is not None:
                flow[3] = app

    def drain(self) -> dict[str, list[list[Any]]] | None:
        """Return and clear everything accumulated since the last drain (None if nothing)."""
        if not self._sec and not self._flows:
            return None
        payload: dict[str, list[list[Any]]] = {
            "traffic_1s": [[s, proto, *v] for (s, proto), v in self._sec.items()],
            "flows_1m": [
                [m, src, dst, port, transport, v[3], v[0], v[1], v[2]]
                for (m, src, dst, port, transport), v in self._flows.items()
            ],
        }
        newest = max((m for m, *_ in self._flows), default=None)
        self._sec.clear()
        self._flows.clear()
        if newest is not None:  # forget key sets for minutes that can no longer receive packets
            for minute in [m for m in self._known if m < newest - 180]:
                del self._known[minute]
        return payload
