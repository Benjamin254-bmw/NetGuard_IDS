"""Passive device inventory. Only *sources* of traffic and ARP senders count as evidence that a
device exists; destinations never do (a scan of empty addresses must not invent devices)."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import TypedDict

from netguard_common.enums import DeviceStatus, DiscoverySource
from netguard_monitor.capture.parser import ArpObservation, Scope


class DeviceUpdate(TypedDict):
    ip: str
    mac: str | None
    first_seen: float
    last_seen: float
    status: str
    source: str


@dataclass
class _State:
    ip: str
    mac: str | None
    first_seen: float
    last_seen: float
    source: DiscoverySource
    status: DeviceStatus = DeviceStatus.ACTIVE
    dirty: bool = True
    last_persisted: float = 0.0


class DeviceTracker:
    def __init__(
        self,
        scope: Scope,
        inactive_after: float = 300.0,
        persist_interval: float = 30.0,
        max_devices: int = 4096,
    ) -> None:
        self._scope = scope
        self._inactive_after = inactive_after
        self._persist_interval = persist_interval
        self._max = max_devices
        self._by_ip: dict[str, _State] = {}
        self._retired: list[DeviceUpdate] = []
        self.capped = 0

    def _valid_host(self, ip: str) -> bool:
        a = IPv4Address(ip)
        net = self._scope.network
        return not (
            a.is_multicast
            or a.is_unspecified
            or a == IPv4Address("255.255.255.255")
            or a == net.network_address
            or a == net.broadcast_address
        ) and self._scope.contains(int(a))

    def observe_ip(
        self, ip: str, ts: float, source: DiscoverySource = DiscoverySource.TRAFFIC
    ) -> None:
        st = self._by_ip.get(ip)
        if st is not None:
            st.last_seen = max(st.last_seen, ts)
            if st.status is DeviceStatus.INACTIVE:
                st.status, st.dirty = DeviceStatus.ACTIVE, True
            return
        self._add(ip, None, ts, source)

    def observe_arp(
        self, obs: ArpObservation, source: DiscoverySource = DiscoverySource.PASSIVE_ARP
    ) -> None:
        self.observe_mac(obs.sender_ip, obs.sender_mac, obs.ts_utc, source)

    def observe_mac(self, ip: str, mac: str, ts: float, source: DiscoverySource) -> None:
        st = self._by_ip.get(ip)
        if st is None:
            self._add(ip, mac, ts, source)
            return
        if st.mac is not None and st.mac != mac:
            # The address now belongs to different hardware: retire the old record, start a new one.
            self._retired.append(self._snapshot(st, DeviceStatus.INACTIVE))
            del self._by_ip[ip]
            self._add(ip, mac, ts, source)
            return
        if st.mac is None:
            st.mac, st.dirty = mac, True  # adopt the hardware address learned from ARP
        st.last_seen = max(st.last_seen, ts)
        if st.status is DeviceStatus.INACTIVE:
            st.status, st.dirty = DeviceStatus.ACTIVE, True

    def _add(self, ip: str, mac: str | None, ts: float, source: DiscoverySource) -> None:
        if not self._valid_host(ip):
            return
        if len(self._by_ip) >= self._max:
            self.capped += 1
            return
        self._by_ip[ip] = _State(ip, mac, ts, ts, source)

    def sweep(self, now: float) -> None:
        for st in self._by_ip.values():
            if st.status is DeviceStatus.ACTIVE and now - st.last_seen > self._inactive_after:
                st.status, st.dirty = DeviceStatus.INACTIVE, True

    @staticmethod
    def _snapshot(st: _State, status: DeviceStatus) -> DeviceUpdate:
        return {
            "ip": st.ip,
            "mac": st.mac,
            "first_seen": st.first_seen,
            "last_seen": st.last_seen,
            "status": status.value,
            "source": st.source.value,
        }

    def drain_updates(self, now: float) -> list[DeviceUpdate]:
        """Records that are new, changed, or due for a periodic last_seen refresh."""
        out, self._retired = self._retired, []
        for st in self._by_ip.values():
            if st.dirty or st.last_seen - st.last_persisted >= self._persist_interval:
                out.append(self._snapshot(st, st.status))
                st.dirty, st.last_persisted = False, st.last_seen
        return out

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._by_ip.values() if s.status is DeviceStatus.ACTIVE)
