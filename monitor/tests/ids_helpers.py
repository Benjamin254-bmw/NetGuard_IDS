"""Builders shared by the detection tests."""

from __future__ import annotations

from typing import Any

from netguard_common.enums import Protocol, Transport
from netguard_monitor.capture.parser import TCP_ACK, TCP_SYN, Packet
from netguard_monitor.ids.base import RuleConfig
from netguard_monitor.ids.rules import ALL_RULES

T = 1_800_000_000.0
SYN, ACK = TCP_SYN, TCP_ACK
ATT, VIC, NRM = "10.10.10.30", "10.10.10.10", "10.10.10.20"


def cfg(key: str, **over: Any) -> RuleConfig:
    cls = next(c for c in ALL_RULES if c.key == key)
    d = cls.defaults
    base: dict[str, Any] = {
        "rule_id": 1,
        "version": 1,
        "key": key,
        "enabled": True,
        "severity": d.severity.value,
        "threshold": d.threshold,
        "window_seconds": d.window_seconds,
        "cooldown_seconds": d.cooldown_seconds,
        "params": dict(d.params),
    }
    return RuleConfig(**(base | over))


def all_cfgs(**per_rule: dict[str, Any]) -> list[RuleConfig]:
    return [cfg(c.key, rule_id=i + 1, **per_rule.get(c.key, {})) for i, c in enumerate(ALL_RULES)]


def tcp(
    ts: float,
    src: str,
    dst: str,
    dport: int,
    flags: int = SYN,
    size: int = 60,
    direction: str = "internal",
    sport: int = 40000,
) -> Packet:
    return Packet(
        ts, ts, src, dst, sport, dport, Transport.TCP, Protocol.TCP, size, flags, direction, None
    )


def udp_dns(ts: float, src: str, name: str | None, dst: str = VIC) -> Packet:
    return Packet(ts, ts, src, dst, 50000, 53, Transport.UDP, Protocol.DNS, 80, 0, "internal", name)


def bulk(ts: float, src: str, dst: str, size: int, direction: str = "internal") -> Packet:
    return Packet(ts, ts, src, dst, 1, 9001, Transport.UDP, Protocol.UDP, size, 0, direction, None)
