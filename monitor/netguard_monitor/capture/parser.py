"""Fast, defensive parser: raw Ethernet frame bytes -> metadata only.

Only headers (and, for DNS queries, the queried name) are read. Payloads are never kept, and the
raw bytes are discarded as soon as this function returns. Anything malformed, non-IPv4, or outside
the authorised subnet yields None; this function must never raise on arbitrary input.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from ipaddress import IPv4Network
from struct import unpack_from
from typing import NamedTuple

from netguard_common.enums import Protocol, Transport

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_8021Q = 0x8100

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10

APP_PORTS: dict[int, Protocol] = {
    53: Protocol.DNS,
    80: Protocol.HTTP,
    443: Protocol.HTTPS,
    22: Protocol.SSH,
}

DIRECTION_INTERNAL = "internal"
DIRECTION_INBOUND = "inbound"
DIRECTION_OUTBOUND = "outbound"


class Packet(NamedTuple):
    ts_mono: float
    ts_utc: float
    src_ip: str
    dst_ip: str
    src_port: int  # 0 when the protocol has no ports
    dst_port: int
    transport: Transport
    protocol: Protocol  # application protocol when inferable, else the transport
    size: int  # frame length on the wire
    tcp_flags: int
    direction: str
    dns_qname: str | None


class ArpObservation(NamedTuple):
    ts_utc: float
    sender_ip: str
    sender_mac: str
    target_ip: str
    op: int  # 1 = request, 2 = reply


@dataclass(frozen=True)
class Scope:
    """The authorised IPv4 subnet, pre-computed as integers for cheap membership tests."""

    network: IPv4Network
    net: int
    mask: int

    @classmethod
    def from_network(cls, network: IPv4Network) -> Scope:
        return cls(network, int(network.network_address), int(network.netmask))

    def contains(self, ip_int: int) -> bool:
        return (ip_int & self.mask) == self.net


class ParseStats:
    """Cheap counters so silent discarding is visible rather than invisible."""

    __slots__ = ("malformed", "non_ip", "out_of_scope", "parsed")

    def __init__(self) -> None:
        self.parsed = 0
        self.malformed = 0
        self.non_ip = 0
        self.out_of_scope = 0


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def parse_dns_query_name(data: bytes, offset: int) -> str | None:
    """Return the first question name of a DNS *query* starting at `offset` (the DNS header),
    or None if the message is a response, has no question, or is malformed."""
    if len(data) < offset + 13:
        return None
    flags, qdcount = unpack_from("!HH", data, offset + 2)  # header: id, flags, qdcount, ...
    if flags & 0x8000 or qdcount < 1:  # QR bit set: a response
        return None
    pos = offset + 12
    labels: list[str] = []
    total = 0
    while True:
        if pos >= len(data):
            return None
        n = data[pos]
        if n == 0:
            break
        if n > 63:  # compression pointer or reserved bits: not valid in a question name
            return None
        pos += 1
        if pos + n > len(data):
            return None
        total += n + 1
        if total > 255:
            return None
        labels.append(data[pos : pos + n].decode("ascii", "replace").lower())
        pos += n
    return ".".join(labels) if labels else None


def parse_frame(
    data: bytes,
    real_len: int,
    ts_mono: float,
    ts_utc: float,
    scope: Scope,
    stats: ParseStats | None = None,
) -> Packet | ArpObservation | None:
    try:
        return _parse(data, real_len, ts_mono, ts_utc, scope, stats)
    except Exception:  # noqa: BLE001 - hostile input must never crash the capture pipeline
        if stats is not None:
            stats.malformed += 1
        return None


def _parse(
    data: bytes,
    real_len: int,
    ts_mono: float,
    ts_utc: float,
    scope: Scope,
    stats: ParseStats | None,
) -> Packet | ArpObservation | None:
    if len(data) < 14:
        if stats:
            stats.malformed += 1
        return None
    (ethertype,) = unpack_from("!H", data, 12)
    off = 14
    if ethertype == ETH_P_8021Q:
        if len(data) < 18:
            return None
        (ethertype,) = unpack_from("!H", data, 16)
        off = 18

    if ethertype == ETH_P_ARP:
        return _parse_arp(data, off, ts_utc, scope, stats)
    if ethertype != ETH_P_IP:
        if stats:
            stats.non_ip += 1
        return None

    if len(data) < off + 20:
        if stats:
            stats.malformed += 1
        return None
    ver_ihl = data[off]
    ihl = (ver_ihl & 0x0F) * 4
    if ver_ihl >> 4 != 4 or ihl < 20 or len(data) < off + ihl:
        if stats:
            stats.malformed += 1
        return None
    frag_offset = unpack_from("!H", data, off + 6)[0] & 0x1FFF
    proto = data[off + 9]
    (src_int,) = unpack_from("!I", data, off + 12)
    (dst_int,) = unpack_from("!I", data, off + 16)

    src_in, dst_in = scope.contains(src_int), scope.contains(dst_int)
    if not (src_in or dst_in):
        if stats:
            stats.out_of_scope += 1
        return None
    direction = (
        DIRECTION_INTERNAL
        if src_in and dst_in
        else DIRECTION_OUTBOUND
        if src_in
        else DIRECTION_INBOUND
    )

    l4 = off + ihl
    src_port = dst_port = 0
    flags = 0
    qname: str | None = None
    transport = Transport.OTHER

    if frag_offset == 0:  # non-first fragments carry no transport header
        if proto == 6 and len(data) >= l4 + 14:
            transport = Transport.TCP
            src_port, dst_port = unpack_from("!HH", data, l4)
            flags = data[l4 + 13]
        elif proto == 17 and len(data) >= l4 + 8:
            transport = Transport.UDP
            src_port, dst_port = unpack_from("!HH", data, l4)
            if dst_port == 53:
                qname = parse_dns_query_name(data, l4 + 8)
        elif proto == 1 and len(data) >= l4 + 4:
            transport = Transport.ICMP

    protocol = Protocol(transport.value)
    if transport in (Transport.TCP, Transport.UDP):
        protocol = APP_PORTS.get(dst_port) or APP_PORTS.get(src_port) or protocol

    if stats:
        stats.parsed += 1
    return Packet(
        ts_mono,
        ts_utc,
        socket.inet_ntoa(data[off + 12 : off + 16]),
        socket.inet_ntoa(data[off + 16 : off + 20]),
        src_port,
        dst_port,
        transport,
        protocol,
        real_len,
        flags,
        direction,
        qname,
    )


def _parse_arp(
    data: bytes, off: int, ts_utc: float, scope: Scope, stats: ParseStats | None
) -> ArpObservation | None:
    if len(data) < off + 28:
        if stats:
            stats.malformed += 1
        return None
    htype, ptype, hlen, plen, op = unpack_from("!HHBBH", data, off)
    if htype != 1 or ptype != ETH_P_IP or hlen != 6 or plen != 4 or op not in (1, 2):
        return None
    sender_mac = data[off + 8 : off + 14]
    (sender_ip_int,) = unpack_from("!I", data, off + 14)
    if sender_ip_int == 0 or not scope.contains(sender_ip_int):  # 0.0.0.0 = address probe
        if stats:
            stats.out_of_scope += 1
        return None
    if sender_mac in (b"\x00" * 6, b"\xff" * 6):
        return None
    return ArpObservation(
        ts_utc,
        socket.inet_ntoa(data[off + 14 : off + 18]),
        _mac(sender_mac),
        socket.inet_ntoa(data[off + 24 : off + 28]),
        op,
    )
