"""The parser is checked against Scapy (an independent implementation) as the oracle."""

import os
import random
from ipaddress import IPv4Network

import pytest
from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Dot1Q, Ether, Raw

from netguard_common.enums import Protocol, Transport
from netguard_monitor.capture.parser import (
    ArpObservation,
    Packet,
    ParseStats,
    Scope,
    parse_dns_query_name,
    parse_frame,
)

SCOPE = Scope.from_network(IPv4Network("10.10.10.0/24"))
ETH = Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")


def parse(frame: object, stats: ParseStats | None = None) -> Packet | ArpObservation | None:
    raw = bytes(frame)  # type: ignore[arg-type]
    return parse_frame(raw, len(raw), 1.0, 1_700_000_000.0, SCOPE, stats)


def as_packet(frame: object) -> Packet:
    result = parse(frame)
    assert isinstance(result, Packet)
    return result


def test_tcp_syn_fields_match_scapy() -> None:
    p = as_packet(
        ETH / IP(src="10.10.10.30", dst="10.10.10.10") / TCP(sport=40000, dport=8080, flags="S")
    )
    assert (p.src_ip, p.dst_ip, p.src_port, p.dst_port) == (
        "10.10.10.30",
        "10.10.10.10",
        40000,
        8080,
    )
    assert p.transport is Transport.TCP and p.protocol is Protocol.TCP
    assert p.tcp_flags == 0x02 and p.direction == "internal" and p.size == 54


@pytest.mark.parametrize(
    ("port", "proto"),
    [(80, Protocol.HTTP), (443, Protocol.HTTPS), (22, Protocol.SSH), (53, Protocol.DNS)],
)
def test_application_protocol_by_port(port: int, proto: Protocol) -> None:
    p = as_packet(ETH / IP(src="10.10.10.30", dst="10.10.10.10") / TCP(sport=50000, dport=port))
    assert p.protocol is proto and p.transport is Transport.TCP


def test_server_reply_is_classified_by_source_port() -> None:
    p = as_packet(
        ETH / IP(src="10.10.10.10", dst="10.10.10.30") / TCP(sport=443, dport=50000, flags="SA")
    )
    assert p.protocol is Protocol.HTTPS and p.tcp_flags == 0x12


def test_udp_and_icmp() -> None:
    u = as_packet(
        ETH
        / IP(src="10.10.10.30", dst="10.10.10.10")
        / UDP(sport=5000, dport=9999)
        / Raw(b"x" * 100)
    )
    assert (
        u.transport is Transport.UDP and u.protocol is Protocol.UDP and u.size == 14 + 20 + 8 + 100
    )
    i = as_packet(ETH / IP(src="10.10.10.30", dst="10.10.10.10") / ICMP())
    assert (
        i.transport is Transport.ICMP
        and i.protocol is Protocol.ICMP
        and (i.src_port, i.dst_port) == (0, 0)
    )


def test_dns_query_name_extracted_lowercased_and_responses_ignored() -> None:
    q = (
        ETH
        / IP(src="10.10.10.20", dst="10.10.10.10")
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="WWW.Example.COM"))
    )
    p = as_packet(q)
    assert p.protocol is Protocol.DNS and p.dns_qname == "www.example.com"
    resp = (
        ETH
        / IP(src="10.10.10.10", dst="10.10.10.20")
        / UDP(sport=53, dport=5353)
        / DNS(
            qr=1, qd=DNSQR(qname="a.example.com"), an=DNSRR(rrname="a.example.com", rdata="1.2.3.4")
        )
    )
    assert as_packet(resp).dns_qname is None  # only queries are interpreted


def test_vlan_tagged_frame() -> None:
    p = as_packet(ETH / Dot1Q(vlan=7) / IP(src="10.10.10.30", dst="10.10.10.10") / TCP(dport=80))
    assert p.dst_port == 80 and p.src_ip == "10.10.10.30"


def test_non_first_fragment_has_no_ports() -> None:
    p = as_packet(
        ETH / IP(src="10.10.10.30", dst="10.10.10.10", proto=17, frag=10) / Raw(b"z" * 40)
    )
    assert p.transport is Transport.OTHER and (p.src_port, p.dst_port) == (0, 0)


def test_direction_and_scope_filtering() -> None:
    out = as_packet(ETH / IP(src="10.10.10.30", dst="93.184.216.34") / TCP(dport=443))
    assert out.direction == "outbound"
    inn = as_packet(ETH / IP(src="93.184.216.34", dst="10.10.10.30") / TCP(sport=443))
    assert inn.direction == "inbound"
    stats = ParseStats()
    assert parse(ETH / IP(src="192.168.5.5", dst="8.8.8.8") / TCP(dport=53), stats) is None
    assert stats.out_of_scope == 1  # not our network: dropped before any metadata is kept


def test_arp_observation_and_probe_handling() -> None:
    req = parse(ETH / ARP(op=1, hwsrc="aa:bb:cc:00:00:30", psrc="10.10.10.30", pdst="10.10.10.10"))
    assert isinstance(req, ArpObservation)
    assert (req.sender_ip, req.sender_mac, req.target_ip, req.op) == (
        "10.10.10.30",
        "aa:bb:cc:00:00:30",
        "10.10.10.10",
        1,
    )
    assert (
        parse(ETH / ARP(op=1, hwsrc="aa:bb:cc:00:00:30", psrc="0.0.0.0", pdst="10.10.10.10"))
        is None
    )
    assert (
        parse(ETH / ARP(op=1, hwsrc="aa:bb:cc:00:00:30", psrc="172.16.0.9", pdst="10.10.10.10"))
        is None
    )


def test_non_ip_ethertype_is_counted_not_crashed() -> None:
    stats = ParseStats()
    assert parse(Ether(type=0x86DD) / Raw(b"\x60" + b"\x00" * 40), stats) is None
    assert stats.non_ip == 1


def test_every_truncation_of_every_frame_is_safe() -> None:
    frames = [
        ETH / IP(src="10.10.10.30", dst="10.10.10.10") / TCP(dport=80, flags="S"),
        ETH
        / IP(src="10.10.10.30", dst="10.10.10.10")
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname="a.b.example.org")),
        ETH / IP(src="10.10.10.30", dst="10.10.10.10") / ICMP(),
        ETH / ARP(op=1, hwsrc="aa:bb:cc:00:00:30", psrc="10.10.10.30", pdst="10.10.10.10"),
        ETH / Dot1Q(vlan=3) / IP(src="10.10.10.30", dst="10.10.10.10") / TCP(),
    ]
    for frame in frames:
        raw = bytes(frame)
        for n in range(len(raw) + 1):
            parse_frame(raw[:n], len(raw), 0.0, 0.0, SCOPE)  # must never raise


def test_random_bytes_never_crash_the_parser() -> None:
    rng = random.Random(int(os.environ.get("FUZZ_SEED", "1234")))
    stats = ParseStats()
    for _ in range(20_000):
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
        parse_frame(blob, len(blob), 0.0, 0.0, SCOPE, stats)
    # also IP-shaped garbage: valid ethertype + version nibble, random everything else
    for _ in range(20_000):
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 120)))
        blob = b"\x00" * 12 + b"\x08\x00" + bytes([0x40 | rng.randint(0, 15)]) + body
        parse_frame(blob, len(blob), 0.0, 0.0, SCOPE, stats)
    assert stats.parsed + stats.malformed + stats.non_ip + stats.out_of_scope >= 0


DNS_HDR = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # id, flags=RD, qdcount=1


def label(text: str) -> bytes:
    return bytes([len(text)]) + text.encode()


def test_dns_parser_positive_control() -> None:
    wire = DNS_HDR + label("www") + label("example") + label("com") + b"\x00" + b"\x00\x01\x00\x01"
    assert parse_dns_query_name(wire, 0) == "www.example.com"


@pytest.mark.parametrize(
    "tail",
    [
        b"\x40" + b"a" * 64 + b"\x00",  # label length 64: reserved bits
        b"\xc0\x0c",  # compression pointer in a question
        b"\x05ab",  # truncated label
        b"\x03abc",  # name never terminated
        b"\x00",  # empty name
        b"".join(label("a" * 60) for _ in range(5)) + b"\x00",  # 305 bytes > 255
    ],
)
def test_malformed_dns_names_return_none(tail: bytes) -> None:
    assert parse_dns_query_name(DNS_HDR + tail, 0) is None


def test_dns_response_flag_and_zero_questions_return_none() -> None:
    body = label("a") + b"\x00"
    response = b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + body
    no_question = b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + body
    assert parse_dns_query_name(response, 0) is None
    assert parse_dns_query_name(no_question, 0) is None
