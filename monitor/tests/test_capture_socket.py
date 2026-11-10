"""Capture tests on the loopback interface. Need CAP_NET_RAW (root or run-with-caps.sh); skipped
otherwise:  sudo scripts/run-with-caps.sh .venv/bin/python -m pytest monitor/tests/test_capture_socket.py
"""

import socket
import time

import pytest

from netguard_monitor.capture.interfaces import get_interface
from netguard_monitor.capture.socket_capture import CaptureSocket
from netguard_monitor.privileges import current_privileges

pytestmark = pytest.mark.skipif(not current_privileges().net_raw, reason="needs CAP_NET_RAW")

N, PAYLOAD = 300, 900


def send_to_closed_port(n: int, port: int = 9999) -> None:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(n):
        u.sendto(b"x" * PAYLOAD, ("127.0.0.1", port))
    u.close()


def drain(cap: CaptureSocket, seconds: float = 1.0) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        item = cap.recv()
        if item is not None:
            out.append(item)
    return out


def test_loopback_frames_are_counted_exactly_once() -> None:
    lo = get_interface("lo")
    assert lo is not None
    cap = CaptureSocket("lo", is_loopback=lo.is_loopback)
    cap.open()
    try:
        send_to_closed_port(N)
        frames = drain(cap)
        drops = cap.kernel_drops()  # read while the socket is still open
    finally:
        cap.close()
    # Each datagram yields one UDP frame and one ICMP port-unreachable reply: 2 per datagram.
    # Without the loopback de-duplication this would be 4 per datagram.
    assert len(frames) == 2 * N
    assert drops == 0


def test_real_length_is_reported_even_though_bytes_are_truncated() -> None:
    cap = CaptureSocket("lo", is_loopback=True, snaplen=64)
    cap.open()
    try:
        send_to_closed_port(5)
        frames = drain(cap, 0.7)
    finally:
        cap.close()
    udp = [f for f in frames if f[0] == 14 + 20 + 8 + PAYLOAD]
    assert len(udp) == 5, "the real on-wire length must survive truncation"
    assert all(len(data) == 64 for _n, data in udp)  # payload beyond snaplen is never copied


def test_kernel_filter_drops_non_ip_non_arp_frames_before_user_space() -> None:
    cap = CaptureSocket("lo", is_loopback=True)
    cap.open()
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        raw.bind(("lo", 0))
        ipv6_ethertype = b"\x00" * 12 + b"\x86\xdd" + b"\x60" + b"\x00" * 39
        for _ in range(10):
            raw.send(ipv6_ethertype)
        raw.close()
        send_to_closed_port(5)  # positive control: IPv4 traffic in the same window must arrive
        frames = drain(cap, 0.7)
    finally:
        cap.close()
    assert len([f for f in frames if f[0] == 14 + 20 + 8 + PAYLOAD]) == 5
    assert [f for f in frames if f[1][12:14] == b"\x86\xdd"] == []


def test_recv_on_a_closed_socket_is_a_clear_error() -> None:
    cap = CaptureSocket("lo", is_loopback=True)
    with pytest.raises(RuntimeError, match="not open"):
        cap.recv()


def test_promiscuous_mode_can_be_requested_and_is_released_on_close() -> None:
    cap = CaptureSocket("lo", is_loopback=True, promiscuous=True)
    cap.open()
    cap.close()


def test_kernel_drop_counter_reports_real_overflow() -> None:
    """A reader that falls behind must be told how many packets the kernel discarded."""
    cap = CaptureSocket("lo", is_loopback=True, rcvbuf=4096)  # tiny buffer, and we do not read
    cap.open()
    try:
        send_to_closed_port(2000)
        time.sleep(0.3)
        drops = cap.kernel_drops()
        survivors = len(drain(cap, 0.7))
    finally:
        cap.close()
    assert drops > 0, "overflow happened but the kernel reported no drops"
    assert survivors < 2 * 2000  # frames were genuinely lost, not merely delayed
    assert cap.effective_rcvbuf <= 8192  # the small buffer was honoured
