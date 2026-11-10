"""AF_PACKET capture with a kernel BPF filter, kernel-side drop accounting, and truncated reads.

Why not Scapy's sniffer: dissection costs ~100 us per frame in pure Python (see
docs/adr/0011-capture-with-af-packet.md). Here the kernel filters, we copy at most `snaplen` bytes,
and parsing happens on another thread so capture never waits for analysis.
"""

from __future__ import annotations

import contextlib
import ctypes
import socket
import struct

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
SO_RCVBUFFORCE = 33
SOL_PACKET = 263
PACKET_STATISTICS = 6
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _ip_or_arp_filter() -> tuple[_SockFprog, object]:
    """Classic BPF: accept IPv4 (0x0800) and ARP (0x0806) ethertypes, reject everything else."""
    insns = (_SockFilter * 5)(
        _SockFilter(0x28, 0, 0, 12),  # ldh [12]
        _SockFilter(0x15, 2, 0, 0x0800),  # jeq IPv4 -> accept
        _SockFilter(0x15, 1, 0, 0x0806),  # jeq ARP  -> accept
        _SockFilter(0x06, 0, 0, 0),  # reject
        _SockFilter(0x06, 0, 0, 262144),  # accept
    )
    return _SockFprog(5, ctypes.cast(insns, ctypes.POINTER(_SockFilter))), insns


class CaptureSocket:
    def __init__(
        self,
        interface: str,
        *,
        is_loopback: bool = False,
        snaplen: int = 320,
        rcvbuf: int = 8 * 1024 * 1024,
        promiscuous: bool = False,
    ) -> None:
        self.interface = interface
        self.snaplen = snaplen
        self._is_loopback = is_loopback
        self._rcvbuf = rcvbuf
        self._promiscuous = promiscuous
        self._sock: socket.socket | None = None
        self._buf = bytearray(snaplen)
        self.effective_rcvbuf = 0

    def open(self) -> None:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            fprog, keepalive = _ip_or_arp_filter()
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
            del keepalive
            try:  # the kernel copies the program on attach, so the buffers above can be released
                sock.setsockopt(
                    socket.SOL_SOCKET, SO_RCVBUFFORCE, self._rcvbuf
                )  # needs CAP_NET_ADMIN
            except OSError:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, self._rcvbuf
                )  # capped by rmem_max
            self.effective_rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            sock.bind((self.interface, 0))
            if self._promiscuous:
                mreq = struct.pack(
                    "iHH8s", socket.if_nametoindex(self.interface), PACKET_MR_PROMISC, 0, b""
                )
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            sock.settimeout(0.5)
        except Exception:
            sock.close()
            raise
        self._sock = sock

    def _require(self) -> socket.socket:
        if self._sock is None:
            raise RuntimeError("capture socket is not open")
        return self._sock

    def recv(self) -> tuple[int, bytes] | None:
        """Return (real_frame_length, first snaplen bytes), or None only when the socket was idle
        for the whole timeout. Loopback duplicates are skipped here, never reported as 'idle'."""
        sock = self._require()
        while True:
            try:
                n, addr = sock.recvfrom_into(self._buf, self.snaplen, socket.MSG_TRUNC)
            except TimeoutError:
                return None
            if self._is_loopback and addr[2] == PACKET_OUTGOING:
                continue  # loopback delivers every frame twice; keep the incoming copy only
            return n, bytes(self._buf[: min(n, self.snaplen)])

    def kernel_drops(self) -> int:
        """Packets the kernel dropped because this socket's buffer was full, since the last call."""
        sock = self._require()
        _packets, drops = struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        return int(drops)

    def close(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None
