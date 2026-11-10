"""Authentication-log source: parse sshd failure lines and tail the log file safely.

Safety properties: starts at the END of the file (history is not an attack happening now);
survives rotation, truncation and in-place rewrite; buffers partial lines; reads at most
MAX_READ bytes per poll and ignores absurdly long lines. Only the source IPv4 address is kept.
"""

from __future__ import annotations

import os
import re
import time
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from typing import BinaryIO

from netguard_monitor.ids.base import AuthFailure

MAX_READ = 1_048_576
MAX_LINE = 4096
HEAD = 64

# Accepts both syslog-style lines ("... sshd[123]: Failed password ...") and the bare format that
# sshd itself writes with -E/-e ("Failed password ..."). The bare form must start the line, so a
# similar message from another program ("sudo[1]: Failed password ...") is not mistaken for sshd.
_FAILED = re.compile(
    r"(?:sshd(?:-session)?\[\d+\]:\s+|^)"
    r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)


def parse_auth_line(line: str, ts: float) -> AuthFailure | None:
    m = _FAILED.search(line)
    if m is None:
        return None
    try:
        ip = str(IPv4Address(m.group(1)))
    except AddressValueError:
        return None
    return AuthFailure(ts, ip)


class LogTailer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.error: str | None = None
        self._fh: BinaryIO | None = None
        self._ino: int | None = None
        self._pos = 0
        self._head = b""
        self._buf = b""
        self._start_at_end = True
        self._open()

    def _open(self) -> None:
        try:
            fh = open(self.path, "rb")  # noqa: SIM115 - kept open between polls
            st = os.fstat(fh.fileno())
        except OSError as exc:
            self.error = type(exc).__name__
            self._fh = None
            self._start_at_end = False  # a file that appears later is new: read it from the start
            return
        self.error = None
        self._fh, self._ino = fh, st.st_ino
        if self._start_at_end:
            self._pos = st.st_size
            fh.seek(self._pos)
            self._head = self._read_head(fh)
        else:
            self._pos = 0
            self._head = b""
        self._start_at_end = False  # later (re)opens read the new file from its beginning
        self._buf = b""

    @staticmethod
    def _read_head(fh: BinaryIO) -> bytes:
        here = fh.tell()
        fh.seek(0)
        head: bytes = fh.read(HEAD)
        fh.seek(here)
        return head

    def _reopen_from_start(self) -> None:
        if self._fh is not None:
            self._fh.close()
        self._fh = None
        self._open()

    def poll(self) -> list[AuthFailure]:
        if self._fh is None:
            self._open()
            if self._fh is None:
                return []
        try:
            st = os.stat(self.path)
        except OSError as exc:
            self.error = type(exc).__name__
            return []
        self.error = None
        assert self._fh is not None  # noqa: S101
        rotated = st.st_ino != self._ino
        truncated = st.st_size < self._pos
        rewritten = False
        if not rotated and not truncated and self._head and len(self._head) <= st.st_size:
            here = self._fh.tell()
            self._fh.seek(0)
            rewritten = self._fh.read(len(self._head)) != self._head
            self._fh.seek(here)
        if rotated or truncated or rewritten:
            self._reopen_from_start()
            if self._fh is None:
                return []
        data = self._fh.read(MAX_READ)
        self._pos = self._fh.tell()
        if not self._head:
            self._head = self._read_head(self._fh)  # fingerprint of the file's first bytes
        if not data:
            return []
        now = time.time()
        buf = self._buf + data
        *lines, self._buf = buf.split(b"\n")
        if len(self._buf) > MAX_LINE:
            self._buf = b""
        out: list[AuthFailure] = []
        for raw in lines:
            if len(raw) > MAX_LINE:
                continue
            f = parse_auth_line(raw.decode("utf-8", "replace"), now)
            if f is not None:
                out.append(f)
        return out

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
