"""Report process privileges so least-privilege deployment can be verified, not assumed."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

CAP_NET_ADMIN = 12
CAP_NET_RAW = 13


@dataclass(frozen=True)
class Privileges:
    is_root: bool
    net_raw: bool
    net_admin: bool


def parse_cap_eff(status_text: str) -> int:
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16)
    raise ValueError("CapEff not found in /proc status text")


def current_privileges(status_path: str = "/proc/self/status") -> Privileges:
    cap_eff = parse_cap_eff(Path(status_path).read_text())
    return Privileges(
        is_root=os.geteuid() == 0,
        net_raw=bool(cap_eff >> CAP_NET_RAW & 1),
        net_admin=bool(cap_eff >> CAP_NET_ADMIN & 1),
    )
