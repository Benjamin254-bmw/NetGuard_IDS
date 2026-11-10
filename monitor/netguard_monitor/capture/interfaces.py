"""Network interface discovery and the safety checks that gate packet capture."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path

import psutil

ARPHRD_LOOPBACK = 772


@dataclass(frozen=True)
class InterfaceInfo:
    name: str
    is_up: bool
    mtu: int
    mac: str | None
    ipv4: tuple[IPv4Interface, ...]
    is_loopback: bool


def _is_loopback(name: str) -> bool:
    try:
        return int(Path(f"/sys/class/net/{name}/type").read_text().strip()) == ARPHRD_LOOPBACK
    except (OSError, ValueError):
        return name == "lo"


def list_interfaces() -> list[InterfaceInfo]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out: list[InterfaceInfo] = []
    for name, entries in sorted(addrs.items()):
        ipv4: list[IPv4Interface] = []
        mac: str | None = None
        for e in entries:
            if e.family.name == "AF_INET" and e.netmask:
                ipv4.append(IPv4Interface(f"{e.address}/{e.netmask}"))
            elif e.family.name == "AF_PACKET" and e.address and e.address != "00:00:00:00:00:00":
                mac = e.address.lower()
        st = stats.get(name)
        out.append(
            InterfaceInfo(
                name=name,
                is_up=bool(st and st.isup),
                mtu=st.mtu if st else 0,
                mac=mac,
                ipv4=tuple(ipv4),
                is_loopback=_is_loopback(name),
            )
        )
    return out


def get_interface(name: str) -> InterfaceInfo | None:
    return next((i for i in list_interfaces() if i.name == name), None)


def capture_problems(
    info: InterfaceInfo | None, requested: str | None, scope: IPv4Network | None
) -> list[str]:
    """Reasons capture must not start. An empty list means every safeguard is satisfied."""
    problems: list[str] = []
    if not requested:
        problems.append(
            "NETGUARD_MONITOR_INTERFACE is not set: the interface must be chosen explicitly"
        )
    elif info is None:
        problems.append(f"interface {requested!r} does not exist")
    elif not info.is_up:
        problems.append(f"interface {requested!r} is down")
    if scope is None:
        problems.append(
            "NETGUARD_AUTHORIZED_SUBNET is not set: authorise the monitored network explicitly"
        )
    if (
        info is not None
        and scope is not None
        and info.ipv4
        and not any(a.network.overlaps(scope) for a in info.ipv4)
    ):
        nets = ", ".join(str(a.network) for a in info.ipv4)
        problems.append(
            f"interface {info.name!r} ({nets}) does not overlap the authorised subnet {scope}; "
            "refusing to capture on an interface that is not on the authorised network"
        )
    return problems
