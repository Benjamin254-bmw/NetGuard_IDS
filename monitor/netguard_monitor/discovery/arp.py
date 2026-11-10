"""Active device discovery by ARP sweep. Off by default; strictly limited to the authorised subnet.

ARP only reaches the directly attached network, so the sweep target is the overlap of the
authorised subnet and the interface's own network, and never larger than MIN_PREFIX_LEN allows.
"""

from __future__ import annotations

from ipaddress import IPv4Network

MIN_PREFIX_LEN = 22  # at most 1024 addresses per sweep


def sweep_target(
    authorized: IPv4Network, interface_networks: list[IPv4Network]
) -> IPv4Network | None:
    """The network an ARP sweep may cover, or None if nothing safe exists."""
    for net in interface_networks:
        if net.subnet_of(authorized):
            target = net
        elif authorized.subnet_of(net):
            target = authorized
        else:
            continue
        return target if target.prefixlen >= MIN_PREFIX_LEN else None
    return None


def validate_sweep(network: IPv4Network, authorized: IPv4Network) -> None:
    if not network.subnet_of(authorized):
        raise ValueError(f"refusing to sweep {network}: outside the authorised subnet {authorized}")
    if network.prefixlen < MIN_PREFIX_LEN:
        raise ValueError(f"refusing to sweep {network}: larger than /{MIN_PREFIX_LEN}")


def arp_sweep(
    interface: str, network: IPv4Network, authorized: IPv4Network, timeout: float = 2.0
) -> list[tuple[str, str]]:
    """Send ARP who-has for every address in `network`; return (ip, mac) of responders."""
    validate_sweep(network, authorized)
    # imported lazily: heavy, and only needed here
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        iface=interface,
        timeout=timeout,
        inter=0.003,
        verbose=0,
    )
    return [(rcv[ARP].psrc, str(rcv[ARP].hwsrc).lower()) for _sent, rcv in answered]
