from ipaddress import IPv4Network

import pytest

from netguard_monitor.discovery.arp import MIN_PREFIX_LEN, arp_sweep, sweep_target, validate_sweep

AUTH = IPv4Network("10.10.10.0/24")


def test_sweep_target_is_the_overlap_of_authorised_and_attached_networks() -> None:
    assert sweep_target(AUTH, [IPv4Network("10.10.10.0/24")]) == AUTH
    assert sweep_target(AUTH, [IPv4Network("10.10.0.0/16")]) == AUTH  # authorised is narrower
    assert sweep_target(IPv4Network("10.10.0.0/22"), [IPv4Network("10.10.1.0/24")]) == IPv4Network(
        "10.10.1.0/24"
    )


def test_no_target_when_networks_do_not_overlap_or_are_too_large() -> None:
    assert sweep_target(AUTH, [IPv4Network("192.168.1.0/24")]) is None
    assert (
        sweep_target(IPv4Network("10.0.0.0/16"), [IPv4Network("10.0.0.0/16")]) is None
    )  # 65k hosts
    assert sweep_target(AUTH, []) is None


def test_validate_refuses_out_of_scope_and_oversized_sweeps() -> None:
    validate_sweep(IPv4Network("10.10.10.0/24"), AUTH)
    validate_sweep(IPv4Network("10.10.10.128/25"), AUTH)
    with pytest.raises(ValueError, match="outside the authorised"):
        validate_sweep(IPv4Network("192.168.0.0/24"), AUTH)
    with pytest.raises(ValueError, match="outside the authorised"):
        validate_sweep(
            IPv4Network("10.10.0.0/16"), AUTH
        )  # bigger than, not inside, the authorised range
    with pytest.raises(ValueError, match="larger than"):
        validate_sweep(IPv4Network("10.0.0.0/16"), IPv4Network("10.0.0.0/8"))


def test_arp_sweep_enforces_the_guard_before_sending_anything() -> None:
    with pytest.raises(ValueError, match="outside the authorised"):
        arp_sweep("lo", IPv4Network("8.8.8.0/24"), AUTH)  # raises before scapy is even imported
    assert MIN_PREFIX_LEN == 22
