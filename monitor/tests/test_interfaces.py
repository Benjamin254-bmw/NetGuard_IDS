from ipaddress import IPv4Interface, IPv4Network

from netguard_monitor.capture.interfaces import (
    InterfaceInfo,
    capture_problems,
    get_interface,
    list_interfaces,
)


def iface(
    name: str = "br-lab", up: bool = True, addrs: tuple[str, ...] = ("10.10.10.1/24",)
) -> InterfaceInfo:
    return InterfaceInfo(
        name, up, 1500, "aa:bb:cc:00:00:01", tuple(IPv4Interface(a) for a in addrs), False
    )


SCOPE = IPv4Network("10.10.10.0/24")


def test_loopback_is_listed_and_flagged() -> None:
    lo = get_interface("lo")
    assert lo is not None and lo.is_loopback and lo.is_up
    assert any(i.name == "lo" for i in list_interfaces())


def test_all_safeguards_satisfied_means_no_problems() -> None:
    assert capture_problems(iface(), "br-lab", SCOPE) == []


def test_interface_must_be_chosen_explicitly() -> None:
    assert any("explicitly" in p for p in capture_problems(None, None, SCOPE))
    assert any("explicitly" in p for p in capture_problems(None, "", SCOPE))


def test_missing_and_down_interfaces_are_refused() -> None:
    assert any("does not exist" in p for p in capture_problems(None, "nope0", SCOPE))
    assert any("is down" in p for p in capture_problems(iface(up=False), "br-lab", SCOPE))


def test_authorised_subnet_must_be_set() -> None:
    assert any(
        "authorise the monitored network explicitly" in p
        for p in capture_problems(iface(), "br-lab", None)
    )


def test_interface_on_a_different_network_is_refused() -> None:
    problems = capture_problems(iface("wlan0", addrs=("192.168.1.20/24",)), "wlan0", SCOPE)
    assert len(problems) == 1 and "does not overlap" in problems[0]


def test_interface_without_an_address_is_allowed_for_mirror_ports() -> None:
    assert capture_problems(iface("mon0", addrs=()), "mon0", SCOPE) == []


def test_multiple_addresses_pass_if_any_overlaps() -> None:
    assert capture_problems(iface(addrs=("192.168.1.2/24", "10.10.10.1/24")), "br-lab", SCOPE) == []
