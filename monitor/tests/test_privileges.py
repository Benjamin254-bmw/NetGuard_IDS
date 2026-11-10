import pytest

from netguard_monitor.privileges import CAP_NET_RAW, current_privileges, parse_cap_eff


def test_parse_cap_eff() -> None:
    assert parse_cap_eff("Name:\tx\nCapEff:\t0000000000003000\n") == 0x3000
    with pytest.raises(ValueError):
        parse_cap_eff("Name:\tx\n")


def test_net_raw_bit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    f = tmp_path / "status"
    f.write_text(f"CapEff:\t{1 << CAP_NET_RAW:016x}\n")
    p = current_privileges(str(f))
    assert p.net_raw and not p.net_admin
    f.write_text("CapEff:\t0000000000000000\n")
    assert not current_privileges(str(f)).net_raw
