from ipaddress import IPv4Network

import pytest
from pydantic import ValidationError

from netguard_common.config import Settings

pytestmark = pytest.mark.usefixtures("clean_env")


def make(**kw: object) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[arg-type]


def test_defaults_are_safe() -> None:
    s = make()
    assert s.env == "development"
    assert s.monitor_interface is None and s.authorized_subnet is None  # must be explicit


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETGUARD_DB_PORT", "5544")
    monkeypatch.setenv("NETGUARD_AUTHORIZED_SUBNET", "10.10.10.0/24")
    s = make()
    assert s.db_port == 5544 and s.authorized_subnet == IPv4Network("10.10.10.0/24")


def test_empty_values_mean_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETGUARD_MONITOR_INTERFACE", "")
    monkeypatch.setenv("NETGUARD_AUTHORIZED_SUBNET", "  ")
    s = make()
    assert s.monitor_interface is None and s.authorized_subnet is None


def test_ipv6_subnet_rejected() -> None:
    with pytest.raises(ValidationError):
        make(authorized_subnet="fd00::/64")


def test_placeholder_secret_rejected() -> None:
    with pytest.raises(ValidationError, match="placeholder"):
        make(db_api_password="CHANGE_ME")


def test_production_requires_secret_key() -> None:
    with pytest.raises(ValidationError, match="secret_key"):
        make(env="production")


def test_db_url_escapes_special_characters_and_hides_password_in_repr() -> None:
    s = make(db_monitor_password="p@ss:/word?#")
    url = s.db_url("monitor")
    assert url.password == "p@ss:/word?#"
    assert "p@ss" not in str(s) and "p@ss" not in repr(s)
    assert url.username == "netguard_monitor" and url.drivername == "postgresql+psycopg"


def test_db_url_requires_password() -> None:
    with pytest.raises(ValueError, match="not set"):
        make().db_url("api")


def test_unreadable_env_file_is_skipped_not_fatal(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import os

    from netguard_common.config import load_settings

    env = tmp_path / ".env"
    env.write_text("NETGUARD_DB_PORT=1234\n")
    env.chmod(0o000)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETGUARD_DB_PORT", "5555")
    try:
        if os.access(env, os.R_OK):  # running as root: permissions do not apply
            pytest.skip("cannot make a file unreadable for this user")
        assert load_settings().db_port == 5555  # environment still wins; no PermissionError
    finally:
        env.chmod(0o600)
