"""Production environment files: each service gets only its own secrets (Phase 8)."""

import pytest
from render_env import quote, render

DEV = {
    "NETGUARD_ENV": "development",
    "NETGUARD_LOG_LEVEL": "INFO",
    "NETGUARD_DB_HOST": "127.0.0.1",
    "NETGUARD_DB_NAME": "netguard",
    "NETGUARD_DB_MIGRATOR_PASSWORD": "migrator-secret",
    "NETGUARD_DB_MONITOR_USER": "netguard_monitor",
    "NETGUARD_DB_MONITOR_PASSWORD": "monitor-secret",
    "NETGUARD_DB_API_USER": "netguard_api",
    "NETGUARD_DB_API_PASSWORD": 'api"se\\cret',
    "NETGUARD_SECRET_KEY": "dev-session-secret-dev-session-secret",
    "NETGUARD_MONITOR_INTERFACE": "eth0",
    "NETGUARD_AUTHORIZED_SUBNET": "192.168.1.0/24",
    "NETGUARD_PROMISCUOUS": "false",
    "NETGUARD_SPILL_DIR": "var/spill",
    "NETGUARD_ALLOWED_ORIGINS": "http://127.0.0.1:5173",
    "NETGUARD_AUTH_LOG_PATH": None,
}


def parse(text: str) -> dict[str, str]:
    """systemd EnvironmentFile semantics for double-quoted values (the only form render() writes)."""
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, raw = line.split("=", 1)
        assert raw.startswith('"') and raw.endswith('"')
        out[key] = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return out


def test_api_file_holds_only_the_api_role_and_a_new_secret() -> None:
    env = parse(render("api", DEV, api_port=8100))
    assert env["NETGUARD_DB_API_PASSWORD"] == 'api"se\\cret'  # quoting round-trips
    assert env["NETGUARD_ENV"] == "production"
    assert env["NETGUARD_SECRET_KEY"] != DEV["NETGUARD_SECRET_KEY"]
    assert len(env["NETGUARD_SECRET_KEY"]) >= 32
    assert env["NETGUARD_API_HOST"] == "127.0.0.1" and env["NETGUARD_API_PORT"] == "8100"
    assert env["NETGUARD_COOKIE_SECURE"] == "true" and env["NETGUARD_ALLOWED_ORIGINS"] == ""
    joined = "\n".join(env.values())
    assert "monitor-secret" not in joined and "migrator-secret" not in joined
    assert "NETGUARD_MONITOR_INTERFACE" not in env


def test_secret_differs_on_every_render() -> None:
    a, b = (parse(render("api", DEV))["NETGUARD_SECRET_KEY"] for _ in range(2))
    assert a != b


def test_monitor_file_holds_no_session_secret_and_no_production_flag() -> None:
    env = parse(render("monitor", DEV))
    assert env["NETGUARD_DB_MONITOR_PASSWORD"] == "monitor-secret"
    assert env["NETGUARD_MONITOR_INTERFACE"] == "eth0"
    assert env["NETGUARD_AUTHORIZED_SUBNET"] == "192.168.1.0/24"
    assert env["NETGUARD_SPILL_DIR"] == "/var/lib/netguard-monitor/spill"
    assert "NETGUARD_SECRET_KEY" not in env and "NETGUARD_ENV" not in env
    joined = "\n".join(env.values())
    assert "api" + '"se' not in joined and "migrator-secret" not in joined
    assert "NETGUARD_AUTH_LOG_PATH" not in env  # unset in the source stays unset


@pytest.mark.parametrize("service,key", [("api", "NETGUARD_DB_API_PASSWORD"),
                                         ("monitor", "NETGUARD_DB_MONITOR_PASSWORD")])
def test_missing_or_placeholder_password_is_refused(service: str, key: str) -> None:
    for bad in (None, "", "CHANGE_ME"):
        with pytest.raises(ValueError, match=key):
            render(service, {**DEV, key: bad})


def test_multiline_values_are_refused() -> None:
    with pytest.raises(ValueError):
        quote("a\nb")
