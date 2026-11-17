"""Behind the reverse proxy (Phase 8): which forwarded headers the API believes, and from whom."""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.__main__ import TRUSTED_PROXIES, server_options
from app.deps import client_ip, origin_allowed
from netguard_common.config import Settings

pytestmark = pytest.mark.usefixtures("clean_env")


def settings(**kw: object) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[call-arg, arg-type]


def echo_client(peer: str) -> TestClient:
    """The real uvicorn middleware, configured exactly as server_options configures it."""
    app = FastAPI()
    s = settings(allowed_origins="")

    @app.get("/echo")
    def echo(request: Request) -> dict[str, object]:
        return {
            "ip": client_ip(request),
            "scheme": request.url.scheme,
            "origin_ok": origin_allowed(request, s),
        }

    opts = server_options(s)
    wrapped = ProxyHeadersMiddleware(app, trusted_hosts=opts["forwarded_allow_ips"])
    return TestClient(wrapped, client=(peer, 40000))  # type: ignore[arg-type]


def test_server_options_pin_the_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")  # must not widen trust
    opts = server_options(settings(api_host="127.0.0.1", api_port=8123))
    assert opts["proxy_headers"] is True
    assert opts["forwarded_allow_ips"] == TRUSTED_PROXIES == "127.0.0.1,::1"
    assert (opts["host"], opts["port"]) == ("127.0.0.1", 8123)


def test_local_proxy_supplies_client_address_and_scheme() -> None:
    r = echo_client("127.0.0.1").get(
        "/echo",
        headers={
            "x-forwarded-for": "192.0.2.44",
            "x-forwarded-proto": "https",
            "host": "netguard.lan",
            "origin": "https://netguard.lan",
        },
    )
    # the browser's https origin matches the API's own origin only because the scheme was forwarded
    assert r.json() == {"ip": "192.0.2.44", "scheme": "https", "origin_ok": True}


def test_remote_peer_cannot_claim_an_address_or_scheme() -> None:
    r = echo_client("198.51.100.7").get(
        "/echo",
        headers={
            "x-forwarded-for": "192.0.2.44",
            "x-forwarded-proto": "https",
            "host": "netguard.lan",
            "origin": "https://netguard.lan",
        },
    )
    assert r.json() == {"ip": "198.51.100.7", "scheme": "http", "origin_ok": False}


def test_foreign_origin_is_refused_behind_the_proxy() -> None:
    r = echo_client("127.0.0.1").get(
        "/echo",
        headers={
            "x-forwarded-for": "192.0.2.44",
            "x-forwarded-proto": "https",
            "host": "netguard.lan",
            "origin": "https://evil.example",
        },
    )
    assert r.json()["origin_ok"] is False
