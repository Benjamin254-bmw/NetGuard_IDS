"""Access-control matrix over every route the application actually registers.

The table below is the policy. The test enumerates the live route table, so a new endpoint that is
not classified here fails the build instead of silently shipping without a decision.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import create_app
from dbhelpers import needs_db
from netguard_common.config import Settings

pytestmark = needs_db

PUBLIC = {
    ("GET", "/api/health"),
    ("GET", "/api/health/ready"),
    ("POST", "/api/auth/login"),
}
ADMIN = {
    ("GET", "/api/users"),
    ("POST", "/api/users"),
    ("PATCH", "/api/users/{user_id}"),
    ("POST", "/api/users/{user_id}/reset-password"),
    ("POST", "/api/users/{user_id}/unlock"),
    ("PATCH", "/api/rules/{rule_id}"),
    ("GET", "/api/audit-logs"),
}
ANALYST = {  # any signed-in user
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/logout-all"),
    ("POST", "/api/auth/change-password"),
    ("GET", "/api/overview"),
    ("GET", "/api/monitor/status"),
    ("GET", "/api/system/info"),
    ("GET", "/api/devices"),
    ("GET", "/api/traffic/series"),
    ("GET", "/api/traffic/protocols"),
    ("GET", "/api/traffic/top-talkers"),
    ("GET", "/api/events"),
    ("GET", "/api/events/{event_id}"),
    ("PATCH", "/api/events/{event_id}"),
    ("GET", "/api/alerts"),
    ("PATCH", "/api/alerts/{alert_id}"),
    ("GET", "/api/rules"),
    ("GET", "/api/rules/{rule_id}"),
}
WEBSOCKETS = {"/api/ws"}
HIDDEN = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}  # dev-only, absent in prod


def flatten(routes: list[object]) -> list[object]:
    """FastAPI wraps include_router() results; look through the wrapper to the real routes.
    (Routers here carry their own prefix, so paths are already complete.)"""
    out: list[object] = []
    for r in routes:
        inner = getattr(r, "original_router", None)
        out.extend(flatten(inner.routes) if inner is not None else [r])
    return out


def routes(app: object) -> tuple[set[tuple[str, str]], set[str]]:
    http: set[tuple[str, str]] = set()
    sockets: set[str] = set()
    for r in flatten(app.routes):  # type: ignore[attr-defined]
        if isinstance(r, APIRoute):
            http |= {(m, r.path) for m in r.methods - {"HEAD", "OPTIONS"}}
        elif isinstance(r, APIWebSocketRoute):
            sockets.add(r.path)
    return http, sockets


def test_every_route_is_classified_exactly_once(api_settings: Settings, db: object) -> None:
    app = create_app(api_settings, engine=db["api"])  # type: ignore[index]
    http, sockets = routes(app)
    assert http == PUBLIC | ADMIN | ANALYST
    assert len(PUBLIC) + len(ADMIN) + len(ANALYST) == len(PUBLIC | ADMIN | ANALYST)  # no overlaps
    assert sockets == WEBSOCKETS


def test_production_exposes_no_docs(api_settings: Settings, db: object) -> None:
    prod = api_settings.model_copy(update={"env": "production"})
    c = TestClient(create_app(prod, engine=db["api"]))  # type: ignore[index]
    for path in HIDDEN:
        assert c.get(path).status_code == 404, path


def call(c: TestClient, method: str, path: str, headers: dict[str, str] | None = None) -> int:
    url = path.replace("{user_id}", "1").replace("{event_id}", "1").replace("{alert_id}", "1")
    url = url.replace("{rule_id}", "1")
    return c.request(method, url, headers=headers or {}, json={}).status_code


@pytest.mark.parametrize("route", sorted(ADMIN | ANALYST))
def test_anonymous_is_always_401(
    route: tuple[str, str], make_client: Callable[..., TestClient]
) -> None:
    c = make_client()
    assert call(c, *route) == 401


@pytest.mark.parametrize("route", sorted(ADMIN))
def test_analyst_is_403_on_admin_routes(
    route: tuple[str, str], signed_in: Callable[..., tuple[TestClient, dict[str, str]]]
) -> None:
    c, csrf = signed_in("ann", "analyst")
    assert call(c, *route, headers=csrf) == 403


@pytest.mark.parametrize("route", sorted(ADMIN | ANALYST))
def test_signed_in_users_are_never_blocked_by_policy_on_permitted_routes(
    route: tuple[str, str], signed_in: Callable[..., tuple[TestClient, dict[str, str]]]
) -> None:
    role = "admin" if route in ADMIN else "analyst"
    c, csrf = signed_in("someone", role)
    # logout routes end the session; the request itself must still be accepted or 4xx on its body
    assert call(c, *route, headers=csrf) not in (401, 403)


UNSAFE = sorted(r for r in ADMIN | ANALYST if r[0] != "GET")


@pytest.mark.parametrize("route", UNSAFE)
def test_unsafe_methods_need_the_csrf_header(
    route: tuple[str, str], signed_in: Callable[..., tuple[TestClient, dict[str, str]]]
) -> None:
    c, _ = signed_in("ann", "analyst")
    assert call(c, *route) == 403  # cookie alone is not enough


@pytest.mark.parametrize("route", UNSAFE)
def test_foreign_origin_is_refused_on_unsafe_methods(
    route: tuple[str, str], signed_in: Callable[..., tuple[TestClient, dict[str, str]]]
) -> None:
    role = "admin" if route in ADMIN else "analyst"
    c, csrf = signed_in("xyz", role)
    assert call(c, *route, headers={**csrf, "origin": "https://evil.example"}) == 403


def test_websocket_requires_authentication(make_client: Callable[..., TestClient]) -> None:
    with make_client() as c, pytest.raises(WebSocketDisconnect), c.websocket_connect("/api/ws"):
        pass
