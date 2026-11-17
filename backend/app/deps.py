"""Shared request plumbing: database transactions and authentication/authorisation dependencies.

Authentication, CSRF and Origin checks happen in ONE dependency (`authenticated`) that every
protected route depends on, so protection cannot be forgotten route by route. Role checks build
on it.
Transactions are explicit (`tx`) and commit before the handler returns: with yield-dependencies the
commit would run after the response is sent.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import Connection, Engine, text

from app import security as sec
from netguard_common.config import Settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_USER = text(
    "SELECT id, username, email, role, is_active, session_version FROM users WHERE id = :id"
)


@dataclass(frozen=True)
class AuthUser:
    id: int
    username: str
    email: str | None
    role: str
    claims: sec.Claims

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_engine(request: Request) -> Engine:
    engine: Engine | None = request.app.state.engine
    if engine is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database not configured")
    return engine


@contextmanager
def tx(request: Request) -> Iterator[Connection]:
    """One transaction: commits when the block ends normally, rolls back on any exception."""
    with get_engine(request).begin() as conn:
        yield conn


def client_ip(request: Request) -> str | None:
    """Direct peer address only. X-Forwarded-For is deliberately not trusted (it is spoofable)."""
    host = request.client.host if request.client else None
    try:
        return str(ip_address(host)) if host else None
    except ValueError:  # unix socket, test client, or anything that is not an address
        return None


def origin_allowed(request: Request, settings: Settings) -> bool:
    """Browsers always send Origin on cross-site and unsafe requests; reject foreign ones."""
    origin = request.headers.get("origin")
    if origin is None:
        return True  # not a browser request (curl, tests, server-to-server)
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    return origin.rstrip("/") in {*settings.origins, own}


def set_session_cookies(
    response: Response, settings: Settings, token: str, claims: sec.Claims
) -> None:
    max_age = int((claims.expires_at - claims.issued_at).total_seconds())
    secure = settings.cookies_secure
    response.set_cookie(
        sec.SESSION_COOKIE, token, max_age=max_age, httponly=True, secure=secure,
        samesite="strict", path="/api",
    )  # fmt: skip
    # Readable by the dashboard script (double-submit CSRF value); carries no authority by itself.
    response.set_cookie(
        sec.CSRF_COOKIE, claims.csrf, max_age=max_age, httponly=False, secure=secure,
        samesite="strict", path="/",
    )  # fmt: skip


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(sec.SESSION_COOKIE, path="/api")
    response.delete_cookie(sec.CSRF_COOKIE, path="/")


def _deny(code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


def authenticated(request: Request, response: Response) -> AuthUser:
    settings = get_settings(request)
    token = request.cookies.get(sec.SESSION_COOKIE)
    if not token:
        raise _deny(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    try:
        claims = sec.decode_token(settings, token)
    except sec.InvalidToken:
        raise _deny(status.HTTP_401_UNAUTHORIZED, "not authenticated") from None
    with tx(request) as conn:
        row = conn.execute(_USER, {"id": claims.user_id}).first()
    if row is None or not row.is_active or row.session_version != claims.session_version:
        raise _deny(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    if request.method not in SAFE_METHODS:
        if not origin_allowed(request, settings):
            raise _deny(status.HTTP_403_FORBIDDEN, "origin not allowed")
        if not sec.csrf_ok(
            claims, request.cookies.get(sec.CSRF_COOKIE), request.headers.get(sec.CSRF_HEADER)
        ):
            raise _deny(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
    now = datetime.now(UTC)
    if sec.should_renew(claims, now):
        new_token, new_claims = sec.issue_token(
            settings, row.id, row.session_version, now, csrf=claims.csrf
        )
        set_session_cookies(response, settings, new_token, new_claims)
    return AuthUser(row.id, row.username, row.email, row.role, claims)


CurrentUser = Annotated[AuthUser, Depends(authenticated)]


def admin_only(user: CurrentUser) -> AuthUser:
    if not user.is_admin:
        raise _deny(status.HTTP_403_FORBIDDEN, "administrator role required")
    return user


AdminUser = Annotated[AuthUser, Depends(admin_only)]
