"""Sign-in, sign-out, current user, password change."""

from __future__ import annotations

import math
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import Row, text

from app import security as sec
from app.audit import audit
from app.deps import (
    AuthUser,
    CurrentUser,
    clear_session_cookies,
    client_ip,
    get_settings,
    set_session_cookies,
    tx,
)
from app.schemas import LoginIn, PasswordChangeIn, SessionOut, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])

# One message for every sign-in failure (unknown user, wrong password, locked, inactive): the
# response must not reveal which usernames exist or whether an account is locked.
GENERIC_FAILURE = "invalid credentials, or sign-in is temporarily paused after repeated failures"

_FIND = text(
    "SELECT id, username, email, role, is_active, password_hash, failed_login_count, "
    "locked_until, session_version FROM users WHERE lower(username) = lower(:u) FOR UPDATE"
)
_FIND_ID = text(
    "SELECT id, username, password_hash, failed_login_count, locked_until, session_version "
    "FROM users WHERE id = :id FOR UPDATE"
)
_FAIL = text("UPDATE users SET failed_login_count = :n, locked_until = :until WHERE id = :id")
_OK = text(
    "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = :now, "
    "password_hash = :h WHERE id = :id"
)


def _user_of(user: AuthUser) -> UserOut:
    return UserOut(id=user.id, username=user.username, email=user.email, role=user.role)


def _user_out(row: Row[Any]) -> UserOut:
    return UserOut(id=row.id, username=row.username, email=row.email, role=row.role)


@router.post("/login", response_model=SessionOut)
def login(body: LoginIn, request: Request, response: Response) -> SessionOut:
    settings = get_settings(request)
    ip = client_ip(request)  # None when the peer is not an IP address
    key = ip or "unknown"  # limiter key; never written to the audit log
    limiter = request.app.state.limiter
    wait = limiter.blocked(key, time.monotonic())
    if wait:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed sign-in attempts from this address",
            headers={"Retry-After": str(math.ceil(wait))},
        )
    now = datetime.now(UTC)
    granted: Row[Any] | None = None
    with tx(request) as conn:
        row = conn.execute(_FIND, {"u": body.username}).first()
        if row is None:
            sec.burn_password_check(body.password)
            audit(
                conn, "auth.login_failed", actor_user_id=None, source_ip=ip,
                details={"reason": "unknown_user", "username": body.username[:64]},
            )  # fmt: skip
        else:
            who = {"source_ip": ip, "target_type": "user", "target_id": row.id}
            locked = sec.is_locked(row.locked_until, now)
            valid = sec.verify_password(row.password_hash, body.password)  # always: uniform timing
            if locked:
                audit(conn, "auth.login_blocked", actor_user_id=None, **who,
                      details={"reason": "locked"})  # fmt: skip
            elif not valid:
                count, until = sec.after_failed_login(row.failed_login_count, row.locked_until, now)
                conn.execute(_FAIL, {"n": count, "until": until, "id": row.id})
                audit(conn, "auth.login_failed", actor_user_id=None, **who,
                      details={"reason": "bad_password", "failed_count": count})  # fmt: skip
                if until is not None and until != row.locked_until:
                    audit(conn, "auth.account_locked", actor_user_id=None, **who,
                          details={"until": until.isoformat()})  # fmt: skip
            elif not row.is_active:
                audit(conn, "auth.login_failed", actor_user_id=None, **who,
                      details={"reason": "inactive"})  # fmt: skip
            else:
                keep = row.password_hash
                new_hash = sec.hash_password(body.password) if sec.needs_rehash(keep) else keep
                conn.execute(_OK, {"now": now, "h": new_hash, "id": row.id})
                audit(conn, "auth.login", actor_user_id=row.id, **who)
                granted = row
    if granted is None:
        limiter.record_failure(key, time.monotonic())
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_FAILURE)
    token, claims = sec.issue_token(settings, granted.id, granted.session_version, now)
    set_session_cookies(response, settings, token, claims)
    return SessionOut(user=_user_out(granted))


@router.get("/me", response_model=SessionOut)
def me(user: CurrentUser) -> SessionOut:
    return SessionOut(user=_user_of(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: CurrentUser) -> Response:
    with tx(request) as conn:
        audit(conn, "auth.logout", actor_user_id=user.id, source_ip=client_ip(request))
    out = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookies(out)
    return out


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(request: Request, user: CurrentUser) -> Response:
    """Revoke every session of this user (a stolen token stops working immediately)."""
    with tx(request) as conn:
        conn.execute(
            text("UPDATE users SET session_version = session_version + 1 WHERE id = :id"),
            {"id": user.id},
        )
        audit(conn, "auth.logout_all", actor_user_id=user.id, source_ip=client_ip(request))
    out = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookies(out)
    return out


@router.post("/change-password", response_model=SessionOut)
def change_password(
    body: PasswordChangeIn, request: Request, response: Response, user: CurrentUser
) -> SessionOut:
    settings = get_settings(request)
    ip = client_ip(request)
    now = datetime.now(UTC)
    problem = sec.password_problem(body.new_password, user.username)
    if problem:
        raise HTTPException(422, f"new password {problem}")
    new_hash = sec.hash_password(body.new_password)
    outcome = "ok"
    version = 0
    with tx(request) as conn:
        row = conn.execute(_FIND_ID, {"id": user.id}).one()
        if sec.is_locked(row.locked_until, now):
            outcome = "locked"
        elif not sec.verify_password(row.password_hash, body.current_password):
            # Counts like a failed sign-in: a stolen session must not be able to brute-force it.
            count, until = sec.after_failed_login(row.failed_login_count, row.locked_until, now)
            conn.execute(_FAIL, {"n": count, "until": until, "id": row.id})
            audit(conn, "auth.password_change_failed", actor_user_id=user.id, source_ip=ip)
            outcome = "bad_current"
        else:
            version = row.session_version + 1
            conn.execute(
                text(
                    "UPDATE users SET password_hash = :h, password_changed_at = :now, "
                    "session_version = :v, failed_login_count = 0, locked_until = NULL "
                    "WHERE id = :id"
                ),
                {"h": new_hash, "now": now, "v": version, "id": user.id},
            )
            audit(conn, "auth.password_changed", actor_user_id=user.id, source_ip=ip,
                  target_type="user", target_id=user.id)  # fmt: skip
    if outcome == "locked":
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many failed attempts; try later"
        )
    if outcome == "bad_current":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is incorrect")
    token, claims = sec.issue_token(settings, user.id, version, now)  # this session continues
    set_session_cookies(response, settings, token, claims)
    return SessionOut(user=_user_of(user))
