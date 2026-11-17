"""User administration (administrators only)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import Row, text
from sqlalchemy.exc import IntegrityError

from app import security as sec
from app.audit import audit
from app.deps import AdminUser, client_ip, tx
from app.schemas import PasswordResetIn, UserCreateIn, UserOut, UserPatchIn

router = APIRouter(prefix="/api/users", tags=["users"])

_COLS = "id, username, email, role, is_active, created_at, last_login_at, locked_until"


def _out(row: Row[Any], now: datetime) -> UserOut:
    return UserOut(
        id=row.id,
        username=row.username,
        email=row.email,
        role=row.role,
        is_active=row.is_active,
        created_at=row.created_at,
        last_login_at=row.last_login_at,
        locked=sec.is_locked(row.locked_until, now),
    )


def _problem(password: str, username: str) -> None:
    msg = sec.password_problem(password, username)
    if msg:
        raise HTTPException(422, f"password {msg}")


@router.get("", response_model=list[UserOut])
def list_users(request: Request, _: AdminUser) -> list[UserOut]:
    now = datetime.now(UTC)
    with tx(request) as conn:
        rows = conn.execute(text(f"SELECT {_COLS} FROM users ORDER BY id")).all()  # noqa: S608
    return [_out(r, now) for r in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreateIn, request: Request, admin: AdminUser) -> UserOut:
    _problem(body.password, body.username)
    pw_hash = sec.hash_password(body.password)
    now = datetime.now(UTC)
    try:
        with tx(request) as conn:
            row = conn.execute(
                text(
                    "INSERT INTO users (username, email, password_hash, role, password_changed_at) "
                    "VALUES (:u, :e, :h, :r, :now) RETURNING "
                    "id, username, email, role, is_active, created_at, last_login_at, locked_until"
                ),
                {"u": body.username, "e": body.email, "h": pw_hash, "r": body.role, "now": now},
            ).one()
            audit(conn, "user.created", actor_user_id=admin.id, source_ip=client_ip(request),
                  target_type="user", target_id=row.id,
                  details={"username": row.username, "role": row.role})  # fmt: skip
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "username or email already in use") from None
    return _out(row, now)


@router.patch("/{user_id}", response_model=UserOut)
def patch_user(user_id: int, body: UserPatchIn, request: Request, admin: AdminUser) -> UserOut:
    now = datetime.now(UTC)
    changes = body.model_fields_set
    if not changes:
        raise HTTPException(422, "nothing to change")
    try:
        with tx(request) as conn:
            # Lock every active administrator first, so two concurrent requests cannot each
            # remove "the other" administrator and leave none.
            admins = {
                r.id
                for r in conn.execute(
                    text("SELECT id FROM users WHERE role = 'admin' AND is_active FOR UPDATE")
                )
            }
            cur = conn.execute(
                text(f"SELECT {_COLS}, session_version FROM users WHERE id = :i FOR UPDATE"),  # noqa: S608
                {"i": user_id},
            ).first()
            if cur is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
            role = body.role if "role" in changes and body.role else cur.role
            wants_active = "is_active" in changes and body.is_active is not None
            active = body.is_active if wants_active else cur.is_active
            email = body.email if "email" in changes else cur.email
            if cur.id in admins and (role != "admin" or not active) and len(admins) == 1:
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "cannot remove the last active administrator"
                )
            access_changed = (role, active) != (cur.role, cur.is_active)
            row = conn.execute(
                text(
                    "UPDATE users SET role = :r, is_active = :a, email = :e, "
                    "session_version = session_version + CASE WHEN :bump THEN 1 ELSE 0 END "
                    "WHERE id = :i RETURNING "
                    "id, username, email, role, is_active, created_at, last_login_at, locked_until"
                ),
                {"r": role, "a": active, "e": email, "bump": access_changed, "i": user_id},
            ).one()
            before = {"role": cur.role, "is_active": cur.is_active, "email": cur.email}
            after = {"role": role, "is_active": active, "email": email}
            audit(
                conn, "user.updated", actor_user_id=admin.id, source_ip=client_ip(request),
                target_type="user", target_id=user_id,
                details={"before": before, "after": after, "sessions_revoked": access_changed},
            )  # fmt: skip
    except IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "email already in use") from None
    return _out(row, now)


@router.post("/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(user_id: int, body: PasswordResetIn, request: Request, admin: AdminUser) -> None:
    with tx(request) as conn:
        target = conn.execute(
            text("SELECT username FROM users WHERE id = :i"), {"i": user_id}
        ).first()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    _problem(body.new_password, target.username)
    pw_hash = sec.hash_password(body.new_password)
    with tx(request) as conn:
        n = conn.execute(
            text(
                "UPDATE users SET password_hash = :h, password_changed_at = now(), "
                "session_version = session_version + 1, failed_login_count = 0, "
                "locked_until = NULL WHERE id = :i"
            ),
            {"h": pw_hash, "i": user_id},
        ).rowcount
        if n != 1:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        audit(conn, "user.password_reset", actor_user_id=admin.id, source_ip=client_ip(request),
              target_type="user", target_id=user_id)  # fmt: skip


@router.post("/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
def unlock(user_id: int, request: Request, admin: AdminUser) -> None:
    with tx(request) as conn:
        n = conn.execute(
            text("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = :i"),
            {"i": user_id},
        ).rowcount
        if n != 1:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        audit(conn, "user.unlocked", actor_user_id=admin.id, source_ip=client_ip(request),
              target_type="user", target_id=user_id)  # fmt: skip
