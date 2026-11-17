"""Phase 5 columns on users: defaults, constraints, and who may change them."""

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError

from dbhelpers import constraint_of, denied, needs_db, run

pytestmark = needs_db

NEW_USER = "INSERT INTO users (username, password_hash) VALUES (:u, 'x') RETURNING id"


def test_defaults(db: dict[str, Engine]) -> None:
    uid = run(db["api"], NEW_USER, u="alice")[0][0]
    row = run(
        db["api"],
        "SELECT failed_login_count, locked_until, session_version, password_changed_at "
        "FROM users WHERE id=:i",
        i=uid,
    )[0]
    assert tuple(row) == (0, None, 1, None)


@pytest.mark.parametrize(
    ("column", "value", "constraint"),
    [
        ("failed_login_count", -1, "ck_users_failed_login_count_nonneg"),
        ("session_version", 0, "ck_users_session_version_positive"),
    ],
)
def test_constraints_reject_bad_values(
    db: dict[str, Engine], column: str, value: int, constraint: str
) -> None:
    uid = run(db["api"], NEW_USER, u="bob")[0][0]
    with pytest.raises(IntegrityError) as exc:
        run(db["api"], f"UPDATE users SET {column} = :v WHERE id = :i", v=value, i=uid)  # noqa: S608
    assert constraint_of(exc.value) == constraint


def test_api_can_throttle_and_revoke_but_monitor_cannot_touch_users(db: dict[str, Engine]) -> None:
    uid = run(db["api"], NEW_USER, u="carol")[0][0]
    run(
        db["api"],
        "UPDATE users SET failed_login_count = 5, locked_until = now() + interval '15 minutes', "
        "session_version = session_version + 1 WHERE id = :i",
        i=uid,
    )
    assert denied(db["monitor"], "SELECT failed_login_count FROM users")
    assert denied(db["monitor"], "UPDATE users SET session_version = 99")
