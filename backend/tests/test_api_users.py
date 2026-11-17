"""User administration: RBAC, last-administrator protection, session revocation, the CLI."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app import cli
from conftest import PASSWORD, sign_in  # type: ignore[import-not-found]
from dbhelpers import needs_db, run
from netguard_common.config import Settings

pytestmark = needs_db

Make = Callable[..., TestClient]
MakeUser = Callable[..., int]
Signed = Callable[..., tuple[TestClient, dict[str, str]]]
GOOD = "a long enough passphrase"


def admin_count(db: dict[str, Engine]) -> int:
    return int(run(db["api"], "SELECT count(*) FROM users WHERE role='admin' AND is_active")[0][0])


def test_analysts_cannot_touch_user_administration(signed_in: Signed) -> None:
    c, csrf = signed_in("ann", "analyst")
    assert c.get("/api/users").status_code == 403
    assert (
        c.post("/api/users", headers=csrf, json={"username": "x" * 3, "password": GOOD}).status_code
        == 403
    )
    assert c.patch("/api/users/1", headers=csrf, json={"role": "admin"}).status_code == 403
    assert (
        c.post("/api/users/1/reset-password", headers=csrf, json={"new_password": GOOD}).status_code
        == 403
    )
    assert c.post("/api/users/1/unlock", headers=csrf).status_code == 403


def test_create_list_and_sign_in_as_the_new_user(
    signed_in: Signed, make_client: Make, db: dict[str, Engine]
) -> None:
    admin, csrf = signed_in("root", "admin")
    r = admin.post("/api/users", headers=csrf, json={"username": "newbie", "password": GOOD,
                                                      "role": "analyst", "email": "n@example.org"})  # fmt: skip
    assert r.status_code == 201 and r.json()["role"] == "analyst" and "password" not in r.text
    assert [u["username"] for u in admin.get("/api/users").json()] == ["root", "newbie"]
    other = make_client()
    sign_in(other, "newbie", GOOD)
    assert run(db["api"], "SELECT action FROM audit_logs WHERE action='user.created'")


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"username": "ROOT", "password": GOOD}, 409),  # duplicate, case-insensitive
        ({"username": "ab", "password": GOOD}, 422),
        ({"username": "has space", "password": GOOD}, 422),
        ({"username": "okname", "password": "short"}, 422),
        ({"username": "okname", "password": GOOD, "role": "owner"}, 422),
        ({"username": "okname", "password": GOOD, "is_admin": True}, 422),
        ({"username": "okname", "password": GOOD, "email": "not-an-email"}, 422),
        ({"username": "okname", "password": "my okname passphrase"}, 422),  # contains the username
    ],
)
def test_create_validation(signed_in: Signed, body: dict[str, object], code: int) -> None:
    admin, csrf = signed_in("root", "admin")
    assert admin.post("/api/users", headers=csrf, json=body).status_code == code


def test_duplicate_email_is_a_conflict(signed_in: Signed) -> None:
    admin, csrf = signed_in("root", "admin")
    ok = {"username": "u1user", "password": GOOD, "email": "Same@Example.org"}
    assert admin.post("/api/users", headers=csrf, json=ok).status_code == 201
    dup = {**ok, "username": "u2user", "email": "same@example.org"}
    assert admin.post("/api/users", headers=csrf, json=dup).status_code == 409


def test_list_reports_locked_accounts(signed_in: Signed, make_user: MakeUser) -> None:
    make_user("stuck", locked_until=datetime.now(UTC) + timedelta(minutes=5))
    make_user("fine")
    admin, _ = signed_in("root", "admin")
    flags = {u["username"]: u["locked"] for u in admin.get("/api/users").json()}
    assert flags == {"stuck": True, "fine": False, "root": False}


# --------------------------------------------------------------------- last administrator
def test_the_last_active_administrator_cannot_be_demoted_or_deactivated(
    signed_in: Signed, db: dict[str, Engine]
) -> None:
    admin, csrf = signed_in("root", "admin")
    me = admin.get("/api/auth/me").json()["user"]["id"]
    for body in ({"role": "analyst"}, {"is_active": False}):
        r = admin.patch(f"/api/users/{me}", headers=csrf, json=body)
        assert r.status_code == 409 and "last active administrator" in r.text
    assert admin_count(db) == 1


def test_with_a_second_administrator_demotion_is_allowed(
    signed_in: Signed, make_user: MakeUser
) -> None:
    admin, csrf = signed_in("root", "admin")
    other = make_user("second", "admin")
    assert (
        admin.patch(f"/api/users/{other}", headers=csrf, json={"role": "analyst"}).status_code
        == 200
    )


def race(
    c1: TestClient,
    h1: dict[str, str],
    target1: int,
    c2: TestClient,
    h2: dict[str, str],
    target2: int,
) -> list[int]:
    """Send two role changes at the same instant from two threads; return both status codes."""
    results: list[int] = []
    barrier = threading.Barrier(2)

    def go(client: TestClient, csrf: dict[str, str], target: int) -> None:
        barrier.wait()
        resp = client.patch(f"/api/users/{target}", headers=csrf, json={"role": "analyst"})
        results.append(resp.status_code)

    threads = [
        threading.Thread(target=go, args=(c1, h1, target1)),
        threading.Thread(target=go, args=(c2, h2, target2)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_concurrent_demotions_cannot_remove_every_administrator(
    make_client: Make, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    """Two administrators demote each other at the same instant, repeated: a missing row lock
    shows up as zero administrators in some round (one round alone catches it only sometimes)."""
    a_id, b_id = make_user("alpha", "admin"), make_user("bravo", "admin")
    for _ in range(20):
        run(
            db["api"],
            "UPDATE users SET role='admin', is_active=true, session_version=session_version+1",
        )
        a, b = make_client(), make_client()
        ca, cb = sign_in(a, "alpha"), sign_in(b, "bravo")
        results = race(a, ca, b_id, b, cb, a_id)
        assert admin_count(db) >= 1, f"no administrator left; statuses {results}"
        assert results.count(200) == 1, results


# --------------------------------------------------------------------- effects of changes
def test_demotion_takes_effect_on_the_next_request_without_new_sign_in(
    make_client: Make, make_user: MakeUser, signed_in: Signed
) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user("promo", "admin")
    c = make_client()
    sign_in(c, "promo")
    assert c.get("/api/users").status_code == 200
    admin.patch(f"/api/users/{uid}", headers=csrf, json={"role": "analyst"})
    assert c.get("/api/users").status_code == 401  # session revoked; a fresh login is analyst


def test_deactivation_revokes_sessions_and_blocks_sign_in(
    make_client: Make, make_user: MakeUser, signed_in: Signed
) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user("leaver")
    c = make_client()
    sign_in(c, "leaver")
    assert (
        admin.patch(f"/api/users/{uid}", headers=csrf, json={"is_active": False}).status_code == 200
    )
    assert c.get("/api/auth/me").status_code == 401
    assert (
        c.post("/api/auth/login", json={"username": "leaver", "password": PASSWORD}).status_code
        == 401
    )


def test_email_change_does_not_revoke_sessions(
    make_client: Make, make_user: MakeUser, signed_in: Signed
) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user("keeper")
    c = make_client()
    sign_in(c, "keeper")
    r = admin.patch(f"/api/users/{uid}", headers=csrf, json={"email": "k@example.org"})
    assert r.status_code == 200 and r.json()["email"] == "k@example.org"
    assert c.get("/api/auth/me").status_code == 200


def test_patch_edge_cases(signed_in: Signed, make_user: MakeUser) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user("target")
    assert admin.patch(f"/api/users/{uid}", headers=csrf, json={}).status_code == 422
    assert admin.patch("/api/users/999999", headers=csrf, json={"role": "admin"}).status_code == 404
    assert admin.patch(f"/api/users/{uid}", headers=csrf, json={"role": "root"}).status_code == 422


def test_patch_is_audited_with_before_and_after(
    signed_in: Signed, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user("target")
    admin.patch(f"/api/users/{uid}", headers=csrf, json={"role": "admin"})
    d = run(db["api"], "SELECT details FROM audit_logs WHERE action='user.updated'")[0][0]
    assert (
        d["before"]["role"] == "analyst"
        and d["after"]["role"] == "admin"
        and d["sessions_revoked"] is True
    )


def test_reset_password_revokes_sessions_clears_lock_and_enforces_policy(
    make_client: Make, make_user: MakeUser, signed_in: Signed
) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user(
        "forgot", locked_until=datetime.now(UTC) + timedelta(minutes=9), failed_login_count=5
    )
    assert (
        admin.post(
            f"/api/users/{uid}/reset-password", headers=csrf, json={"new_password": "short"}
        ).status_code
        == 422
    )
    assert (
        admin.post(
            "/api/users/999999/reset-password", headers=csrf, json={"new_password": GOOD}
        ).status_code
        == 404
    )
    assert (
        admin.post(
            f"/api/users/{uid}/reset-password", headers=csrf, json={"new_password": GOOD}
        ).status_code
        == 204
    )
    c = make_client()
    assert (
        c.post("/api/auth/login", json={"username": "forgot", "password": GOOD}).status_code == 200
    )


def test_unlock(signed_in: Signed, make_client: Make, make_user: MakeUser) -> None:
    admin, csrf = signed_in("root", "admin")
    uid = make_user(
        "stuck", locked_until=datetime.now(UTC) + timedelta(minutes=9), failed_login_count=5
    )
    c = make_client()
    assert (
        c.post("/api/auth/login", json={"username": "stuck", "password": PASSWORD}).status_code
        == 401
    )
    assert admin.post(f"/api/users/{uid}/unlock", headers=csrf).status_code == 204
    assert (
        c.post("/api/auth/login", json={"username": "stuck", "password": PASSWORD}).status_code
        == 200
    )
    assert admin.post("/api/users/999999/unlock", headers=csrf).status_code == 404


def test_admin_actions_need_csrf(signed_in: Signed) -> None:
    admin, _ = signed_in("root", "admin")
    assert (
        admin.post("/api/users", json={"username": "okname", "password": GOOD}).status_code == 403
    )


# --------------------------------------------------------------------- CLI
@pytest.fixture
def cli_env(
    monkeypatch: pytest.MonkeyPatch, test_settings: Settings, db: dict[str, Engine]
) -> None:
    monkeypatch.setenv("NETGUARD_DB_NAME", test_settings.db_name)
    monkeypatch.setenv("NG_PW", GOOD)


def test_cli_creates_an_admin_who_can_sign_in(
    cli_env: None, make_client: Make, db: dict[str, Engine]
) -> None:
    assert cli.main(["create-user", "--username", "founder", "--password-env", "NG_PW"]) == 0
    sign_in(make_client(), "founder", GOOD)
    row = run(db["api"], "SELECT details FROM audit_logs WHERE action='user.created'")[0][0]
    assert row == {"username": "founder", "via": "cli"} and GOOD not in json.dumps(row)


def test_cli_rejects_weak_passwords_and_unknown_users(
    cli_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NG_PW", "short")
    with pytest.raises(SystemExit, match="at least 12"):
        cli.main(["create-user", "--username", "founder", "--password-env", "NG_PW"])
    monkeypatch.setenv("NG_PW", GOOD)
    with pytest.raises(SystemExit, match="no such user"):
        cli.main(["reset-password", "--username", "ghost", "--password-env", "NG_PW"])
    with pytest.raises(SystemExit, match="no such user"):
        cli.main(["unlock", "--username", "ghost"])


def test_cli_reset_and_unlock(cli_env: None, make_user: MakeUser, make_client: Make) -> None:
    make_user("ann", failed_login_count=5, locked_until=datetime.now(UTC) + timedelta(minutes=9))
    assert cli.main(["unlock", "--username", "ann"]) == 0
    assert (
        make_client()
        .post("/api/auth/login", json={"username": "ann", "password": PASSWORD})
        .status_code
        == 200
    )
    assert cli.main(["reset-password", "--username", "ann", "--password-env", "NG_PW"]) == 0
    assert (
        make_client()
        .post("/api/auth/login", json={"username": "ann", "password": GOOD})
        .status_code
        == 200
    )
