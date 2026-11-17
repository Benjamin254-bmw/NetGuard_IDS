"""Sign-in, sessions, CSRF, lockout, revocation: against the real database and the `api` role."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine

from app import security as sec
from app.api.auth import GENERIC_FAILURE
from conftest import PASSWORD, sign_in  # type: ignore[import-not-found]
from dbhelpers import needs_db, run
from netguard_common.config import Settings

pytestmark = needs_db

Make = Callable[..., TestClient]
MakeUser = Callable[..., int]
Signed = Callable[..., tuple[TestClient, dict[str, str]]]


def login(c: TestClient, username: str, password: str) -> object:
    return c.post("/api/auth/login", json={"username": username, "password": password})


def audit_actions(db: dict[str, Engine]) -> list[str]:
    return [r[0] for r in run(db["api"], "SELECT action FROM audit_logs ORDER BY id")]


# ------------------------------------------------------------------------------ sign-in
def test_login_sets_hardened_cookies_and_me_works(client: TestClient, make_user: MakeUser) -> None:
    make_user("ann")
    r = login(client, "ann", PASSWORD)
    assert r.status_code == 200 and r.json()["user"]["username"] == "ann"  # type: ignore[attr-defined]
    assert "password" not in r.text  # type: ignore[attr-defined]
    cookies = [h for h in r.headers.get_list("set-cookie")]  # type: ignore[attr-defined]
    session = next(c for c in cookies if c.startswith(sec.SESSION_COOKIE + "="))
    csrf = next(c for c in cookies if c.startswith(sec.CSRF_COOKIE + "="))
    assert "HttpOnly" in session and "SameSite=strict" in session and "Path=/api" in session
    assert "HttpOnly" not in csrf and "SameSite=strict" in csrf and "Path=/" in csrf
    assert client.get("/api/auth/me").json()["user"]["role"] == "analyst"


def test_username_is_case_insensitive(client: TestClient, make_user: MakeUser) -> None:
    make_user("Ann")
    assert login(client, "aNN", PASSWORD).status_code == 200  # type: ignore[attr-defined]


def test_every_failure_looks_identical(
    client: TestClient, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    make_user("ann")
    make_user("off", is_active=False)
    make_user("locked", locked_until=datetime.now(UTC) + timedelta(minutes=5))
    cases = [("nobody", PASSWORD), ("ann", "wrong password!"), ("off", PASSWORD),
             ("locked", PASSWORD)]  # fmt: skip
    seen = {(r.status_code, r.text) for r in (login(client, u, p) for u, p in cases)}  # type: ignore[attr-defined]
    assert seen == {(401, json.dumps({"detail": GENERIC_FAILURE}, separators=(",", ":")))}
    assert sec.SESSION_COOKIE not in client.cookies


def test_oversized_or_malformed_input_is_rejected_before_hashing(client: TestClient) -> None:
    for body in ({"username": "a", "password": "x" * 257}, {"username": "a"},
                 {"username": "a", "password": "b", "extra": 1}, "nope"):  # fmt: skip
        assert client.post("/api/auth/login", json=body).status_code == 422


def test_login_requires_json(client: TestClient, make_user: MakeUser) -> None:
    make_user("ann")
    r = client.post("/api/auth/login", data={"username": "ann", "password": PASSWORD})
    assert r.status_code == 422  # a cross-site HTML form cannot sign anyone in


# ------------------------------------------------------------------------------ lockout
def test_five_failures_lock_the_account_even_for_the_right_password(
    client: TestClient, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    uid = make_user("ann")
    for _ in range(5):
        assert login(client, "ann", "wrong password!").status_code == 401  # type: ignore[attr-defined]
    row = run(db["api"], "SELECT failed_login_count, locked_until FROM users WHERE id=:i", i=uid)[0]
    assert row[0] == 5 and row[1] is not None
    assert login(client, "ann", PASSWORD).status_code == 401  # type: ignore[attr-defined]
    acts = audit_actions(db)
    assert acts.count("auth.login_failed") == 5
    assert acts.count("auth.account_locked") == 1 and acts.count("auth.login_blocked") == 1


def test_attempts_while_locked_do_not_extend_the_lock(
    client: TestClient, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    uid = make_user("ann")
    for _ in range(5):
        login(client, "ann", "wrong password!")
    before = run(db["api"], "SELECT locked_until FROM users WHERE id=:i", i=uid)[0][0]
    for _ in range(3):
        login(client, "ann", "wrong password!")
    assert run(db["api"], "SELECT locked_until FROM users WHERE id=:i", i=uid)[0][0] == before


def test_lock_expires_and_success_resets_the_counter(
    client: TestClient, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    uid = make_user("ann")
    for _ in range(5):
        login(client, "ann", "wrong password!")
    run(db["api"], "UPDATE users SET locked_until = now() - interval '1 second' WHERE id=:i", i=uid)
    assert login(client, "ann", PASSWORD).status_code == 200  # type: ignore[attr-defined]
    row = run(
        db["api"],
        "SELECT failed_login_count, locked_until, last_login_at FROM users WHERE id=:i",
        i=uid,
    )[0]
    assert row[0] == 0 and row[1] is None and row[2] is not None


def test_failures_below_the_limit_are_forgotten_on_success(
    client: TestClient, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    uid = make_user("ann")
    for _ in range(4):
        login(client, "ann", "wrong password!")
    assert login(client, "ann", PASSWORD).status_code == 200  # type: ignore[attr-defined]
    assert run(db["api"], "SELECT failed_login_count FROM users WHERE id=:i", i=uid)[0][0] == 0


def test_one_address_trying_many_usernames_is_throttled(client: TestClient) -> None:
    for i in range(20):
        assert login(client, f"ghost{i}", "wrong password!").status_code == 401  # type: ignore[attr-defined]
    r = login(client, "ghost-again", "wrong password!")
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0  # type: ignore[attr-defined]


# ------------------------------------------------------------------------------ sessions
def test_no_cookie_bad_cookie_and_expired_cookie_are_401(
    client: TestClient, make_user: MakeUser, api_settings: Settings
) -> None:
    uid = make_user("ann")
    assert client.get("/api/auth/me").status_code == 401
    client.cookies.set(sec.SESSION_COOKIE, "garbage", path="/api")
    assert client.get("/api/auth/me").status_code == 401
    old = datetime.now(UTC) - timedelta(hours=2)
    token, _ = sec.issue_token(api_settings, uid, 1, old)
    client.cookies.set(sec.SESSION_COOKIE, token, path="/api")
    assert client.get("/api/auth/me").status_code == 401


def test_token_signed_with_another_key_is_401(
    client: TestClient, make_user: MakeUser, api_settings: Settings
) -> None:
    uid = make_user("ann")
    other = api_settings.model_copy(update={"secret_key": SecretStr("x" * 40)})
    token, _ = sec.issue_token(other, uid, 1, datetime.now(UTC))
    client.cookies.set(sec.SESSION_COOKIE, token, path="/api")
    assert client.get("/api/auth/me").status_code == 401


def test_token_of_a_deleted_or_deactivated_user_stops_working(
    signed_in: Signed, db: dict[str, Engine]
) -> None:
    c, _ = signed_in("ann")
    assert c.get("/api/auth/me").status_code == 200
    run(db["api"], "UPDATE users SET is_active = false WHERE username='ann'")
    assert c.get("/api/auth/me").status_code == 401


def test_logout_all_revokes_every_session(make_client: Make, make_user: MakeUser) -> None:
    make_user("ann")
    a, b = make_client(), make_client()
    csrf_a = sign_in(a, "ann")
    sign_in(b, "ann")
    assert a.post("/api/auth/logout-all", headers=csrf_a).status_code == 204
    assert a.get("/api/auth/me").status_code == 401 and b.get("/api/auth/me").status_code == 401


def test_logout_clears_cookies_and_is_audited(signed_in: Signed, db: dict[str, Engine]) -> None:
    c, csrf = signed_in("ann")
    r = c.post("/api/auth/logout", headers=csrf)
    assert r.status_code == 204
    assert c.get("/api/auth/me").status_code == 401
    assert "auth.logout" in audit_actions(db)


def test_sliding_renewal_keeps_csrf_value(
    client: TestClient, make_user: MakeUser, api_settings: Settings
) -> None:
    uid = make_user("ann")
    token, claims = sec.issue_token(api_settings, uid, 1, datetime.now(UTC) - timedelta(minutes=20))
    client.cookies.set(sec.SESSION_COOKIE, token, path="/api")
    r = client.get("/api/auth/me")
    renewed = [h for h in r.headers.get_list("set-cookie") if h.startswith(sec.SESSION_COOKIE)]
    assert r.status_code == 200 and len(renewed) == 1
    new = sec.decode_token(api_settings, renewed[0].split("=", 1)[1].split(";")[0])
    assert new.csrf == claims.csrf and new.issued_at > claims.issued_at


def test_fresh_token_is_not_reissued_on_every_request(signed_in: Signed) -> None:
    c, _ = signed_in("ann")
    r = c.get("/api/auth/me")
    assert not [h for h in r.headers.get_list("set-cookie") if h.startswith(sec.SESSION_COOKIE)]


# ------------------------------------------------------------------------------ CSRF / origin
def test_unsafe_requests_need_the_csrf_header(signed_in: Signed) -> None:
    c, csrf = signed_in("ann")
    assert c.post("/api/auth/logout").status_code == 403
    assert c.post("/api/auth/logout", headers={sec.CSRF_HEADER: "wrong"}).status_code == 403
    assert c.post("/api/auth/logout", headers=csrf).status_code == 204


def test_csrf_value_from_another_session_is_rejected(
    make_client: Make, make_user: MakeUser
) -> None:
    make_user("ann")
    make_user("bob")
    a, b = make_client(), make_client()
    sign_in(a, "ann")
    csrf_b = sign_in(b, "bob")
    # bob's token is valid for bob's session only: ann's cookies + bob's header must fail
    assert a.post("/api/auth/logout", headers=csrf_b).status_code == 403


def test_foreign_origin_is_rejected_allowed_origin_accepted(signed_in: Signed) -> None:
    c, csrf = signed_in("ann")
    evil = {**csrf, "Origin": "https://evil.example"}
    assert c.post("/api/auth/logout", headers=evil).status_code == 403
    good = {**csrf, "Origin": "http://127.0.0.1:5173"}
    assert c.post("/api/auth/logout", headers=good).status_code == 204


def test_safe_requests_do_not_need_csrf(signed_in: Signed) -> None:
    c, _ = signed_in("ann")
    assert c.get("/api/auth/me").status_code == 200


# ------------------------------------------------------------------------------ passwords
def test_change_password_revokes_other_sessions_keeps_this_one(
    make_client: Make, make_user: MakeUser
) -> None:
    make_user("ann")
    a, other = make_client(), make_client()
    csrf = sign_in(a, "ann")
    sign_in(other, "ann")
    new = "a brand new passphrase"
    r = a.post("/api/auth/change-password", headers=csrf,
               json={"current_password": PASSWORD, "new_password": new})  # fmt: skip
    assert r.status_code == 200
    assert a.get("/api/auth/me").status_code == 200  # this session got a fresh token
    assert other.get("/api/auth/me").status_code == 401
    fresh = make_client()
    assert login(fresh, "ann", PASSWORD).status_code == 401  # type: ignore[attr-defined]
    assert login(fresh, "ann", new).status_code == 200  # type: ignore[attr-defined]


def test_change_password_rejects_wrong_current_and_weak_new(
    signed_in: Signed, db: dict[str, Engine]
) -> None:
    c, csrf = signed_in("ann")
    bad = c.post("/api/auth/change-password", headers=csrf,
                 json={"current_password": "not it", "new_password": "another fine passphrase"})  # fmt: skip
    assert bad.status_code == 400
    weak = c.post("/api/auth/change-password", headers=csrf,
                  json={"current_password": PASSWORD, "new_password": "short"})  # fmt: skip
    assert weak.status_code == 422
    assert run(db["api"], "SELECT failed_login_count FROM users WHERE username='ann'")[0][0] == 1


def test_change_password_guesses_are_throttled_like_sign_in(signed_in: Signed) -> None:
    c, csrf = signed_in("ann")
    for _ in range(5):
        c.post("/api/auth/change-password", headers=csrf,
               json={"current_password": "nope", "new_password": "another fine passphrase"})  # fmt: skip
    r = c.post("/api/auth/change-password", headers=csrf,
               json={"current_password": PASSWORD, "new_password": "another fine passphrase"})  # fmt: skip
    assert r.status_code == 429


def test_no_secret_ever_reaches_the_audit_log(
    client: TestClient, make_user: MakeUser, db: dict[str, Engine]
) -> None:
    make_user("ann")
    login(client, "ann", "hunter2-wrong-guess")
    csrf = sign_in(client, "ann")
    client.post("/api/auth/change-password", headers=csrf,
                json={"current_password": PASSWORD, "new_password": "the-new-secret-phrase"})  # fmt: skip
    dump = json.dumps(
        run(db["api"], "SELECT action, details, target_id FROM audit_logs"), default=str
    )
    for secret in (
        "hunter2-wrong-guess",
        PASSWORD,
        "the-new-secret-phrase",
        "argon2",
        sec.SESSION_COOKIE,
    ):
        assert secret not in dump


# ------------------------------------------------------------------------------ hardening
def test_security_headers_on_every_response(client: TestClient) -> None:
    for path in ("/api/health", "/api/auth/me"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff" and h["cache-control"] == "no-store"
        assert (
            h["x-frame-options"] == "DENY" and "default-src 'none'" in h["content-security-policy"]
        )


def test_production_has_no_docs_and_secure_cookies(
    make_client: Make, make_user: MakeUser, api_settings: Settings
) -> None:
    prod = api_settings.model_copy(update={"env": "production"})
    c = make_client(prod)
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
    make_user("ann")
    r = login(c, "ann", PASSWORD)
    cookies = r.headers.get_list("set-cookie")  # type: ignore[attr-defined]
    assert cookies and all("Secure" in h for h in cookies)


def test_development_keeps_docs_and_plain_cookies(client: TestClient, make_user: MakeUser) -> None:
    assert client.get("/docs").status_code == 200
    make_user("ann")
    cookies = login(client, "ann", PASSWORD).headers.get_list("set-cookie")  # type: ignore[attr-defined]
    assert cookies and not any("Secure" in h for h in cookies)


def test_a_request_without_database_is_a_clean_503() -> None:
    from app.main import create_app

    c = TestClient(create_app(Settings(secret_key="s" * 40, env="test"), db_check=lambda: False))  # type: ignore[arg-type]
    c.cookies.set(sec.SESSION_COOKIE, "x", path="/api")
    assert c.get("/api/auth/me").status_code == 401  # rejected before any database access
    assert c.post("/api/auth/login", json={"username": "a", "password": "b"}).status_code == 503


@pytest.mark.parametrize("path", ["/api/auth/me", "/api/users"])
def test_protected_routes_reject_anonymous(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 401
