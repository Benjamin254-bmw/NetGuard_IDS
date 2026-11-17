"""Unit tests for app.security (no database)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app import security as S
from netguard_common.config import Settings

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
KEY = "k" * 40


@pytest.fixture
def settings(clean_env: None) -> Settings:
    return Settings(secret_key=KEY, session_ttl_minutes=30)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- passwords
def test_password_roundtrip_uses_argon2id() -> None:
    h = S.hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert S.verify_password(h, "correct horse battery")
    assert not S.verify_password(h, "correct horse batterY")
    assert not S.needs_rehash(h)


def test_garbage_hash_is_a_failed_verification_not_an_exception() -> None:
    assert S.verify_password("not-a-hash", "x") is False
    assert S.verify_password("", "x") is False


def test_each_hash_is_salted() -> None:
    assert S.hash_password("same password 123") != S.hash_password("same password 123")


def test_unknown_user_path_does_real_hashing_work(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = S.verify_password

    def spy(encoded: str, password: str) -> bool:
        calls.append(encoded)
        return real(encoded, password)

    monkeypatch.setattr(S, "verify_password", spy)
    S.burn_password_check("whatever")
    S.burn_password_check("whatever")
    assert len(calls) == 2 and calls[0].startswith("$argon2id$") and calls[0] == calls[1]


@pytest.mark.parametrize(
    ("password", "username", "problem"),
    [
        ("short", "bob", "at least 12"),
        ("x" * 129, "bob", "at most 128"),
        ("aaaaaaaaaaaaaaaa", "bob", "repetitive"),
        ("my-BOB-secret-9", "bob", "username"),
        ("correct horse battery", "bob", None),
        ("a1b2c3d4e5f6", "bob", None),
    ],
)
def test_password_policy(password: str, username: str, problem: str | None) -> None:
    got = S.password_problem(password, username)
    assert (got is None) if problem is None else (got is not None and problem in got)


def test_password_length_limits_are_exact() -> None:
    assert S.password_problem("abcdefghijk1", "u") is None  # 12
    assert S.password_problem("abcdefghijk", "u") is not None  # 11
    assert S.password_problem(("abcde" * 30)[:128], "u") is None
    assert S.password_problem(("abcde" * 30)[:129], "u") is not None


# --------------------------------------------------------------------------- throttling
def test_lock_after_five_consecutive_failures() -> None:
    count, until = 0, None
    for i in range(1, 5):
        count, until = S.after_failed_login(count, until, NOW)
        assert (count, until) == (i, None)
    count, until = S.after_failed_login(count, until, NOW)
    assert count == 5 and until == NOW + timedelta(seconds=S.LOCK_SECONDS)


def test_expired_lock_gives_a_fresh_set_of_attempts() -> None:
    locked_until = NOW - timedelta(seconds=1)
    assert S.after_failed_login(5, locked_until, NOW) == (1, None)


def test_lock_boundary_is_exclusive() -> None:
    until = NOW
    assert S.is_locked(until, NOW - timedelta(microseconds=1)) is True
    assert S.is_locked(until, NOW) is False  # the instant it expires, the user may try
    assert S.is_locked(None, NOW) is False


# --------------------------------------------------------------------------- tokens
def test_token_roundtrip(settings: Settings) -> None:
    token, issued = S.issue_token(settings, 7, 3, NOW)
    got = S.decode_token(settings, token, NOW + timedelta(minutes=1))
    assert (got.user_id, got.session_version, got.csrf) == (7, 3, issued.csrf)
    assert got.expires_at - got.issued_at == timedelta(minutes=30)


def test_expiry_boundary(settings: Settings) -> None:
    token, claims = S.issue_token(settings, 1, 1, NOW)
    S.decode_token(settings, token, claims.expires_at - timedelta(seconds=1))
    with pytest.raises(S.InvalidToken):
        S.decode_token(settings, token, claims.expires_at)


def test_tampered_or_foreign_tokens_are_rejected(settings: Settings) -> None:
    token, _ = S.issue_token(settings, 1, 1, NOW)
    head, body, sig = token.split(".")
    bad = ".".join([head, body, sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")])
    for t in ("", "garbage", token + "x", bad):
        with pytest.raises(S.InvalidToken):
            S.decode_token(settings, t, NOW)
    other = Settings(secret_key="z" * 40)  # type: ignore[arg-type]
    with pytest.raises(S.InvalidToken):
        S.decode_token(other, token, NOW)


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_algorithm_is_pinned(settings: Settings) -> None:
    payload = {
        "sub": "1",
        "sv": 1,
        "csrf": "c",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    unsigned = jwt.encode(payload, None, algorithm="none")
    hs512 = jwt.encode(payload, KEY, algorithm="HS512")
    for t in (unsigned, hs512):
        with pytest.raises(S.InvalidToken):
            S.decode_token(settings, t, NOW)


@pytest.mark.parametrize("drop", ["sub", "exp", "iat", "sv", "csrf"])
def test_missing_claims_are_rejected(settings: Settings, drop: str) -> None:
    payload = {
        "sub": "1",
        "sv": 1,
        "csrf": "c",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    del payload[drop]
    with pytest.raises(S.InvalidToken):
        S.decode_token(settings, jwt.encode(payload, KEY, algorithm="HS256"), NOW)


def test_non_numeric_subject_is_rejected(settings: Settings) -> None:
    payload = {
        "sub": "admin",
        "sv": 1,
        "csrf": "c",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }
    with pytest.raises(S.InvalidToken):
        S.decode_token(settings, jwt.encode(payload, KEY, algorithm="HS256"), NOW)


def test_missing_secret_is_a_configuration_error(clean_env: None) -> None:
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        S.issue_token(Settings(), 1, 1, NOW)


def test_sliding_renewal_threshold(settings: Settings) -> None:
    _, claims = S.issue_token(settings, 1, 1, NOW)
    assert not S.should_renew(claims, NOW + timedelta(minutes=15))  # exactly half
    assert S.should_renew(claims, NOW + timedelta(minutes=15, seconds=1))


def test_renewed_token_keeps_the_csrf_value(settings: Settings) -> None:
    _, first = S.issue_token(settings, 1, 1, NOW)
    _, second = S.issue_token(settings, 1, 1, NOW + timedelta(minutes=20), csrf=first.csrf)
    assert second.csrf == first.csrf and second.issued_at > first.issued_at


@pytest.mark.parametrize(
    ("cookie", "header", "ok"),
    [
        ("c", "c", True),
        ("c", "d", False),
        (None, "c", False),
        ("c", None, False),
        ("", "", False),
        ("d", "d", False),
    ],  # last: cookie and header agree but not the signed claim
)
def test_csrf_double_submit(
    settings: Settings, cookie: str | None, header: str | None, ok: bool
) -> None:
    _, claims = S.issue_token(settings, 1, 1, NOW, csrf="c")
    assert S.csrf_ok(claims, cookie, header) is ok


def test_settings_reject_short_secret(clean_env: None) -> None:
    with pytest.raises(ValueError, match="at least 32"):
        Settings(secret_key="short")  # type: ignore[arg-type]


def test_repetitiveness_boundary_is_four_versus_five_distinct_characters() -> None:
    assert S.password_problem("abcdabcdabcdabcd", "u") is not None  # 4 distinct characters
    assert S.password_problem("abcdeabcdeabcde", "u") is None  # 5 distinct characters


def test_a_lock_that_expires_this_very_instant_starts_a_fresh_set() -> None:
    assert S.after_failed_login(5, NOW, NOW) == (1, None)
    assert (
        S.after_failed_login(5, NOW + timedelta(seconds=1), NOW)[0] == 6
    )  # still locked: keeps counting
