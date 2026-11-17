"""Authentication primitives: password hashing, session tokens, CSRF, login throttling.

Everything here is a pure function of its inputs (time is passed in), so each branch is unit-tested
without a database. The HTTP layer lives in app/api/.

Design (docs/adr/0016-api-auth.md):
  * Passwords: Argon2id (argon2-cffi defaults). No default accounts: the first admin is created by
    the CLI. Unknown users cost the same CPU as known ones (dummy hash) so response time does not
    reveal which usernames exist.
  * Session: a signed JWT (HS256, algorithm pinned, exp/iat/sub required) in an HttpOnly cookie.
    The token carries only the user id, a session version and a CSRF value. Role and active flag
    are read from the database on every request, so deactivation or demotion takes effect at once,
    and bumping users.session_version revokes every token issued before it.
  * CSRF: double submit. State-changing requests must send X-CSRF-Token equal to the readable csrf
    cookie AND to the csrf claim inside the signed token.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from netguard_common.config import Settings

SESSION_COOKIE = "ng_session"
CSRF_COOKIE = "ng_csrf"
CSRF_HEADER = "X-CSRF-Token"
ALGORITHM = "HS256"

MAX_FAILURES = 5  # consecutive failed logins before a temporary lock
LOCK_SECONDS = 900  # 15 minutes
PASSWORD_MIN = 12
PASSWORD_MAX = 128  # bounds hashing cost for oversized input

_hasher = PasswordHasher()  # Argon2id
_dummy_hash: str | None = None


# ------------------------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return _hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(encoded: str) -> bool:
    return _hasher.check_needs_rehash(encoded)


def burn_password_check(password: str) -> None:
    """Spend the same time as a real verification (used when the username does not exist)."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(16))
    verify_password(_dummy_hash, password)


def password_problem(password: str, username: str) -> str | None:
    """Why a new password is unacceptable (None = acceptable). Length-based, per NIST 800-63B."""
    if len(password) < PASSWORD_MIN:
        return f"must be at least {PASSWORD_MIN} characters"
    if len(password) > PASSWORD_MAX:
        return f"must be at most {PASSWORD_MAX} characters"
    if len(set(password)) < 5:
        return "is too repetitive"
    if username.lower() in password.lower():
        return "must not contain the username"
    return None


# ----------------------------------------------------------------------------------- throttling
def is_locked(locked_until: datetime | None, now: datetime) -> bool:
    return locked_until is not None and now < locked_until


def after_failed_login(
    failed_count: int, locked_until: datetime | None, now: datetime
) -> tuple[int, datetime | None]:
    """New (failed_count, locked_until) after one more wrong password.

    A lock that has expired starts a fresh set of attempts; reaching MAX_FAILURES locks the account.
    """
    if locked_until is not None and now >= locked_until:
        failed_count, locked_until = 0, None
    failed_count += 1
    if failed_count >= MAX_FAILURES:
        return failed_count, now + timedelta(seconds=LOCK_SECONDS)
    return failed_count, locked_until


# ------------------------------------------------------------------------------------- sessions
class InvalidToken(Exception):
    """The session token is missing, malformed, expired, or signed with another key."""


@dataclass(frozen=True)
class Claims:
    user_id: int
    session_version: int
    csrf: str
    issued_at: datetime
    expires_at: datetime


def _key(settings: Settings) -> str:
    if settings.secret_key is None:
        raise RuntimeError("NETGUARD_SECRET_KEY is not set; run 'make init-env'")
    return settings.secret_key.get_secret_value()


def issue_token(
    settings: Settings, user_id: int, session_version: int, now: datetime, csrf: str | None = None
) -> tuple[str, Claims]:
    claims = Claims(
        user_id=user_id,
        session_version=session_version,
        csrf=csrf or secrets.token_urlsafe(32),
        issued_at=now.replace(microsecond=0),
        expires_at=now.replace(microsecond=0) + timedelta(minutes=settings.session_ttl_minutes),
    )
    token = jwt.encode(
        {
            "sub": str(claims.user_id),
            "sv": claims.session_version,
            "csrf": claims.csrf,
            "iat": int(claims.issued_at.timestamp()),
            "exp": int(claims.expires_at.timestamp()),
        },
        _key(settings),
        algorithm=ALGORITHM,
    )
    return token, claims


def decode_token(settings: Settings, token: str, now: datetime | None = None) -> Claims:
    try:
        data = jwt.decode(
            token,
            _key(settings),
            algorithms=[ALGORITHM],  # pinned: never trust the header's alg
            options={"require": ["exp", "iat", "sub"], "verify_exp": False},
        )
        expires = datetime.fromtimestamp(int(data["exp"]), UTC)
        if (now or datetime.now(UTC)) >= expires:
            raise InvalidToken("expired")
        return Claims(
            user_id=int(data["sub"]),
            session_version=int(data["sv"]),
            csrf=str(data["csrf"]),
            issued_at=datetime.fromtimestamp(int(data["iat"]), UTC),
            expires_at=expires,
        )
    except InvalidToken:
        raise
    except (jwt.PyJWTError, KeyError, ValueError, TypeError) as exc:
        raise InvalidToken(type(exc).__name__) from exc


def should_renew(claims: Claims, now: datetime) -> bool:
    """Sliding session: re-issue once more than half the lifetime has passed."""
    return (now - claims.issued_at) > (claims.expires_at - claims.issued_at) / 2


def csrf_ok(claims: Claims, cookie_value: str | None, header_value: str | None) -> bool:
    """Header, cookie and signed claim must all be the same non-empty value."""
    if not cookie_value or not header_value:
        return False
    return hmac.compare_digest(header_value, cookie_value) and hmac.compare_digest(
        header_value, claims.csrf
    )
