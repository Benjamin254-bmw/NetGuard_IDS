"""Fixtures for API integration tests: real PostgreSQL, the real `api` database role."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine

from app import security as sec
from app.main import create_app
from dbhelpers import run
from netguard_common.config import Settings

PASSWORD = "correct horse battery"


@pytest.fixture
def cheap_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Argon2 with minimal cost so tests that create many users stay fast (same algorithm)."""
    monkeypatch.setattr(sec, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))
    monkeypatch.setattr(sec, "_dummy_hash", None)


@pytest.fixture
def api_settings(test_settings: Settings) -> Settings:
    return test_settings.model_copy(
        update={"secret_key": SecretStr("s" * 40), "env": "test", "session_ttl_minutes": 30}
    )


@pytest.fixture
def make_client(
    db: dict[str, Engine], api_settings: Settings, cheap_hashing: None
) -> Iterator[Callable[..., TestClient]]:
    made: list[TestClient] = []

    def _make(settings: Settings | None = None, **kw: Any) -> TestClient:
        c = TestClient(create_app(settings or api_settings, engine=db["api"]), **kw)
        made.append(c)
        return c

    yield _make
    for c in made:
        c.close()


@pytest.fixture
def client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client()


@pytest.fixture
def make_user(db: dict[str, Engine], cheap_hashing: None) -> Callable[..., int]:
    def _make(username: str, role: str = "analyst", password: str = PASSWORD, **cols: Any) -> int:
        values: dict[str, Any] = {"is_active": True} | cols
        names = ["username", "password_hash", "role", *values]
        marks = ", ".join(f":{n}" for n in names)
        return int(
            run(
                db["api"],
                f"INSERT INTO users ({', '.join(names)}) VALUES ({marks}) RETURNING id",  # noqa: S608
                username=username,
                password_hash=sec.hash_password(password),
                role=role,
                **values,
            )[0][0]
        )

    return _make


def sign_in(c: TestClient, username: str, password: str = PASSWORD) -> dict[str, str]:
    """Log in and return the CSRF header the dashboard would send."""
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {sec.CSRF_HEADER: c.cookies[sec.CSRF_COOKIE]}


@pytest.fixture
def signed_in(
    make_client: Callable[..., TestClient], make_user: Callable[..., int]
) -> Callable[..., tuple[TestClient, dict[str, str]]]:
    """A fresh client signed in as a new user: signed_in('ann', 'admin') -> (client, csrf headers)."""

    def _make(username: str, role: str = "analyst") -> tuple[TestClient, dict[str, str]]:
        make_user(username, role)
        c = make_client()
        return c, sign_in(c, username)

    return _make
