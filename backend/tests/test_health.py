import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from netguard_common.config import Settings

pytestmark = pytest.mark.usefixtures("clean_env")


def client(db_ok: bool) -> TestClient:
    return TestClient(create_app(Settings(_env_file=None), db_check=lambda: db_ok))  # type: ignore[call-arg]


def test_liveness() -> None:
    r = client(False).get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_ready_when_db_up() -> None:
    r = client(True).get("/api/health/ready")
    assert r.status_code == 200 and r.json() == {"status": "ok", "database": "ok"}


def test_ready_degraded_without_leaking_details() -> None:
    r = client(False).get("/api/health/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "degraded", "database": "unavailable"}
