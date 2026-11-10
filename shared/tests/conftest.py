"""Fixtures for database integration tests. Run against '<NETGUARD_DB_NAME>_test' only
(created by scripts/db_init.sh); the development database is never touched."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from dbhelpers import ALL_TABLES, T0, EventMaker, RuleMaker, run
from sqlalchemy import Engine, text

from netguard_common.config import Settings, load_settings
from netguard_common.db import make_engine

ROOT = Path(__file__).resolve().parents[2]
@pytest.fixture(scope="session")
def test_settings() -> Settings:
    s = load_settings()
    return s.model_copy(update={"db_name": f"{s.db_name}_test"})


@pytest.fixture(scope="session")
def engines(test_settings: Settings) -> Iterator[dict[str, Engine]]:
    es = {r: make_engine(test_settings, r, pool_size=2) for r in ("migrator", "monitor", "api")}  # type: ignore[arg-type]
    yield es
    for e in es.values():
        e.dispose()


@pytest.fixture(scope="session")
def alembic_cfg(engines: dict[str, Engine]) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.attributes["engine"] = engines["migrator"]
    return cfg


@pytest.fixture(scope="session")
def migrated(alembic_cfg: Config) -> Config:
    command.downgrade(alembic_cfg, "base")
    command.upgrade(alembic_cfg, "head")
    return alembic_cfg


@pytest.fixture
def db(engines: dict[str, Engine], migrated: Config) -> dict[str, Engine]:
    """Engines per role, with every table emptied before the test."""
    with engines["migrator"].begin() as c:
        c.execute(text(f"TRUNCATE {ALL_TABLES} RESTART IDENTITY CASCADE"))
    return engines


@pytest.fixture
def make_rule(db: dict[str, Engine]) -> RuleMaker:
    def _make(**o: Any) -> int:
        v: dict[str, Any] = {
            "key": "port_scan", "name": "Port scan", "category": "port_scan",
            "description": "d", "severity": "high", "threshold": 15, "window_seconds": 10,
            "cooldown_seconds": 60, "params": {},
        } | o
        v["params"] = json.dumps(v["params"])
        return int(run(db["monitor"], """
            INSERT INTO detection_rules (key, name, category, description, severity, threshold,
                                         window_seconds, cooldown_seconds, params)
            VALUES (:key, :name, :category, :description, :severity, :threshold,
                    :window_seconds, :cooldown_seconds, CAST(:params AS jsonb)) RETURNING id""", **v)[0][0])
    return _make


@pytest.fixture
def make_event(db: dict[str, Engine], make_rule: RuleMaker) -> EventMaker:
    def _make(rule_id: int | None = None, **o: Any) -> int:
        rid = rule_id or make_rule()
        v: dict[str, Any] = {
            "category": "port_scan", "rule_id": rid, "rule_version": 1, "severity": "high",
            "src_ip": "10.10.10.30", "description": "scan", "dedup_key": "port_scan|10.10.10.30",
            "detected_at": T0, "last_seen_at": T0,
        } | o
        return int(run(db["monitor"], """
            INSERT INTO security_events (category, rule_id, rule_version, severity, src_ip, description,
                                         dedup_key, detected_at, last_seen_at)
            VALUES (:category, :rule_id, :rule_version, :severity, CAST(:src_ip AS inet), :description,
                    :dedup_key, :detected_at, :last_seen_at) RETURNING id""", **v)[0][0])
    return _make
