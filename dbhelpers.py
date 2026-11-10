"""Plain helpers for database integration tests (fixtures live in conftest.py)."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

INTEGRATION = os.environ.get("NETGUARD_TEST_INTEGRATION") == "1"
needs_db = pytest.mark.skipif(
    not INTEGRATION, reason="integration test (NETGUARD_TEST_INTEGRATION=1)"
)

ALL_TABLES = (
    "ingest_batches, alerts, security_events, detection_rule_versions, detection_rules, devices, "
    "traffic_stats_1s, connection_aggregates_1m, settings, audit_logs, monitor_status, users"
)
T0 = "2026-01-01T00:00:00+00:00"
RuleMaker = Callable[..., int]
EventMaker = Callable[..., int]


def sqlstate(exc: BaseException) -> str | None:
    return getattr(getattr(exc, "orig", None), "sqlstate", None)


def run(engine: Engine, sql: str, **params: Any) -> list[Any]:
    with engine.begin() as c:
        res = c.execute(text(sql), params)
        return list(res.all()) if res.returns_rows else []


def denied(engine: Engine, sql: str, **params: Any) -> bool:
    """True if PostgreSQL refused the statement for lack of privilege (SQLSTATE 42501)."""
    try:
        run(engine, sql, **params)
    except ProgrammingError as exc:
        return sqlstate(exc) == "42501"
    return False


def constraint_of(exc: BaseException) -> str | None:
    """Name of the constraint/index PostgreSQL reports for an integrity error."""
    return getattr(getattr(getattr(exc, "orig", None), "diag", None), "constraint_name", None)
