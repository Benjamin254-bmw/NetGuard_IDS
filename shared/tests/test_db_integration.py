"""Needs a live database prepared with scripts/db_init.sh: NETGUARD_TEST_INTEGRATION=1 pytest"""

import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from netguard_common.config import load_settings
from netguard_common.db import check_connection, make_engine

pytestmark = pytest.mark.skipif(
    os.environ.get("NETGUARD_TEST_INTEGRATION") != "1", reason="integration test"
)


def test_each_role_connects_with_utc_and_no_collation_mismatch() -> None:
    s = load_settings()
    for role in ("migrator", "monitor", "api"):
        info = check_connection(make_engine(s, role, pool_size=1))  # type: ignore[arg-type]
        assert info["timezone"] == "UTC"
        assert info["collation_mismatch"] is False
        if info["server_version_num"] >= 170000:
            assert info["locale_provider"] == "b"  # builtin: immune to glibc version drift


def test_monitor_and_api_cannot_create_tables_but_migrator_can() -> None:
    s = load_settings()
    for role in ("monitor", "api"):
        with make_engine(s, role, pool_size=1).connect() as conn:  # type: ignore[arg-type]
            with pytest.raises(ProgrammingError):
                conn.execute(text("CREATE TABLE ng_probe (id int)"))
    with make_engine(s, "migrator", pool_size=1).connect() as conn:
        conn.execute(text("CREATE TABLE ng_probe (id int)"))
        conn.rollback()  # never persisted
