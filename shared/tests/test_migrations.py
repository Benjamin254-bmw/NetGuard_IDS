from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text

from dbhelpers import needs_db, run

pytestmark = needs_db

EXPECTED = {
    "users",
    "devices",
    "traffic_stats_1s",
    "connection_aggregates_1m",
    "detection_rules",
    "detection_rule_versions",
    "security_events",
    "alerts",
    "settings",
    "audit_logs",
    "monitor_status",
    "ingest_batches",
    "alembic_version",
}


def tables(engine: Engine) -> set[str]:
    rows = run(
        engine, "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
    )
    return {r[0] for r in rows}


def test_head_creates_expected_tables(db: dict[str, Engine]) -> None:
    assert tables(db["migrator"]) == EXPECTED


def test_models_and_migrations_have_not_drifted(migrated: Config) -> None:
    command.check(migrated)  # raises if autogenerate would produce any operation


def test_downgrade_removes_everything_and_upgrade_restores(
    migrated: Config, db: dict[str, Engine]
) -> None:
    command.downgrade(migrated, "base")
    assert tables(db["migrator"]) == {"alembic_version"}
    fn = run(
        db["migrator"], "SELECT count(*) FROM pg_proc WHERE proname = 'detection_rules_versioning'"
    )
    assert fn[0][0] == 0
    command.upgrade(migrated, "head")
    assert tables(db["migrator"]) == EXPECTED


def test_all_timestamps_are_timestamptz(db: dict[str, Engine]) -> None:
    rows = run(
        db["migrator"],
        """
        SELECT table_name, column_name, data_type FROM information_schema.columns
        WHERE table_schema='public' AND data_type LIKE 'timestamp%' AND data_type <> 'timestamp with time zone'""",
    )
    assert rows == []


def test_address_columns_use_inet(db: dict[str, Engine]) -> None:
    rows = run(
        db["migrator"],
        text("""
        SELECT table_name||'.'||column_name FROM information_schema.columns
        WHERE table_schema='public' AND column_name IN ('ip','src_ip','dst_ip','source_ip')
          AND udt_name <> 'inet'""").text,
    )
    assert rows == []
