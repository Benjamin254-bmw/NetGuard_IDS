"""Database engine construction and connectivity diagnostics."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine, text

from netguard_common.config import Role, Settings

_DIAG_SQL = text(
    """
    SELECT current_setting('server_version') AS server_version,
           current_setting('server_version_num')::int AS server_version_num,
           current_user AS role,
           current_database() AS database,
           current_setting('TimeZone') AS timezone,
           d.datlocprovider AS locale_provider,
           d.datcollate AS collate,
           (d.datcollversion IS NOT NULL
            AND d.datcollversion IS DISTINCT FROM
                pg_database_collation_actual_version(d.oid)) AS collation_mismatch
    FROM pg_database d WHERE d.datname = current_database()
    """
)


def make_engine(settings: Settings, role: Role, *, pool_size: int = 5) -> Engine:
    return create_engine(
        settings.db_url(role),
        pool_size=pool_size,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5},
    )


def check_connection(engine: Engine) -> dict[str, Any]:
    """Return facts about the live connection; raises if the database is unreachable."""
    with engine.connect() as conn:
        row = conn.execute(_DIAG_SQL).mappings().one()
    return dict(row)
