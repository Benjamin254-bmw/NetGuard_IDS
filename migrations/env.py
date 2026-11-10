"""Alembic environment. Connects as the migrator role (owner of all objects)."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Engine

from netguard_common.config import load_settings
from netguard_common.db import make_engine
from netguard_common.models import Base

config = context.config
target_metadata = Base.metadata


def _engine() -> Engine:
    supplied = config.attributes.get("engine")  # tests may inject an engine
    if supplied is not None:
        return supplied  # type: ignore[no-any-return]
    return make_engine(load_settings(), "migrator", pool_size=1)


def run_migrations_online() -> None:
    engine = _engine()
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise SystemExit("Offline mode is not supported: migrations apply grants for live roles.")
run_migrations_online()
