"""Batched pruning of high-volume tables. Each batch is its own short transaction."""

from __future__ import annotations

from sqlalchemy import Engine, text

_TABLES = (
    ("traffic_stats_1s", "bucket_start", "hours"),
    ("connection_aggregates_1m", "bucket_start", "days"),
    ("ingest_batches", "applied_at", "ledger"),
)


def prune(
    engine: Engine,
    now_epoch: float,
    retention_1s_hours: int,
    retention_1m_days: int,
    ledger_days: int = 7,
    batch_size: int = 5000,
) -> dict[str, int]:
    """Delete rows older than their retention. Returns rows deleted per table."""
    ages = {
        "hours": retention_1s_hours * 3600,
        "days": retention_1m_days * 86400,
        "ledger": ledger_days * 86400,
    }
    deleted: dict[str, int] = {}
    for table, column, unit in _TABLES:
        sql = text(
            f"DELETE FROM {table} WHERE ctid IN ("  # noqa: S608 - names are constants above
            f"SELECT ctid FROM {table} "
            f"WHERE {column} < to_timestamp(:now) - make_interval(secs => :age) LIMIT :n)"
        )
        total = 0
        while True:
            with engine.begin() as conn:
                n = conn.execute(
                    sql, {"now": now_epoch, "age": ages[unit], "n": batch_size}
                ).rowcount
            total += n
            if n < batch_size:
                break
        deleted[table] = total
    return deleted
