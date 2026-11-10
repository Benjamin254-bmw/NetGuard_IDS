"""Database tests for rule registry and event persistence: exactly-once, alerts, NOTIFY."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
import pytest
from sqlalchemy import Engine

from dbhelpers import needs_db, run
from netguard_common.config import Settings
from netguard_monitor.ids.engine import IdsEngine
from netguard_monitor.ids.registry import build_engine, load_configs, load_open_windows, sync_rules
from netguard_monitor.persistence.writer import apply_batch, new_batch

pytestmark = needs_db
KEY = "port_scan|10.10.10.30|10.10.10.10"


@contextmanager
def listener(s: Settings) -> Iterator[psycopg.Connection[Any]]:
    pw = s.db_api_password.get_secret_value() if s.db_api_password else ""
    with psycopg.connect(
        host=s.db_host,
        port=s.db_port,
        dbname=s.db_name,
        user=s.db_api_user,
        password=pw,
        autocommit=True,
    ) as conn:
        conn.execute("LISTEN ids_alerts")
        yield conn


def notifications(conn: psycopg.Connection[Any], wait: float = 1.0) -> list[str]:
    return [n.payload for n in conn.notifies(timeout=wait)]


def open_op(rule_id: int, **over: Any) -> dict[str, Any]:
    return {
        "op": "open",
        "event_uuid": "6f1d2a0e-0000-4000-8000-000000000001",
        "rule_id": rule_id,
        "rule_version": 1,
        "category": "port_scan",
        "severity": "high",
        "src_ip": "10.10.10.30",
        "dst_ip": "10.10.10.10",
        "dst_port": None,
        "protocol": "tcp",
        "title": "Port scan",
        "description": "scan",
        "evidence": {"distinct_ports": 15},
        "dedup_key": KEY,
        "detected_at": 1_800_000_000.0,
        "hits": 1,
    } | over


def hit_op(**over: Any) -> dict[str, Any]:
    return {
        "op": "hit",
        "dedup_key": KEY,
        "hits": 5,
        "last_seen": 1_800_000_003.0,
        "evidence": {"distinct_ports": 20},
        "severity": "high",
        "escalate": False,
        "title": "Port scan",
    } | over


def close_op() -> dict[str, Any]:
    return {"op": "close", "dedup_key": KEY, "closed_at": 1_800_000_100.0}


def apply(db: dict[str, Engine], ops: list[dict[str, Any]], batch: Any = None) -> bool:
    b = batch or new_batch("events", ops)
    with db["monitor"].begin() as conn:
        return apply_batch(conn, b)


def rule_id(db: dict[str, Engine]) -> int:
    sync_rules(db["monitor"])
    return next(c.rule_id for c in load_configs(db["monitor"]) if c.key == "port_scan")


def events(db: dict[str, Engine]) -> list[Any]:
    return run(
        db["migrator"],
        "SELECT severity, hit_count, is_open, dedup_key, rule_version, "
        "evidence->>'distinct_ports', host(src_ip), protocol FROM security_events ORDER BY id",
    )


def alerts(db: dict[str, Engine]) -> list[Any]:
    return run(db["migrator"], "SELECT severity, title, status FROM alerts ORDER BY id")


# ------------------------------------------------------------------ registry
def test_sync_inserts_defaults_for_every_rule_and_is_idempotent(db: dict[str, Engine]) -> None:
    sync_rules(db["monitor"])
    sync_rules(db["monitor"])
    cfgs = {c.key: c for c in load_configs(db["monitor"])}
    assert sorted(cfgs) == [
        "abnormal_traffic",
        "auth_failures",
        "excessive_connections",
        "port_scan",
        "suspicious_dns",
    ]
    assert all(c.version == 1 and c.enabled for c in cfgs.values())
    assert (cfgs["port_scan"].threshold, cfgs["port_scan"].window_seconds) == (15, 10)
    assert cfgs["suspicious_dns"].params["max_label_length"] == 52


def test_sync_never_overwrites_administrator_changes(db: dict[str, Engine]) -> None:
    sync_rules(db["monitor"])
    run(
        db["api"],
        "UPDATE detection_rules SET threshold = 40, enabled = false WHERE key = 'port_scan'",
    )
    sync_rules(db["monitor"])
    c = next(c for c in load_configs(db["monitor"]) if c.key == "port_scan")
    assert (c.threshold, c.enabled, c.version) == (40, False, 2)  # change kept and versioned
    run(db["migrator"], "UPDATE detection_rules SET name = 'stale' WHERE key = 'port_scan'")
    sync_rules(db["monitor"])
    assert (
        run(db["monitor"], "SELECT name FROM detection_rules WHERE key='port_scan'")[0][0]
        == "Port scan"
    )


# ------------------------------------------------------------------ event lifecycle
def test_open_creates_event_and_one_alert(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    assert apply(db, [open_op(rid)])
    assert events(db) == [("high", 1, True, KEY, 1, "15", "10.10.10.30", "tcp")]
    assert alerts(db) == [("high", "Port scan", "new")]


def test_hits_accumulate_and_close_ends_the_window(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    apply(db, [open_op(rid), hit_op(), hit_op(hits=2)])
    assert events(db)[0][1] == 8 and events(db)[0][5] == "20"
    assert len(alerts(db)) == 1  # plain hits never raise alerts
    apply(db, [close_op()])
    assert events(db)[0][2] is False
    apply(db, [open_op(rid, event_uuid="6f1d2a0e-0000-4000-8000-000000000002")])
    assert [e[2] for e in events(db)] == [False, True] and len(alerts(db)) == 2


def test_escalation_raises_the_severity_and_a_second_alert(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    apply(db, [open_op(rid, severity="high"), hit_op(severity="critical", escalate=True)])
    assert events(db)[0][0] == "critical"
    assert [a[0] for a in alerts(db)] == ["high", "critical"]
    assert alerts(db)[1][1].endswith("(escalated)")
    apply(db, [hit_op(severity="low")])  # severity can never go down within a window
    assert events(db)[0][0] == "critical"


def test_a_late_hit_cannot_modify_a_closed_event(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    apply(db, [open_op(rid), close_op()])
    before = (events(db), alerts(db))
    apply(db, [hit_op(severity="critical", escalate=True)])  # the window is already closed
    assert (events(db), alerts(db)) == before


def test_opening_an_already_open_key_merges_without_a_second_alert(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    apply(db, [open_op(rid)])
    apply(
        db,
        [
            open_op(
                rid, event_uuid="6f1d2a0e-0000-4000-8000-000000000009", hits=3, severity="critical"
            )
        ],
    )
    assert len(events(db)) == 1 and events(db)[0][1] == 4 and events(db)[0][0] == "critical"
    assert len(alerts(db)) == 1


def test_event_keeps_the_rule_version_that_produced_it(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    apply(db, [open_op(rid)])
    run(db["api"], "UPDATE detection_rules SET threshold = 99 WHERE key = 'port_scan'")
    apply(
        db,
        [
            close_op(),
            open_op(rid, rule_version=2, event_uuid="6f1d2a0e-0000-4000-8000-0000000000aa"),
        ],
    )
    assert [e[4] for e in events(db)] == [1, 2]
    assert run(
        db["migrator"],
        "SELECT threshold FROM detection_rule_versions WHERE rule_id=:r ORDER BY version",
        r=rid,
    ) == [(15,), (99,)]


# ------------------------------------------------------------------ exactly-once and notify
def test_replaying_a_batch_changes_nothing(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    batch = new_batch("events", [open_op(rid), hit_op()])
    assert apply(db, [], batch) is True
    before = (events(db), alerts(db))
    assert apply(db, [], batch) is False
    assert (events(db), alerts(db)) == before


def test_alert_commit_sends_notify_with_the_alert_id(
    db: dict[str, Engine], test_settings: Settings
) -> None:
    rid = rule_id(db)
    with listener(test_settings) as conn:
        apply(db, [open_op(rid)])
        got = notifications(conn)
    alert_id = run(db["migrator"], "SELECT id FROM alerts")[0][0]
    assert got == [str(alert_id)]


def test_rollback_sends_no_notification_and_no_alert(
    db: dict[str, Engine], test_settings: Settings
) -> None:
    rid = rule_id(db)
    with listener(test_settings) as conn:
        with pytest.raises(RuntimeError):
            with db["monitor"].begin() as c:
                apply_batch(c, new_batch("events", [open_op(rid)]))
                raise RuntimeError("boom")
        assert notifications(conn, wait=0.5) == []
    assert events(db) == [] and alerts(db) == []


def test_a_malformed_op_aborts_the_whole_batch(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    with pytest.raises(ValueError):
        apply(db, [open_op(rid), {"op": "explode"}])
    assert events(db) == [] and alerts(db) == []  # ledger entry rolled back too
    assert run(db["migrator"], "SELECT count(*) FROM ingest_batches")[0][0] == 0


# ------------------------------------------------------------------ restart
def test_open_events_are_restored_into_a_new_engine(db: dict[str, Engine]) -> None:
    rid = rule_id(db)
    apply(db, [open_op(rid)])
    rows = load_open_windows(db["monitor"])
    assert [(r["dedup_key"], r["rule_key"], r["severity"]) for r in rows] == [
        (KEY, "port_scan", "high")
    ]
    eng = build_engine(db["monitor"])
    assert isinstance(eng, IdsEngine) and eng.open_events == 1
    json.dumps(rows[0]["evidence"])
