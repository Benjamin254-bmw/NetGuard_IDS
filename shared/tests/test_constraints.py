"""Every negative test asserts WHICH constraint fired, so it cannot pass for the wrong reason."""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from dbhelpers import T0, EventMaker, RuleMaker, constraint_of, needs_db, run
from netguard_common.enums import DetectionCategory, Protocol, Severity
from netguard_common.models import DetectionRule, SecurityEvent

pytestmark = needs_db


def violates(constraint: str, fn: Any, *args: Any, **kw: Any) -> None:
    with pytest.raises(IntegrityError) as ei:
        fn(*args, **kw)
    assert constraint_of(ei.value) == constraint


def bad_text(fn: Any, *args: Any, **kw: Any) -> None:
    with pytest.raises(DataError):
        fn(*args, **kw)


DEV = (
    "INSERT INTO devices (ip, mac, status, discovery_source, first_seen, last_seen) "
    "VALUES (CAST(:ip AS inet), CAST(:mac AS macaddr), 'active', 'passive_arp', :a, :b)"
)


def test_device_address_and_time_constraints(db: dict[str, Engine]) -> None:
    m = db["migrator"]
    violates("ck_devices_ip_v4_host", run, m, DEV, ip="fd00::1", mac=None, a=T0, b=T0)
    violates("ck_devices_ip_v4_host", run, m, DEV, ip="10.10.10.0/24", mac=None, a=T0, b=T0)
    violates(
        "ck_devices_seen_order",
        run,
        m,
        DEV,
        ip="10.10.10.5",
        mac=None,
        a="2026-01-02T00:00:00+00:00",
        b=T0,
    )
    bad_text(run, m, DEV, ip="10.10.10.999", mac=None, a=T0, b=T0)


def test_device_mac_unique_but_null_macs_repeat(db: dict[str, Engine]) -> None:
    m = db["migrator"]
    run(m, DEV, ip="10.10.10.5", mac="aa:bb:cc:dd:ee:01", a=T0, b=T0)
    violates("uq_devices_mac", run, m, DEV, ip="10.10.10.6", mac="aa:bb:cc:dd:ee:01", a=T0, b=T0)
    run(m, DEV, ip="10.10.10.7", mac=None, a=T0, b=T0)
    run(m, DEV, ip="10.10.10.8", mac=None, a=T0, b=T0)


@pytest.mark.parametrize(
    ("override", "constraint"),
    [
        ({"threshold": 0}, "ck_detection_rules_threshold_positive"),
        ({"window_seconds": 0}, "ck_detection_rules_window_range"),
        ({"window_seconds": 86401}, "ck_detection_rules_window_range"),
        ({"cooldown_seconds": -1}, "ck_detection_rules_cooldown_range"),
        ({"severity": "urgent"}, "ck_detection_rules_severity"),
        ({"category": "nonsense"}, "ck_detection_rules_category"),
        ({"key": "Bad Key"}, "ck_detection_rules_key_format"),
    ],
)
def test_rule_value_constraints(
    db: dict[str, Engine], make_rule: RuleMaker, override: dict[str, Any], constraint: str
) -> None:
    violates(constraint, make_rule, **override)


def test_rule_params_must_be_a_json_object(db: dict[str, Engine]) -> None:
    violates(
        "ck_detection_rules_params_object",
        run,
        db["migrator"],
        "INSERT INTO detection_rules (key,name,category,description,severity,threshold,window_seconds,params) "
        "VALUES ('k_arr','n','port_scan','d','low',1,1,CAST('[]' AS jsonb))",
    )


@pytest.mark.parametrize(
    ("override", "constraint"),
    [
        ({"severity": "urgent"}, "ck_security_events_severity"),
        ({"category": "nonsense"}, "ck_security_events_category"),
        ({"last_seen_at": "2025-12-31T00:00:00+00:00"}, "ck_security_events_seen_order"),
        ({"rule_version": 99}, "fk_security_events_rule_version"),
    ],
)
def test_event_constraints(
    db: dict[str, Engine],
    make_rule: RuleMaker,
    make_event: EventMaker,
    override: dict[str, Any],
    constraint: str,
) -> None:
    rid = make_rule()  # one rule, so nothing fails because of a duplicate rule
    violates(constraint, make_event, rid, **override)


def test_event_rejects_malformed_ip(
    db: dict[str, Engine], make_rule: RuleMaker, make_event: EventMaker
) -> None:
    bad_text(make_event, make_rule(), src_ip="not-an-ip")


def test_open_dedup_key_unique_until_closed(
    db: dict[str, Engine], make_rule: RuleMaker, make_event: EventMaker
) -> None:
    rid = make_rule()
    first = make_event(rid)
    violates("uq_security_events_open_dedup", make_event, rid)  # same open window, same key
    make_event(rid, dedup_key="port_scan|10.10.10.99")  # different key is fine
    run(db["monitor"], "UPDATE security_events SET is_open = false WHERE id = :i", i=first)
    assert make_event(rid) != first  # window closed: a new event may open


def test_event_uuid_replay_is_idempotent(db: dict[str, Engine], make_rule: RuleMaker) -> None:
    rid, u = make_rule(), str(uuid.uuid4())
    sql = (
        "INSERT INTO security_events (event_uuid,category,rule_id,rule_version,severity,src_ip,description,"
        "dedup_key,detected_at,last_seen_at) VALUES (CAST(:u AS uuid),'port_scan',:r,1,'high',"
        "CAST('10.10.10.30' AS inet),'x',:k,:t,:t) ON CONFLICT (event_uuid) DO NOTHING"
    )
    run(db["monitor"], sql, u=u, r=rid, k="k1", t=T0)
    run(db["monitor"], sql, u=u, r=rid, k="k2", t=T0)  # replayed spill record
    assert run(db["migrator"], "SELECT count(*) FROM security_events")[0][0] == 1


def test_severity_rank_orders_severities(
    db: dict[str, Engine], make_rule: RuleMaker, make_event: EventMaker
) -> None:
    rid = make_rule()
    for i, sev in enumerate(("critical", "informational", "high", "low", "medium")):
        make_event(rid, severity=sev, dedup_key=f"k{i}")
    rows = run(db["migrator"], "SELECT severity FROM security_events ORDER BY severity_rank DESC")
    assert [r[0] for r in rows] == ["critical", "high", "medium", "low", "informational"]


def test_alert_requires_ack_timestamp(db: dict[str, Engine], make_event: EventMaker) -> None:
    ev = make_event()
    violates(
        "ck_alerts_ack_timestamp",
        run,
        db["migrator"],
        "INSERT INTO alerts (event_id, severity, title, status) VALUES (:e,'high','t','acknowledged')",
        e=ev,
    )
    run(
        db["migrator"],
        "INSERT INTO alerts (event_id, severity, title) VALUES (:e,'high','t')",
        e=ev,
    )


def test_monitor_status_is_a_singleton(db: dict[str, Engine]) -> None:
    violates(
        "ck_monitor_status_singleton",
        run,
        db["migrator"],
        "INSERT INTO monitor_status (id, state) VALUES (2, 'running')",
    )
    run(db["migrator"], "INSERT INTO monitor_status (id, state) VALUES (1, 'running')")
    violates(
        "pk_monitor_status",
        run,
        db["migrator"],
        "INSERT INTO monitor_status (id, state) VALUES (1, 'running')",
    )


def test_audit_traffic_and_aggregate_constraints(db: dict[str, Engine]) -> None:
    m = db["migrator"]
    violates(
        "ck_audit_logs_action_format",
        run,
        m,
        "INSERT INTO audit_logs (actor_type, action) VALUES ('system', 'BadAction')",
    )
    violates(
        "ck_traffic_stats_1s_non_negative",
        run,
        m,
        "INSERT INTO traffic_stats_1s (bucket_start, protocol, packets, bytes) VALUES (:t,'tcp',-1,0)",
        t=T0,
    )
    agg = (
        "INSERT INTO connection_aggregates_1m (bucket_start,src_ip,dst_ip,dst_port,transport,packets,bytes) "
        "VALUES (:t,'10.10.10.30','10.10.10.10',:p,'tcp',1,1)"
    )
    violates(
        "ck_connection_aggregates_1m_minute_aligned",
        run,
        m,
        agg,
        t="2026-01-01T00:00:30+00:00",
        p=80,
    )
    violates("ck_connection_aggregates_1m_port_range", run, m, agg, t=T0, p=70000)
    run(m, agg, t=T0, p=80)


def test_user_name_rules(db: dict[str, Engine]) -> None:
    m = db["migrator"]
    ins = "INSERT INTO users (username, password_hash) VALUES (:u, 'x')"
    run(m, ins, u="Admin")
    violates("uq_users_username_lower", run, m, ins, u="admin")  # case-insensitive
    violates("ck_users_username_format", run, m, ins, u="a b")


def test_orm_models_round_trip_against_the_real_schema(db: dict[str, Engine]) -> None:
    t = datetime(2026, 1, 1, tzinfo=UTC)
    with Session(db["migrator"]) as s:
        rule = DetectionRule(
            key="port_scan",
            name="Port scan",
            category=DetectionCategory.PORT_SCAN,
            description="d",
            severity=Severity.HIGH,
            threshold=15,
            window_seconds=10,
        )
        s.add(rule)
        s.flush()
        ev = SecurityEvent(
            category=DetectionCategory.PORT_SCAN,
            rule_id=rule.id,
            rule_version=1,
            severity=Severity.HIGH,
            src_ip="10.10.10.30",
            protocol=Protocol.TCP,
            description="scan",
            evidence={"distinct_ports": 20},
            dedup_key="k",
            detected_at=t,
            last_seen_at=t,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)
        assert ev.severity is Severity.HIGH and ev.severity_rank == 3 and ev.hit_count == 1
        assert str(ev.src_ip).split("/")[0] == "10.10.10.30"
        assert ev.evidence == {"distinct_ports": 20} and ev.is_open is True
