"""Least-privilege checks: the live database must match netguard_common.grants, and the
behaviours that matter (who may change what) are asserted independently of that table."""

import pytest
from sqlalchemy import Engine

from dbhelpers import EventMaker, RuleMaker, denied, needs_db, run
from netguard_common.config import Settings
from netguard_common.grants import GRANTS

pytestmark = needs_db
TABLE_PRIVS = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def role_name(s: Settings, key: str) -> str:
    return s.db_monitor_user if key == "monitor" else s.db_api_user


def test_live_privileges_match_the_matrix_exactly(
    db: dict[str, Engine], test_settings: Settings
) -> None:
    m = db["migrator"]
    tables = [
        r[0]
        for r in run(
            m,
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name <> 'alembic_version'",
        )
    ]
    assert sorted(tables) == sorted(GRANTS), "every table needs an explicit entry in GRANTS"
    for table in tables:
        cols = [
            r[0]
            for r in run(
                m,
                "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=:t",
                t=table,
            )
        ]
        for key in ("monitor", "api"):
            role = role_name(test_settings, key)
            granted = GRANTS[table].get(key, ())
            table_level = {p for p in granted if "(" not in p}
            col_level = {
                p.split("(")[0]: set(p.split("(")[1].rstrip(")").split(","))
                for p in granted
                if "(" in p
            }
            for priv in TABLE_PRIVS:
                has = run(m, "SELECT has_table_privilege(:r, :t, :p)", r=role, t=table, p=priv)[0][
                    0
                ]
                assert has == (priv in table_level), f"{role} {priv} on {table}"
            for col in cols:
                has = run(
                    m, "SELECT has_column_privilege(:r, :t, :c, 'UPDATE')", r=role, t=table, c=col
                )[0][0]
                expected = "UPDATE" in table_level or col in col_level.get("UPDATE", set())
                assert has == expected, f"{role} UPDATE({col}) on {table}"


def test_public_has_no_access_to_any_table(db: dict[str, Engine]) -> None:
    rows = run(
        db["migrator"],
        "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'PUBLIC' AND table_schema = 'public'",
    )
    assert rows[0][0] == 0


def test_monitor_can_record_but_not_triage(db: dict[str, Engine], make_event: EventMaker) -> None:
    ev = make_event()  # monitor INSERT works
    run(
        db["monitor"],
        "UPDATE security_events SET hit_count = hit_count + 1, last_seen_at = now() WHERE id = :e",
        e=ev,
    )
    assert denied(
        db["monitor"], "UPDATE security_events SET status = 'resolved' WHERE id = :e", e=ev
    )
    assert denied(
        db["monitor"], "UPDATE security_events SET src_ip = '1.2.3.4' WHERE id = :e", e=ev
    )
    assert denied(db["monitor"], "DELETE FROM security_events WHERE id = :e", e=ev)
    assert denied(db["monitor"], "SELECT * FROM users")
    assert denied(db["monitor"], "UPDATE detection_rules SET threshold = 1")


def test_api_can_triage_but_not_forge_or_erase_detections(
    db: dict[str, Engine], make_event: EventMaker
) -> None:
    ev = make_event()
    run(
        db["api"],
        "UPDATE security_events SET status = 'investigating', status_updated_at = now() WHERE id = :e",
        e=ev,
    )
    assert (
        run(db["api"], "SELECT status FROM security_events WHERE id = :e", e=ev)[0][0]
        == "investigating"
    )
    assert denied(db["api"], "UPDATE security_events SET severity = 'low' WHERE id = :e", e=ev)
    assert denied(db["api"], "UPDATE security_events SET hit_count = 1 WHERE id = :e", e=ev)
    assert denied(db["api"], "DELETE FROM security_events WHERE id = :e", e=ev)
    assert denied(
        db["api"],
        "INSERT INTO security_events (category,rule_id,rule_version,severity,src_ip,description,dedup_key,detected_at,last_seen_at) VALUES ('port_scan',1,1,'low','1.2.3.4','x','k',now(),now())",
    )
    assert denied(
        db["api"],
        "INSERT INTO devices (ip, discovery_source, first_seen, last_seen) VALUES ('1.2.3.4','traffic',now(),now())",
    )
    assert denied(
        db["api"],
        "INSERT INTO connection_aggregates_1m (bucket_start,src_ip,dst_ip,dst_port,transport,packets,bytes) VALUES (date_trunc('minute', now()),'1.1.1.1','2.2.2.2',1,'tcp',1,1)",
    )


def test_api_edits_rule_config_but_not_identity(
    db: dict[str, Engine], make_rule: RuleMaker
) -> None:
    rid = make_rule()
    run(
        db["api"], "UPDATE detection_rules SET threshold = 30, enabled = false WHERE id = :r", r=rid
    )
    assert denied(db["api"], "UPDATE detection_rules SET name = 'x' WHERE id = :r", r=rid)
    assert denied(db["api"], "UPDATE detection_rules SET key = 'x' WHERE id = :r", r=rid)
    assert denied(db["api"], "DELETE FROM detection_rules WHERE id = :r", r=rid)
    assert denied(
        db["api"],
        "INSERT INTO detection_rules (key,name,category,description,severity,threshold,window_seconds) VALUES ('new_rule','n','port_scan','d','low',1,1)",
    )
    run(db["monitor"], "UPDATE detection_rules SET description = 'from code' WHERE id = :r", r=rid)
    assert denied(db["monitor"], "UPDATE detection_rules SET threshold = 1 WHERE id = :r", r=rid)


@pytest.mark.parametrize("role", ["api", "monitor"])
def test_audit_log_is_append_only(db: dict[str, Engine], role: str) -> None:
    run(db[role], "INSERT INTO audit_logs (actor_type, action) VALUES ('system', 'test.event')")
    assert denied(db[role], "UPDATE audit_logs SET action = 'tampered.event'")
    assert denied(db[role], "DELETE FROM audit_logs")
    assert denied(db[role], "TRUNCATE audit_logs")


def test_runtime_roles_cannot_change_schema(db: dict[str, Engine]) -> None:
    for role in ("api", "monitor"):
        assert denied(db[role], "CREATE TABLE sneaky (id int)")
        assert denied(db[role], "ALTER TABLE devices ADD COLUMN x int")
        assert denied(db[role], "DROP TABLE devices")
        assert denied(db[role], "DROP TRIGGER trg_detection_rules_update ON detection_rules")
