import json

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import DBAPIError, IntegrityError

from dbhelpers import EventMaker, RuleMaker, constraint_of, denied, needs_db, run

pytestmark = needs_db

HIST = "SELECT version, enabled, severity, threshold, window_seconds, cooldown_seconds, params, changed_by FROM detection_rule_versions WHERE rule_id = :r ORDER BY version"


def mk_user(db: dict[str, Engine]) -> int:
    return int(
        run(
            db["api"],
            "INSERT INTO users (username, password_hash) VALUES ('alice', 'x') RETURNING id",
        )[0][0]
    )


def test_insert_creates_version_1_snapshot(db: dict[str, Engine], make_rule: RuleMaker) -> None:
    rid = make_rule(threshold=15, window_seconds=10, params={"scope": "tcp"})
    rows = run(db["migrator"], HIST, r=rid)
    assert len(rows) == 1
    v, enabled, sev, thr, win, cd, params, by = rows[0]
    assert (v, enabled, sev, thr, win, cd, params, by) == (
        1,
        True,
        "high",
        15,
        10,
        60,
        {"scope": "tcp"},
        None,
    )


def test_config_change_by_api_bumps_version_and_snapshots(
    db: dict[str, Engine], make_rule: RuleMaker
) -> None:
    rid, uid = make_rule(), mk_user(db)
    before = run(db["migrator"], "SELECT updated_at FROM detection_rules WHERE id=:r", r=rid)[0][0]
    run(
        db["api"],
        "UPDATE detection_rules SET threshold = 25, updated_by = :u WHERE id = :r",
        u=uid,
        r=rid,
    )
    run(
        db["api"],
        "UPDATE detection_rules SET severity = 'critical', window_seconds = 5, updated_by = :u WHERE id = :r",
        u=uid,
        r=rid,
    )
    hist = run(db["migrator"], HIST, r=rid)
    assert [h[0] for h in hist] == [1, 2, 3]
    assert hist[0][3] == 15 and hist[0][2] == "high"  # v1 preserved untouched
    assert hist[1][3] == 25 and hist[1][2] == "high" and hist[1][7] == uid
    assert hist[2][2] == "critical" and hist[2][4] == 5 and hist[2][3] == 25
    cur = run(db["migrator"], "SELECT version, updated_at FROM detection_rules WHERE id=:r", r=rid)[
        0
    ]
    assert cur[0] == 3 and cur[1] > before


def test_non_config_updates_and_no_op_updates_do_not_bump(
    db: dict[str, Engine], make_rule: RuleMaker
) -> None:
    rid = make_rule()
    run(db["monitor"], "UPDATE detection_rules SET description = 'new text' WHERE id = :r", r=rid)
    run(db["api"], "UPDATE detection_rules SET threshold = 15 WHERE id = :r", r=rid)  # same value
    assert run(db["migrator"], "SELECT version FROM detection_rules WHERE id=:r", r=rid)[0][0] == 1
    assert len(run(db["migrator"], HIST, r=rid)) == 1


def test_enable_toggle_and_params_are_versioned(
    db: dict[str, Engine], make_rule: RuleMaker
) -> None:
    rid = make_rule()
    run(db["api"], "UPDATE detection_rules SET enabled = false WHERE id = :r", r=rid)
    run(
        db["api"],
        "UPDATE detection_rules SET params = CAST(:p AS jsonb) WHERE id = :r",
        r=rid,
        p=json.dumps({"a": 1}),
    )
    hist = run(db["migrator"], HIST, r=rid)
    assert [(h[0], h[1], h[6]) for h in hist] == [
        (1, True, {}),
        (2, False, {}),
        (3, False, {"a": 1}),
    ]


def test_rule_key_is_immutable(db: dict[str, Engine], make_rule: RuleMaker) -> None:
    rid = make_rule()
    with pytest.raises(DBAPIError, match="immutable"):
        run(db["migrator"], "UPDATE detection_rules SET key = 'other_key' WHERE id = :r", r=rid)


def test_history_cannot_be_written_or_spoofed_by_runtime_roles(
    db: dict[str, Engine], make_rule: RuleMaker
) -> None:
    rid = make_rule()
    for role in ("api", "monitor"):
        assert denied(
            db[role],
            "INSERT INTO detection_rule_versions (rule_id,version,enabled,severity,threshold,window_seconds,cooldown_seconds,params) VALUES (:r,9,true,'low',1,1,1,CAST('{}' AS jsonb))",
            r=rid,
        )
        assert denied(
            db[role], "UPDATE detection_rule_versions SET threshold = 1 WHERE rule_id = :r", r=rid
        )
        assert denied(db[role], "DELETE FROM detection_rule_versions WHERE rule_id = :r", r=rid)
    assert denied(db["api"], "UPDATE detection_rules SET version = 50 WHERE id = :r", r=rid)


def test_event_keeps_the_rule_version_that_produced_it(
    db: dict[str, Engine], make_rule: RuleMaker, make_event: EventMaker
) -> None:
    rid = make_rule(threshold=15)
    ev = make_event(rid, rule_version=1)
    run(db["api"], "UPDATE detection_rules SET threshold = 40 WHERE id = :r", r=rid)
    run(db["api"], "UPDATE detection_rules SET threshold = 80 WHERE id = :r", r=rid)
    row = run(
        db["migrator"],
        """
        SELECT v.threshold, r.threshold, r.version FROM security_events e
        JOIN detection_rule_versions v ON v.rule_id = e.rule_id AND v.version = e.rule_version
        JOIN detection_rules r ON r.id = e.rule_id WHERE e.id = :e""",
        e=ev,
    )[0]
    assert tuple(row) == (15, 80, 3)  # the event still points at the config that fired it


def test_rule_with_events_cannot_be_deleted(
    db: dict[str, Engine], make_rule: RuleMaker, make_event: EventMaker
) -> None:
    rid = make_rule()
    make_event(rid)
    with pytest.raises(IntegrityError) as ei:
        run(db["migrator"], "DELETE FROM detection_rules WHERE id = :r", r=rid)
    assert constraint_of(ei.value) in {
        "fk_detection_rule_versions_rule_id_detection_rules",
        "fk_security_events_rule_version",
    }
