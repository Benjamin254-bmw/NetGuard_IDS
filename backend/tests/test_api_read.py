"""Read and write endpoints for monitoring data, against the real database and the real api role."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine

from dbhelpers import EventMaker, RuleMaker, needs_db, run

pytestmark = needs_db

Signed = Callable[..., tuple]  # type: ignore[type-arg]


def add_alert(db: dict[str, Engine], event_id: int, title: str = "Port scan") -> int:
    return int(
        run(
            db["monitor"],
            "INSERT INTO alerts (event_id, severity, title) VALUES (:e, 'high', :t) RETURNING id",
            e=event_id,
            t=title,
        )[0][0]
    )


def test_monitor_status_states(signed_in: Signed, db: dict[str, Engine]) -> None:
    c, _ = signed_in("ann")
    assert c.get("/api/monitor/status").json()["effective_state"] == "never_started"
    run(
        db["monitor"],
        "INSERT INTO monitor_status (id, state, heartbeat_at) VALUES (1, 'running', now())",
    )
    body = c.get("/api/monitor/status").json()
    assert body["effective_state"] == "running"
    run(
        db["monitor"],
        "UPDATE monitor_status SET heartbeat_at = now() - interval '2 minutes'",
    )
    body = c.get("/api/monitor/status").json()
    assert body["state"] == "running"
    assert body["effective_state"] == "stale"  # a silent monitor is not reported as healthy


def test_overview_counts(signed_in: Signed, db: dict[str, Engine], make_event: EventMaker) -> None:
    c, _ = signed_in("ann")
    ev = make_event(severity="high", detected_at=datetime.now(UTC), last_seen_at=datetime.now(UTC))
    add_alert(db, ev)
    body = c.get("/api/overview").json()
    assert body["open_events_by_severity"] == {"high": 1}
    assert body["alerts"] == {"new": 1, "total": 1}
    assert body["events_24h_by_category"] == {"port_scan": 1}


def test_events_filters_and_keyset_pagination(
    signed_in: Signed, make_event: EventMaker, make_rule: RuleMaker
) -> None:
    c, _ = signed_in("ann")
    rule = make_rule()
    ids = [
        make_event(
            rule, src_ip=f"10.10.10.{i}", dedup_key=f"k{i}", severity="low" if i % 2 else "high"
        )
        for i in range(1, 8)
    ]
    first = c.get("/api/events", params={"limit": 3}).json()
    assert [e["id"] for e in first["items"]] == ids[::-1][:3]
    assert first["next_before_id"] == first["items"][-1]["id"]
    second = c.get("/api/events", params={"limit": 3, "before_id": first["next_before_id"]}).json()
    assert [e["id"] for e in second["items"]] == ids[::-1][3:6]
    last = c.get("/api/events", params={"limit": 3, "before_id": second["next_before_id"]}).json()
    assert [e["id"] for e in last["items"]] == [ids[0]]
    assert last["next_before_id"] is None
    # backfill: everything newer than a known id, no gaps
    newer = c.get("/api/events", params={"after_id": ids[3]}).json()
    assert sorted(e["id"] for e in newer["items"]) == ids[4:]
    only_low = c.get("/api/events", params={"severity": "low"}).json()["items"]
    assert only_low and all(e["severity"] == "low" for e in only_low)
    one = c.get("/api/events", params={"src_ip": "10.10.10.3"}).json()["items"]
    assert [e["src_ip"] for e in one] == ["10.10.10.3"]


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"severity": "bogus"},
        {"src_ip": "not-an-ip"},
        {"src_ip": "::1"},
        {"before_id": 0},
        {"before_id": 5, "after_id": 1},
        {"category": "x'; DROP TABLE users;--"},
    ],
)
def test_events_reject_bad_filters(signed_in: Signed, params: dict[str, object]) -> None:
    c, _ = signed_in("ann")
    assert c.get("/api/events", params=params).status_code == 422


def test_event_detail_has_alerts_and_rule_snapshot(
    signed_in: Signed, db: dict[str, Engine], make_event: EventMaker, make_rule: RuleMaker
) -> None:
    c, _ = signed_in("ann")
    rule = make_rule(threshold=15)
    ev = make_event(rule, rule_version=1)
    add_alert(db, ev)
    run(db["migrator"], "UPDATE detection_rules SET threshold = 99 WHERE id = :i", i=rule)
    body = c.get(f"/api/events/{ev}").json()
    assert body["rule_snapshot"]["threshold"] == 15  # as it was when the event fired
    assert len(body["alerts"]) == 1
    assert c.get("/api/events/99999").status_code == 404


def test_event_status_change_is_audited_and_validated(
    signed_in: Signed, db: dict[str, Engine], make_event: EventMaker
) -> None:
    c, csrf = signed_in("ann", "analyst")
    ev = make_event()
    assert c.patch(f"/api/events/{ev}", json={"status": "resolved"}).status_code == 403  # no CSRF
    assert c.patch(f"/api/events/{ev}", headers=csrf, json={"status": "bogus"}).status_code == 422
    r = c.patch(f"/api/events/{ev}", headers=csrf, json={"status": "investigating"})
    assert r.status_code == 200 and r.json()["status"] == "investigating"
    assert r.json()["status_updated_by"] is not None
    rows = run(db["api"], "SELECT details FROM audit_logs WHERE action = 'event.status_change'")
    assert rows[0][0] == {"from": "new", "to": "investigating"}
    assert (
        c.patch("/api/events/99999", headers=csrf, json={"status": "resolved"}).status_code == 404
    )


def test_alert_acknowledge_dismiss_and_reopen(
    signed_in: Signed, db: dict[str, Engine], make_event: EventMaker
) -> None:
    c, csrf = signed_in("ann")
    alert = add_alert(db, make_event())
    r = c.patch(f"/api/alerts/{alert}", headers=csrf, json={"status": "acknowledged"})
    assert r.status_code == 200
    assert r.json()["acknowledged_by"] is not None and r.json()["acknowledged_at"]
    r = c.patch(f"/api/alerts/{alert}", headers=csrf, json={"status": "new"})
    assert r.status_code == 200 and r.json()["acknowledged_at"] is None
    assert c.get("/api/alerts", params={"status": "new"}).json()["items"][0]["id"] == alert
    assert c.get("/api/alerts", params={"status": "dismissed"}).json()["items"] == []
    assert (
        c.patch("/api/alerts/99999", headers=csrf, json={"status": "dismissed"}).status_code == 404
    )


def test_devices_and_filter(signed_in: Signed, db: dict[str, Engine]) -> None:
    c, _ = signed_in("ann")
    for ip, mac, status in (
        ("10.10.10.5", "aa:bb:cc:00:00:05", "active"),
        ("10.10.10.6", None, "inactive"),
    ):
        run(
            db["monitor"],
            "INSERT INTO devices (ip, mac, status, discovery_source, first_seen, last_seen) "
            "VALUES (CAST(:ip AS inet), CAST(:mac AS macaddr), :s, "
            "'traffic', now(), now())",
            ip=ip,
            mac=mac,
            s=status,
        )
    body = c.get("/api/devices").json()
    assert body["total"] == 2
    assert {d["ip"] for d in body["items"]} == {"10.10.10.5", "10.10.10.6"}
    assert [
        d["ip"] for d in c.get("/api/devices", params={"status": "inactive"}).json()["items"]
    ] == ["10.10.10.6"]
    assert c.get("/api/devices", params={"status": "x"}).status_code == 422


def seed_traffic(db: dict[str, Engine]) -> datetime:
    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=5)
    for i in range(10):
        run(
            db["monitor"],
            "INSERT INTO traffic_stats_1s (bucket_start, protocol, packets, bytes, new_connections) "
            "VALUES (:t, :p, :n, :b, 1)",
            t=base + timedelta(seconds=i),
            p="tcp" if i % 2 else "udp",
            n=10,
            b=1000,
        )
    run(
        db["monitor"],
        "INSERT INTO connection_aggregates_1m (bucket_start, src_ip, dst_ip, dst_port, transport, "
        "packets, bytes, syn_count) VALUES (:t, '10.10.10.5', '10.10.10.9', 443, 'tcp', 50, 9000, 1), "
        "(:t, '10.10.10.6', '10.10.10.9', 80, 'tcp', 500, 900, 1)",
        t=base.replace(second=0),
    )
    return base


def test_traffic_series_protocols_and_top_talkers(signed_in: Signed, db: dict[str, Engine]) -> None:
    c, _ = signed_in("ann")
    base = seed_traffic(db)
    window = {
        "from": (base - timedelta(seconds=5)).isoformat(),
        "to": (base + timedelta(seconds=30)).isoformat(),
    }
    raw = c.get("/api/traffic/series", params={**window, "bucket": 1}).json()
    assert len(raw["points"]) == 10 and all(p["packets"] == 10 for p in raw["points"])
    coarse = c.get("/api/traffic/series", params={**window, "bucket": 60}).json()
    assert sum(p["packets"] for p in coarse["points"]) == 100  # totals preserved by bucketing
    protos = {
        p["protocol"]: p["packets"]
        for p in c.get("/api/traffic/protocols", params=window).json()["items"]
    }
    assert protos == {"tcp": 50, "udp": 50}
    window = {
        "from": (base - timedelta(minutes=2)).isoformat(),
        "to": (base + timedelta(minutes=2)).isoformat(),
    }  # the aggregates are per-minute, so their bucket may start before the per-second window
    by_bytes = c.get("/api/traffic/top-talkers", params={**window, "by": "bytes"}).json()["items"]
    by_packets = c.get("/api/traffic/top-talkers", params={**window, "by": "packets"}).json()[
        "items"
    ]
    assert by_bytes[0]["ip"] == "10.10.10.5" and by_packets[0]["ip"] == "10.10.10.6"
    dst = c.get("/api/traffic/top-talkers", params={**window, "direction": "dst"}).json()["items"]
    assert [d["ip"] for d in dst] == ["10.10.10.9"]


@pytest.mark.parametrize("direction", ["src", "dst"])
@pytest.mark.parametrize("by", ["bytes", "packets"])
def test_top_talkers_matches_the_straightforward_query(
    signed_in: Signed, db: dict[str, Engine], direction: str, by: str
) -> None:
    """Flow counts and totals must equal count(DISTINCT ...) over the raw rows, across several minutes."""
    c, _ = signed_in("ann")
    t0 = (datetime.now(UTC) - timedelta(minutes=10)).replace(second=0, microsecond=0)
    rows = [  # (minute offset, src, dst, port, transport, packets, bytes)
        (0, "10.10.10.5", "10.10.10.9", 443, "tcp", 10, 1000),
        (1, "10.10.10.5", "10.10.10.9", 443, "tcp", 20, 2000),  # same flow again: still ONE flow
        (0, "10.10.10.5", "10.10.10.9", 80, "tcp", 5, 300),
        (1, "10.10.10.5", "10.10.10.8", 443, "udp", 7, 700),
        (1, "10.10.10.5", "10.10.10.9", 443, "udp", 3, 30),  # same address and port, other transport
        (0, "10.10.10.6", "10.10.10.9", 443, "tcp", 90, 50),
        (1, "10.10.10.6", "10.10.10.7", 53, "udp", 1, 99),
    ]
    for m, src, dst, port, tr, pk, by_ in rows:
        run(
            db["monitor"],
            "INSERT INTO connection_aggregates_1m (bucket_start, src_ip, dst_ip, dst_port, transport, "
            "packets, bytes, syn_count) VALUES (:t, :s, :d, :p, :tr, :pk, :b, 0)",
            t=t0 + timedelta(minutes=m), s=src, d=dst, p=port, tr=tr, pk=pk, b=by_,
        )  # fmt: skip
    window = {"from": (t0 - timedelta(minutes=1)).isoformat(), "to": (t0 + timedelta(minutes=5)).isoformat()}
    got = c.get(
        "/api/traffic/top-talkers", params={**window, "by": by, "direction": direction, "limit": 10}
    ).json()["items"]
    key = "src_ip" if direction == "src" else "dst_ip"
    want = run(
        db["migrator"],
        f"SELECT host({key}) AS ip, CAST(sum(bytes) AS bigint), CAST(sum(packets) AS bigint), "  # noqa: S608
        "count(DISTINCT (dst_ip, dst_port, transport)) FROM connection_aggregates_1m "
        "WHERE bucket_start >= :s AND bucket_start < :e "
        f"GROUP BY 1 ORDER BY {'sum(bytes)' if by == 'bytes' else 'sum(packets)'} DESC, 1",
        s=t0 - timedelta(minutes=1), e=t0 + timedelta(minutes=5),
    )  # fmt: skip
    assert [(g["ip"], g["bytes"], g["packets"], g["flows"]) for g in got] == [tuple(w) for w in want]
    if direction == "src":  # spot-check the values themselves, not only the agreement
        top = next(g for g in got if g["ip"] == "10.10.10.5")
        assert (top["bytes"], top["packets"], top["flows"]) == (4030, 45, 4)


@pytest.mark.parametrize(
    "params",
    [
        {"bucket": 7},
        {
            "bucket": 1,
            "from": "2026-01-01T00:00:00Z",
            "to": "2026-01-01T23:00:00Z",
        },  # too many points
        {"from": "2026-01-02T00:00:00Z", "to": "2026-01-01T00:00:00Z"},
        {"from": "2026-01-01T00:00:00Z", "to": "2026-03-01T00:00:00Z", "bucket": 300},  # > 24 h
    ],
)
def test_series_bounds(signed_in: Signed, params: dict[str, object]) -> None:
    c, _ = signed_in("ann")
    assert c.get("/api/traffic/series", params=params).status_code == 422


def test_top_talkers_rejects_unknown_ordering(signed_in: Signed) -> None:
    c, _ = signed_in("ann")
    assert (
        c.get("/api/traffic/top-talkers", params={"by": "bytes; DROP TABLE x"}).status_code == 422
    )
    assert c.get("/api/traffic/top-talkers", params={"limit": 51}).status_code == 422


def test_rules_list_detail_and_versions(signed_in: Signed, make_rule: RuleMaker) -> None:
    c, _ = signed_in("ann")
    rid = make_rule(params={"min_ports": 10, "ignore": ["10.10.10.1"], "label": "x", "flag": True})
    assert [r["id"] for r in c.get("/api/rules").json()["items"]] == [rid]
    detail = c.get(f"/api/rules/{rid}").json()
    assert detail["versions"][0]["version"] == 1
    assert c.get("/api/rules/99999").status_code == 404


def test_rule_patch_admin_only_versions_and_audits(
    signed_in: Signed, db: dict[str, Engine], make_rule: RuleMaker
) -> None:
    rid = make_rule(params={"min_ports": 10})
    analyst, a_csrf = signed_in("ann", "analyst")
    assert (
        analyst.patch(f"/api/rules/{rid}", headers=a_csrf, json={"threshold": 5}).status_code == 403
    )
    admin, csrf = signed_in("root", "admin")
    r = admin.patch(
        f"/api/rules/{rid}", headers=csrf, json={"threshold": 5, "params": {"min_ports": 12}}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["threshold"] == 5 and body["params"] == {"min_ports": 12}
    assert body["version"] == 2 and body["updated_by"] is not None
    versions = admin.get(f"/api/rules/{rid}").json()["versions"]
    assert [v["threshold"] for v in versions] == [5, 15]  # history keeps the old settings
    details = run(db["api"], "SELECT details FROM audit_logs WHERE action = 'rule.update'")[0][0]
    assert details["before"]["threshold"] == 15 and details["after"]["threshold"] == 5
    # an identical patch is a no-op: no new version, no audit row
    again = admin.patch(f"/api/rules/{rid}", headers=csrf, json={"threshold": 5}).json()
    assert again["version"] == 2
    assert run(db["api"], "SELECT count(*) FROM audit_logs WHERE action='rule.update'")[0][0] == 1


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"threshold": 0},
        {"threshold": -1},
        {"window_seconds": 3601},
        {"cooldown_seconds": -1},
        {"severity": "urgent"},
        {"enabled": "yes please"},
        {"name": "renamed"},
        {"params": {"unknown_key": 1}},
        {"params": {"min_ports": "ten"}},
        {"params": {"min_ports": True}},
        {"params": {"min_ports": -5}},
        {"params": {"min_ports": 10**12}},
        {"params": {"ignore": "10.10.10.1"}},
        {"params": {"ignore": [1, 2]}},
        {"params": {"ignore": ["x"] * 101}},
        {"params": {"label": "y" * 256}},
        {"params": {"min_ports": {"nested": 1}}},
    ],
)
def test_rule_patch_validation(
    signed_in: Signed, make_rule: RuleMaker, body: dict[str, object]
) -> None:
    rid = make_rule(params={"min_ports": 10, "ignore": ["10.10.10.1"], "label": "x"})
    admin, csrf = signed_in("root", "admin")
    r = admin.patch(f"/api/rules/{rid}", headers=csrf, json=body)
    assert r.status_code == 422, r.text
    assert admin.get(f"/api/rules/{rid}").json()["version"] == 1  # nothing was applied


def test_audit_log_admin_only_with_filters_and_paging(signed_in: Signed) -> None:
    analyst, _ = signed_in("ann", "analyst")
    assert analyst.get("/api/audit-logs").status_code == 403
    admin, _ = signed_in("root", "admin")
    first = admin.get("/api/audit-logs", params={"limit": 1}).json()
    assert len(first["items"]) == 1 and first["next_before_id"] is not None
    logins = admin.get("/api/audit-logs", params={"action": "auth.login"}).json()["items"]
    assert logins and all(i["action"] == "auth.login" for i in logins)
    assert admin.get("/api/audit-logs", params={"action": "BAD ACTION"}).status_code == 422


def test_system_info_shows_settings_but_no_secrets(
    signed_in: Signed, db: dict[str, Engine]
) -> None:
    c, _ = signed_in("ann")
    r = c.get("/api/system/info")
    assert r.status_code == 200
    body = r.json()
    assert body["retention_per_minute_days"] >= 1
    assert body["session_ttl_minutes"] == 30
    text_ = r.text.lower()
    for forbidden in ("secret", "password", "s" * 40):  # the test secret key is 40 x "s"
        assert forbidden not in text_
