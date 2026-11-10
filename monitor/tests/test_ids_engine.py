"""Engine (dedup / coalescing / escalation / cooldown / reconfiguration) and log source tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ids_helpers import ATT, VIC, T, all_cfgs, tcp

from netguard_monitor.ids.base import AuthFailure
from netguard_monitor.ids.engine import HIT_FLUSH_SECONDS, IdsEngine
from netguard_monitor.ids.logsource import LogTailer, parse_auth_line


def run_flood(
    eng: IdsEngine, n: int, start: float = T, step: float = 0.001, port: int = 9002
) -> None:
    for i in range(n):
        eng.on_packet(tcp(start + i * step, ATT, VIC, port, sport=30000 + i))


def kinds(ops: list[dict]) -> list[str]:  # type: ignore[type-arg]
    return [o["op"] for o in ops]


# ------------------------------------------------------------------ dedup and coalescing
def test_one_open_event_per_key_and_hits_are_coalesced() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 130)  # crosses 100 at the 100th SYN: 31 detections in total
    ops = eng.drain_ops()
    assert kinds(ops) == ["open"]
    op = ops[0]
    assert op["dedup_key"] == f"excessive_connections|{ATT}|{VIC}|9002" and op["hits"] == 1
    assert (
        op["rule_id"] == 2 and op["rule_version"] == 1 and op["category"] == "excessive_connections"
    )
    assert op["detected_at"] == T + 99 * 0.001
    eng.tick(T + 0.5)
    assert eng.drain_ops() == []  # not yet time to flush hits
    eng.tick(T + 0.13 + HIT_FLUSH_SECONDS + 0.01)
    hit = eng.drain_ops()[0]
    assert hit["op"] == "hit" and hit["hits"] == 30 and hit["escalate"] is False


def test_escalation_is_sent_immediately_and_flagged() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 1000)  # reaches 10x the threshold
    ops = eng.drain_ops()
    assert kinds(ops) == ["open", "hit"]
    assert ops[1]["escalate"] is True and ops[1]["severity"] == "high"
    assert ops[1]["hits"] == 900 and ops[0]["severity"] == "medium"


def test_event_closes_after_cooldown_and_reopens_as_a_new_event() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 120)
    first = eng.drain_ops()[0]["event_uuid"]
    eng.tick(T + 30)  # still inside the 60 s cooldown: pending hits flushed, event stays open
    assert kinds(eng.drain_ops()) == ["hit"] and eng.open_events == 1
    eng.tick(T + 70)
    assert kinds(eng.drain_ops()) == ["close"] and eng.open_events == 0
    run_flood(eng, 120, start=T + 200)
    reopened = eng.drain_ops()[0]
    assert reopened["op"] == "open" and reopened["event_uuid"] != first


def test_closing_flushes_pending_hits_first() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 110)
    eng.drain_ops()
    eng.tick(T + 61)
    assert kinds(eng.drain_ops()) == ["hit", "close"]


def test_ongoing_activity_keeps_the_event_open() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 120)
    eng.drain_ops()
    for k in range(1, 6):  # a new burst every 30 s: never quiet for 60 s
        run_flood(eng, 120, start=T + 30 * k)
        eng.tick(T + 30 * k + 1)
    assert eng.open_events == 1


def test_ops_are_json_serialisable_and_shutdown_leaves_events_open() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 130)
    eng.flush()
    ops = eng.drain_ops()
    json.dumps(ops)  # must not raise: they travel through the batch/spill machinery
    assert kinds(ops) == ["open", "hit"] and eng.open_events == 1  # not closed


# ------------------------------------------------------------------ configuration
def test_disabled_rule_is_silent_and_enabling_it_works() -> None:
    eng = IdsEngine(all_cfgs(excessive_connections={"enabled": False}))
    run_flood(eng, 200)
    assert eng.drain_ops() == []
    eng.reconfigure(all_cfgs(excessive_connections={"enabled": True, "version": 2}))
    run_flood(eng, 200, start=T + 5)
    assert kinds(eng.drain_ops()) == ["open"]


def test_reconfigure_applies_new_threshold_and_records_the_version() -> None:
    eng = IdsEngine(all_cfgs())
    run_flood(eng, 50)
    assert eng.drain_ops() == []
    eng.reconfigure(all_cfgs(excessive_connections={"threshold": 10, "version": 7}))
    run_flood(eng, 20, start=T + 1)
    op = eng.drain_ops()[0]
    assert op["rule_version"] == 7


def test_unknown_rules_in_the_database_are_ignored() -> None:
    cfgs = all_cfgs()
    eng = IdsEngine(cfgs[:2])  # only two rules configured
    assert sorted(eng.rules) == ["excessive_connections", "port_scan"]
    eng.on_auth_failure(AuthFailure(T, ATT))  # no auth rule: nothing happens, no crash


def test_restore_open_resumes_coalescing_instead_of_duplicating() -> None:
    eng = IdsEngine(all_cfgs())
    key = f"excessive_connections|{ATT}|{VIC}|9002"
    eng.restore_open(
        [
            {
                "dedup_key": key,
                "event_uuid": "u-1",
                "rule_key": "excessive_connections",
                "severity": "medium",
                "last_seen": T,
                "evidence": {},
            }
        ]
    )
    run_flood(eng, 130)
    assert kinds(eng.drain_ops()) == []  # detections are hits on the restored event, not an open
    eng.tick(T + 3)
    assert kinds(eng.drain_ops()) == ["hit"]
    eng.tick(T + 100)
    assert kinds(eng.drain_ops()) == ["close"]


# ------------------------------------------------------------------ auth log lines
def test_parse_failed_login_variants() -> None:
    good = [
        "Nov  8 12:00:01 h sshd[123]: Failed password for root from 10.10.10.30 port 5555 ssh2",
        "Nov  8 12:00:01 h sshd[123]: Failed password for invalid user bob from 10.10.10.30 port 5 ssh2",
        "2026-11-08T12:00:01.123+00:00 h sshd[9]: Failed publickey for alice from 10.10.10.30 port 22 ssh2",
        "Nov  8 12:00:01 h sshd-session[9]: Failed keyboard-interactive/pam for x from 10.10.10.30 port 2 ssh2",
        # bare format written by `sshd -E <file>` (captured from a real sshd in the lab)
        "Failed password for root from 10.10.10.30 port 34480 ssh2",
        "Failed password for invalid user bob from 10.10.10.30 port 34481 ssh2",
    ]
    for line in good:
        assert parse_auth_line(line, 5.0) == AuthFailure(5.0, "10.10.10.30"), line


def test_parse_ignores_everything_else() -> None:
    bad = [
        "Nov  8 12:00:01 h sshd[1]: Accepted password for root from 10.10.10.30 port 5 ssh2",
        "Nov  8 12:00:01 h sshd[1]: Invalid user bob from 10.10.10.30 port 5",
        "Nov  8 12:00:01 h sshd[1]: Failed password for root from fe80::1 port 5 ssh2",
        "Nov  8 12:00:01 h sshd[1]: Failed password for root from 999.1.1.1 port 5 ssh2",
        "Nov  8 12:00:01 h sudo[1]: Failed password for root from 10.10.10.30 port 5 ssh2",
        "Connection closed by authenticating user root 10.10.10.30 port 34480 [preauth]",
        "  Failed password for root from 10.10.10.30 port 5 ssh2",  # indented: not a bare sshd line
        "",
    ]
    for line in bad:
        assert parse_auth_line(line, 1.0) is None, line


# ------------------------------------------------------------------ tailer
LINE = "Nov  8 12:00:01 h sshd[1]: Failed password for root from 10.10.10.30 port 5 ssh2\n"


def append(path: Path, text: str) -> None:
    with open(path, "a") as f:
        f.write(text)


def test_tailer_starts_at_the_end_and_reads_new_lines(tmp_path: Path) -> None:
    p = tmp_path / "auth.log"
    p.write_text(LINE * 50)  # history: not an attack in progress
    t = LogTailer(p)
    assert t.poll() == []
    append(p, LINE * 3)
    assert len(t.poll()) == 3 and t.poll() == []


def test_tailer_buffers_partial_lines(tmp_path: Path) -> None:
    p = tmp_path / "auth.log"
    p.write_text("")
    t = LogTailer(p)
    append(p, LINE[:30])
    assert t.poll() == []
    append(p, LINE[30:])
    assert len(t.poll()) == 1


def test_tailer_survives_rotation_truncation_and_rewrite(tmp_path: Path) -> None:
    p = tmp_path / "auth.log"
    p.write_text(LINE * 5)
    t = LogTailer(p)
    os.rename(p, tmp_path / "auth.log.1")  # logrotate: new file, new inode
    p.write_text(LINE * 2)
    assert len(t.poll()) == 2
    p.write_text(LINE)  # truncated (copytruncate): smaller than our offset
    assert len(t.poll()) == 1
    p.write_text(LINE.replace("root", "adm") * 2)  # rewritten in place, same size class
    assert len(t.poll()) == 2


def test_tailer_waits_for_a_missing_file_then_reads_it_from_the_start(tmp_path: Path) -> None:
    p = tmp_path / "auth.log"
    t = LogTailer(p)
    assert t.poll() == [] and t.error == "FileNotFoundError"
    p.write_text(LINE * 4)
    assert len(t.poll()) == 4 and t.error is None


def test_tailer_ignores_absurdly_long_lines(tmp_path: Path) -> None:
    p = tmp_path / "auth.log"
    p.write_text("")
    t = LogTailer(p)
    append(p, "x" * 10_000 + "\n" + LINE)
    assert len(t.poll()) == 1
