"""Unit tests for the end-to-end latency helpers."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evalkit import e2e  # noqa: E402


def arr(alert_id: int, event_id: int, t_ws: float, created: str = "1970-01-01T00:00:10Z") -> dict:
    return {"alert_id": alert_id, "event_id": event_id, "t_ws": t_ws, "created_at": created, "severity": "high"}


def test_epoch_accepts_z_and_offset() -> None:
    assert e2e.epoch("1970-01-01T00:00:10Z") == 10.0
    assert e2e.epoch("1970-01-01T03:00:10+03:00") == 10.0


def test_match_picks_the_trials_own_alert_not_an_earlier_or_foreign_one() -> None:
    arrivals = [arr(1, 100, 5.0), arr(2, 200, 12.0), arr(3, 300, 13.0)]
    src = {100: "10.10.10.200", 200: "10.10.10.201", 300: "10.10.10.200"}
    # alert 1 is from the same address but arrived BEFORE the launch; alert 2 is another source
    got = e2e.match_alert("10.10.10.200", 10.0, arrivals, src)
    assert got is not None and got["alert_id"] == 3


def test_no_alert_is_a_miss_not_a_dropped_trial() -> None:
    assert e2e.match_alert("10.10.10.200", 0.0, [], {}) is None
    rec = e2e.trial_record("10.10.10.200", 0.0, None)
    assert rec == {"ip": "10.10.10.200", "detected": False}
    s = e2e.summarise([rec])
    assert (s["trials"], s["detected"], s["missed"]) == (1, 0, 1)
    assert s["total_s"] == {"n": 0}


def test_record_splits_total_into_two_parts_that_add_up() -> None:
    rec = e2e.trial_record("10.10.10.200", 8.0, arr(1, 1, 10.75, "1970-01-01T00:00:10Z"))
    assert rec["total"] == 2.75
    assert rec["to_alert_row"] == 2.0
    assert rec["delivery"] == 0.75
    assert abs(rec["to_alert_row"] + rec["delivery"] - rec["total"]) < 1e-9


def test_summary_statistics_and_negative_delivery_is_reported() -> None:
    recs = [
        e2e.trial_record("a", 0.0, arr(i, i, 10.0 + i * 0.1, "1970-01-01T00:00:10Z")) for i in range(1, 11)
    ]
    recs.append(e2e.trial_record("b", 0.0, None))
    recs.append(e2e.trial_record("c", 0.0, arr(99, 99, 9.5, "1970-01-01T00:00:10Z")))
    s = e2e.summarise(recs)
    assert (s["trials"], s["detected"], s["missed"]) == (12, 11, 1)
    assert s["negative_delivery"] == 1  # clock-resolution artefact is counted, not hidden
    assert s["total_s"]["max"] == 11.0


def test_scan_process_duration_is_summarised_for_every_trial_including_misses() -> None:
    a = e2e.trial_record("a", 0.0, arr(1, 1, 10.5)) | {"scan_process": 0.25}
    b = e2e.trial_record("b", 0.0, None) | {"scan_process": 0.75}
    s = e2e.summarise([a, b])
    assert s["scan_process_s"]["n"] == 2 and s["scan_process_s"]["max"] == 0.75
    assert s["total_s"]["n"] == 1
