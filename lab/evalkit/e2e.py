"""Pure helpers for the end-to-end latency measurement (no I/O, so they can be unit-tested).

One trial = one port scan from a fresh source address. The measurement is the time from the moment
the scan process is started to the moment its alert arrives on the dashboard's WebSocket. Three
timestamps are taken on one machine (one clock):

  t_launch   just before the scan process is spawned
  created_at the alert row's timestamp (the database's now(), i.e. the START of the committing
             transaction, so the delivery step below includes the commit itself)
  t_ws       when the WebSocket message was received by the measuring client
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .scoring import percentile


def epoch(iso: str) -> float:
    """ISO-8601 timestamp (with offset or Z) to seconds since the epoch."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def stats(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "min": round(min(values), 3),
        "median": round(percentile(values, 0.5) or 0.0, 3),
        "p95": round(percentile(values, 0.95) or 0.0, 3),
        "max": round(max(values), 3),
    }


def match_alert(
    ip: str, t_launch: float, arrivals: list[dict[str, Any]], event_src: dict[int, str]
) -> dict[str, Any] | None:
    """The first alert pushed after `t_launch` whose event came from `ip`, or None (a miss)."""
    for a in sorted(arrivals, key=lambda x: x["t_ws"]):
        if a["t_ws"] < t_launch:
            continue
        if event_src.get(a["event_id"]) == ip:
            return a
    return None


def trial_record(ip: str, t_launch: float, arrival: dict[str, Any] | None) -> dict[str, Any]:
    if arrival is None:
        return {"ip": ip, "detected": False}
    created = epoch(arrival["created_at"])
    return {
        "ip": ip,
        "detected": True,
        "alert_id": arrival["alert_id"],
        "severity": arrival["severity"],
        "total": arrival["t_ws"] - t_launch,
        "to_alert_row": created - t_launch,
        "delivery": arrival["t_ws"] - created,
    }


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    hit = [r for r in records if r["detected"]]
    return {
        "trials": len(records),
        "detected": len(hit),
        "missed": len(records) - len(hit),
        "scan_process_s": stats([r["scan_process"] for r in records if "scan_process" in r]),
        "total_s": stats([r["total"] for r in hit]),
        "to_alert_row_s": stats([r["to_alert_row"] for r in hit]),
        "delivery_s": stats([r["delivery"] for r in hit]),
        "negative_delivery": sum(1 for r in hit if r["delivery"] < 0),
    }
