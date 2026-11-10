"""Heartbeat: one row that tells the dashboard whether monitoring is running, degraded or stale."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from sqlalchemy import Engine, text

_UPSERT = text(
    """
    INSERT INTO monitor_status
      (id, state, interface, started_at, heartbeat_at, packets_captured, packets_dropped,
       packets_per_second, capture_queue_depth, write_queue_depth, spill_backlog,
       degraded_reasons, last_error, version)
    VALUES (1, :state, :interface, to_timestamp(CAST(:started AS double precision)), now(),
            :captured, :dropped, :pps, :cq, :wq, :spill, CAST(:reasons AS jsonb), :err, :version)
    ON CONFLICT (id) DO UPDATE SET
      state = EXCLUDED.state, interface = EXCLUDED.interface, started_at = EXCLUDED.started_at,
      heartbeat_at = now(), packets_captured = EXCLUDED.packets_captured,
      packets_dropped = EXCLUDED.packets_dropped, packets_per_second = EXCLUDED.packets_per_second,
      capture_queue_depth = EXCLUDED.capture_queue_depth,
      write_queue_depth = EXCLUDED.write_queue_depth, spill_backlog = EXCLUDED.spill_backlog,
      degraded_reasons = EXCLUDED.degraded_reasons, last_error = EXCLUDED.last_error,
      version = EXCLUDED.version
    """
)


@dataclass
class StatusSnapshot:
    state: str
    interface: str | None
    started_at: float | None
    packets_captured: int = 0
    packets_dropped: int = 0
    packets_per_second: float = 0.0
    capture_queue_depth: int = 0
    write_queue_depth: int = 0
    spill_backlog: int = 0
    degraded_reasons: list[str] = field(default_factory=list)
    last_error: str | None = None
    version: str | None = None


def write_status(engine: Engine, s: StatusSnapshot) -> None:
    with engine.begin() as conn:
        conn.execute(
            _UPSERT,
            {
                "state": s.state,
                "interface": s.interface,
                "started": s.started_at,
                "captured": s.packets_captured,
                "dropped": s.packets_dropped,
                "pps": s.packets_per_second,
                "cq": s.capture_queue_depth,
                "wq": s.write_queue_depth,
                "spill": s.spill_backlog,
                "reasons": json.dumps(s.degraded_reasons),
                "err": s.last_error,
                "version": s.version,
            },
        )
