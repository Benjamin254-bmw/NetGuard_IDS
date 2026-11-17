"""Overview and monitor health."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from sqlalchemy import text

from app.deps import CurrentUser, tx

router = APIRouter(prefix="/api", tags=["system"])

STALE_AFTER_SECONDS = 15.0  # the monitor heartbeats every few seconds

_MONITOR = text(
    "SELECT state, interface, started_at, heartbeat_at, packets_captured, packets_dropped, "
    "packets_per_second, capture_queue_depth, write_queue_depth, spill_backlog, "
    "degraded_reasons, last_error, version, "
    "extract(epoch FROM (now() - heartbeat_at)) AS age FROM monitor_status"
)


def monitor_status(conn: Any) -> dict[str, Any]:
    row = conn.execute(_MONITOR).mappings().first()
    if row is None:
        return {"state": "never_started", "effective_state": "never_started"}
    d = dict(row)
    age = float(d.pop("age"))
    d["heartbeat_age_seconds"] = round(age, 1)
    # A monitor that stopped writing may still say "running": staleness overrides the stored state.
    d["effective_state"] = "stale" if age > STALE_AFTER_SECONDS else d["state"]
    return d


@router.get("/monitor/status")
def get_monitor_status(request: Request, _: CurrentUser) -> dict[str, Any]:
    with tx(request) as conn:
        return monitor_status(conn)


@router.get("/overview")
def overview(request: Request, _: CurrentUser) -> dict[str, Any]:
    with tx(request) as conn:
        mon = monitor_status(conn)
        open_by_sev = {
            r.severity: r.n
            for r in conn.execute(
                text("SELECT severity, count(*) AS n FROM security_events WHERE is_open GROUP BY 1")
            )
        }
        by_cat = {
            r.category: r.n
            for r in conn.execute(
                text(
                    "SELECT category, count(*) AS n FROM security_events "
                    "WHERE detected_at >= now() - interval '24 hours' GROUP BY 1"
                )
            )
        }
        alerts = conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE status = 'new') AS new, "
                "count(*) AS total FROM alerts"
            )
        ).one()
        devices = {
            r.status: r.n
            for r in conn.execute(text("SELECT status, count(*) AS n FROM devices GROUP BY 1"))
        }
        traffic = conn.execute(
            text(
                "SELECT COALESCE(CAST(sum(packets) AS bigint), 0) AS packets, "
                "COALESCE(CAST(sum(bytes) AS bigint), 0) AS bytes FROM traffic_stats_1s "
                "WHERE bucket_start >= now() - interval '5 minutes'"
            )
        ).one()
    return {
        "generated_at": datetime.now(UTC),
        "monitor": mon,
        "open_events_by_severity": open_by_sev,
        "events_24h_by_category": by_cat,
        "alerts": {"new": alerts.new, "total": alerts.total},
        "devices": {"active": devices.get("active", 0), "inactive": devices.get("inactive", 0)},
        "traffic_last_5m": {"packets": traffic.packets, "bytes": traffic.bytes},
    }


@router.get("/system/info")
def system_info(request: Request, _: CurrentUser) -> dict[str, Any]:
    """Read-only configuration for the Settings page. Only values that are safe to show:
    never the secret key, database credentials or paths of secret files."""
    st = request.app.state.settings
    with tx(request) as conn:
        mon = conn.execute(text("SELECT interface, version FROM monitor_status")).first()
    return {
        "api_version": request.app.version,
        "environment": st.env,
        "monitor_version": mon.version if mon else None,
        "monitored_interface": (mon.interface if mon else None) or st.monitor_interface,
        "authorized_subnet": str(st.authorized_subnet) if st.authorized_subnet else None,
        "retention_per_second_hours": st.retention_1s_hours,
        "retention_per_minute_days": st.retention_1m_days,
        "rules_reload_seconds": st.rules_reload_seconds,
        "session_ttl_minutes": st.session_ttl_minutes,
        "cookies_secure": st.cookies_secure,
        "allowed_origins": st.origins,
    }
