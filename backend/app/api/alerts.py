"""Alerts: list, and acknowledge/dismiss."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import text

from app.api.common import AfterId, BeforeId, Limit, keyset, page
from app.audit import audit
from app.deps import CurrentUser, client_ip, tx
from app.schemas import AlertStatusIn

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

COLUMNS = (
    "a.id, a.event_id, a.severity, a.title, a.created_at, a.status, a.acknowledged_by, "
    "a.acknowledged_at, e.category, host(e.src_ip) AS src_ip"
)


def fetch_alert(conn: Any, alert_id: int) -> dict[str, Any] | None:
    """One alert in the shape used by the list endpoint and the WebSocket push."""
    row = (
        conn.execute(
            text(  # COLUMNS is a module constant
                f"SELECT {COLUMNS} FROM alerts a JOIN security_events e ON e.id = a.event_id "  # noqa: S608
                "WHERE a.id = :i"
            ),
            {"i": alert_id},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


@router.get("")
def list_alerts(
    request: Request,
    _: CurrentUser,
    status: Literal["new", "acknowledged", "dismissed"] | None = None,
    severity: Literal["informational", "low", "medium", "high", "critical"] | None = None,
    limit: Limit = 50,
    before_id: BeforeId = None,
    after_id: AfterId = None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    if status:
        where.append("a.status = :status")
        params["status"] = status
    if severity:
        where.append("a.severity = :severity")
        params["severity"] = severity
    ascending = keyset("a.id", before_id, after_id, params, where)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with tx(request) as conn:
        rows = (
            conn.execute(
                text(
                    f"SELECT {COLUMNS} FROM alerts a JOIN security_events e ON e.id = a.event_id "  # noqa: S608
                    f"{clause} ORDER BY a.id {'ASC' if ascending else 'DESC'} LIMIT :limit"
                ),
                params,
            )
            .mappings()
            .all()
        )
    return page([dict(r) for r in rows], limit, ascending)


@router.patch("/{alert_id}")
def set_alert_status(
    alert_id: int, body: AlertStatusIn, request: Request, user: CurrentUser
) -> dict[str, Any]:
    with tx(request) as conn:
        old = conn.execute(
            text("SELECT status FROM alerts WHERE id = :i FOR UPDATE"), {"i": alert_id}
        ).first()
        if old is None:
            raise HTTPException(404, "no such alert")
        if body.status == "new":  # reopening clears the acknowledgement
            conn.execute(
                text(
                    "UPDATE alerts SET status = 'new', acknowledged_by = NULL, "
                    "acknowledged_at = NULL WHERE id = :i"
                ),
                {"i": alert_id},
            )
        else:
            conn.execute(
                text(
                    "UPDATE alerts SET status = :s, acknowledged_by = :u, acknowledged_at = now() "
                    "WHERE id = :i"
                ),
                {"s": body.status, "u": user.id, "i": alert_id},
            )
        audit(
            conn,
            "alert.status_change",
            actor_user_id=user.id,
            source_ip=client_ip(request),
            target_type="alert",
            target_id=alert_id,
            details={"from": old.status, "to": body.status},
        )
        result = fetch_alert(conn, alert_id)
    if result is None:  # cannot happen inside the transaction that just updated it
        raise HTTPException(500, "alert vanished")
    return result
