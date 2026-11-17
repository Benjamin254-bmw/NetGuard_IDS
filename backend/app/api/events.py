"""Security events: list with filters and keyset pagination, detail, and status changes."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import text

from app.api.common import AfterId, BeforeId, Limit, SrcIp, aware, keyset, page
from app.audit import audit
from app.deps import CurrentUser, client_ip, tx
from app.schemas import EventStatusIn

router = APIRouter(prefix="/api/events", tags=["events"])

Severity = Literal["informational", "low", "medium", "high", "critical"]
Category = Literal[
    "port_scan", "excessive_connections", "auth_failures", "abnormal_traffic", "suspicious_dns"
]
Status = Literal["new", "investigating", "resolved", "false_positive"]

COLUMNS = (
    "id, event_uuid, category, rule_id, rule_version, severity, host(src_ip) AS src_ip, "
    "host(dst_ip) AS dst_ip, dst_port, protocol, description, is_open, hit_count, detected_at, "
    "last_seen_at, status, status_updated_at, status_updated_by"
)


@router.get("")
def list_events(
    request: Request,
    _: CurrentUser,
    severity: Severity | None = None,
    category: Category | None = None,
    status: Status | None = None,
    is_open: bool | None = None,
    src_ip: SrcIp = None,
    frm: Annotated[datetime | None, Query(alias="from")] = None,
    to: Annotated[datetime | None, Query()] = None,
    limit: Limit = 50,
    before_id: BeforeId = None,
    after_id: AfterId = None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    for column, value in (
        ("severity", severity),
        ("category", category),
        ("status", status),
        ("is_open", is_open),
    ):
        if value is not None:
            where.append(f"{column} = :{column}")  # column names come from this fixed tuple
            params[column] = value
    if src_ip is not None:
        where.append("src_ip = CAST(:src_ip AS inet)")
        params["src_ip"] = str(src_ip)
    if frm is not None:
        where.append("detected_at >= :frm")
        params["frm"] = aware(frm)
    if to is not None:
        where.append("detected_at < :to")
        params["to"] = aware(to)
    ascending = keyset("id", before_id, after_id, params, where)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    order = "ASC" if ascending else "DESC"
    with tx(request) as conn:
        rows = (
            conn.execute(
                text(  # only fixed fragments are concatenated; every value is bound
                    f"SELECT {COLUMNS} FROM security_events {clause} "  # noqa: S608
                    f"ORDER BY id {order} LIMIT :limit"
                ),
                params,
            )
            .mappings()
            .all()
        )
    return page([dict(r) for r in rows], limit, ascending)


@router.get("/{event_id}")
def get_event(event_id: int, request: Request, _: CurrentUser) -> dict[str, Any]:
    with tx(request) as conn:
        row = (
            conn.execute(
                text(f"SELECT {COLUMNS}, evidence, dedup_key FROM security_events WHERE id = :i"),  # noqa: S608
                {"i": event_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise HTTPException(404, "no such event")
        event = dict(row)
        alerts = conn.execute(
            text(
                "SELECT id, severity, title, created_at, status, acknowledged_by, acknowledged_at "
                "FROM alerts WHERE event_id = :i ORDER BY id"
            ),
            {"i": event_id},
        ).mappings()
        event["alerts"] = [dict(a) for a in alerts]
        rule = (
            conn.execute(
                text(
                    "SELECT v.rule_id, v.version, v.enabled, v.severity, v.threshold, "
                    "v.window_seconds, v.cooldown_seconds, v.params, v.changed_at, r.key, r.name "
                    "FROM detection_rule_versions v JOIN detection_rules r ON r.id = v.rule_id "
                    "WHERE v.rule_id = :r AND v.version = :v"
                ),
                {"r": event["rule_id"], "v": event["rule_version"]},
            )
            .mappings()
            .first()
        )
        event["rule_snapshot"] = dict(rule) if rule else None
    return event


@router.patch("/{event_id}")
def set_event_status(
    event_id: int, body: EventStatusIn, request: Request, user: CurrentUser
) -> dict[str, Any]:
    with tx(request) as conn:
        old = conn.execute(
            text("SELECT status FROM security_events WHERE id = :i FOR UPDATE"), {"i": event_id}
        ).first()
        if old is None:
            raise HTTPException(404, "no such event")
        conn.execute(
            text(
                "UPDATE security_events SET status = :s, status_updated_at = now(), "
                "status_updated_by = :u WHERE id = :i"
            ),
            {"s": body.status, "u": user.id, "i": event_id},
        )
        audit(
            conn,
            "event.status_change",
            actor_user_id=user.id,
            source_ip=client_ip(request),
            target_type="event",
            target_id=event_id,
            details={"from": old.status, "to": body.status},
        )
        row = (
            conn.execute(
                text(f"SELECT {COLUMNS} FROM security_events WHERE id = :i"),  # noqa: S608
                {"i": event_id},
            )
            .mappings()
            .one()
        )
    return dict(row)
