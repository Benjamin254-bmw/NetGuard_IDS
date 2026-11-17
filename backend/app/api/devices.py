"""Discovered devices."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Request
from sqlalchemy import text

from app.deps import CurrentUser, tx

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("")
def list_devices(
    request: Request,
    _: CurrentUser,
    status: Literal["active", "inactive"] | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, Any]:
    where = "WHERE status = :status" if status else ""
    with tx(request) as conn:
        rows = (
            conn.execute(
                text(  # `where` is one of two fixed fragments; the value is bound
                    "SELECT id, host(ip) AS ip, CAST(mac AS text) AS mac, hostname, status, "  # noqa: S608
                    f"discovery_source, first_seen, last_seen FROM devices {where} "
                    "ORDER BY last_seen DESC, id DESC LIMIT :limit OFFSET :offset"
                ),
                {"status": status, "limit": limit, "offset": offset},
            )
            .mappings()
            .all()
        )
        total = conn.execute(
            text(f"SELECT count(*) FROM devices {where}"),  # noqa: S608
            {"status": status} if status else {},
        ).scalar_one()
    return {"items": [dict(r) for r in rows], "total": total, "limit": limit, "offset": offset}
