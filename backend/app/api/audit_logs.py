"""Audit log: admins only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from sqlalchemy import text

from app.api.common import BeforeId, Limit, keyset, page
from app.deps import AdminUser, tx

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


@router.get("")
def list_audit_logs(
    request: Request,
    _: AdminUser,
    action: str | None = Query(default=None, pattern=r"^[a-z_]+([.][a-z_]+)+$", max_length=64),
    actor_user_id: int | None = Query(default=None, ge=1),
    limit: Limit = 50,
    before_id: BeforeId = None,
) -> dict[str, Any]:
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    if action:
        where.append("action = :action")
        params["action"] = action
    if actor_user_id:
        where.append("actor_user_id = :actor")
        params["actor"] = actor_user_id
    keyset("id", before_id, None, params, where)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with tx(request) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT id, occurred_at, actor_type, actor_user_id, action, target_type, "  # noqa: S608
                    f"target_id, host(source_ip) AS source_ip, details FROM audit_logs {clause} "
                    "ORDER BY id DESC LIMIT :limit"
                ),
                params,
            )
            .mappings()
            .all()
        )
    return page([dict(r) for r in rows], limit, False)
