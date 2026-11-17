"""Audit trail. Every security-relevant action writes one row in the same transaction as the action,
so a change cannot commit without its record. Details never contain passwords, tokens or hashes."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Connection, text

FORBIDDEN_KEYS = {"password", "new_password", "current_password", "password_hash", "token", "csrf"}

_INSERT = text(
    "INSERT INTO audit_logs "
    "(actor_type, actor_user_id, action, target_type, target_id, source_ip, details) "
    "VALUES (CAST(:actor_type AS text), :actor, :action, :target_type, :target_id, "
    "CAST(:ip AS inet), CAST(:details AS jsonb))"
)


def _clean(details: dict[str, Any]) -> dict[str, Any]:
    return {k: ("[redacted]" if k.lower() in FORBIDDEN_KEYS else v) for k, v in details.items()}


def audit(
    conn: Connection,
    action: str,
    *,
    actor_user_id: int | None,
    source_ip: str | None,
    target_type: str | None = None,
    target_id: int | str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        _INSERT,
        {
            "actor_type": "user" if actor_user_id is not None else "system",
            "actor": actor_user_id,
            "action": action,
            "target_type": target_type,
            "target_id": None if target_id is None else str(target_id),
            "ip": source_ip,
            "details": json.dumps(_clean(details or {}), default=str),
        },
    )
