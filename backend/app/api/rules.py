"""Detection rules: read for every user, change for admins. Each change creates a new rule version
(by database trigger) which events snapshot, so historical events still show the rule as it was."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import text

from app.audit import audit
from app.deps import AdminUser, CurrentUser, client_ip, tx
from app.schemas import RulePatchIn

router = APIRouter(prefix="/api/rules", tags=["rules"])

COLUMNS = (
    "id, key, name, category, description, enabled, severity, threshold, window_seconds, "
    "cooldown_seconds, params, version, created_at, updated_at, updated_by"
)
TUNABLE = ("enabled", "severity", "threshold", "window_seconds", "cooldown_seconds")
MAX_PARAM = 1_000_000_000


def _kind(value: object) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    return "other"


def check_params(current: dict[str, Any], new: dict[str, object]) -> dict[str, Any]:
    """Only existing parameters may be changed, with the same type and sane bounds.
    Unknown keys are refused so a typo cannot silently disable a detector setting."""
    merged = dict(current)
    for key, value in new.items():
        if key not in current:
            raise HTTPException(422, f"unknown parameter '{key}' for this rule")
        kind = _kind(value)
        if kind != _kind(current[key]) or kind == "other":
            raise HTTPException(422, f"parameter '{key}' must be of type {_kind(current[key])}")
        if kind == "number" and not (0 <= float(value) <= MAX_PARAM):  # type: ignore[arg-type]
            raise HTTPException(422, f"parameter '{key}' out of range")
        if kind == "string" and len(value) > 255:  # type: ignore[arg-type]
            raise HTTPException(422, f"parameter '{key}' too long")
        if kind == "list":
            items: list[object] = list(value)  # type: ignore[call-overload]
            if len(items) > 100 or not all(isinstance(i, str) and len(i) <= 255 for i in items):
                raise HTTPException(422, f"parameter '{key}' must be at most 100 short strings")
        merged[key] = value
    return merged


@router.get("")
def list_rules(request: Request, _: CurrentUser) -> dict[str, Any]:
    with tx(request) as conn:
        rows = conn.execute(text(f"SELECT {COLUMNS} FROM detection_rules ORDER BY id")).mappings()  # noqa: S608
        return {"items": [dict(r) for r in rows]}


@router.get("/{rule_id}")
def get_rule(rule_id: int, request: Request, _: CurrentUser) -> dict[str, Any]:
    with tx(request) as conn:
        row = (
            conn.execute(
                text(f"SELECT {COLUMNS} FROM detection_rules WHERE id = :i"),  # noqa: S608
                {"i": rule_id},
            )
            .mappings()
            .first()
        )
        if row is None:
            raise HTTPException(404, "no such rule")
        versions = conn.execute(
            text(
                "SELECT version, enabled, severity, threshold, window_seconds, cooldown_seconds, "
                "params, changed_by, changed_at FROM detection_rule_versions "
                "WHERE rule_id = :i ORDER BY version DESC"
            ),
            {"i": rule_id},
        ).mappings()
        return {**dict(row), "versions": [dict(v) for v in versions]}


@router.patch("/{rule_id}")
def patch_rule(
    rule_id: int, body: RulePatchIn, request: Request, user: AdminUser
) -> dict[str, Any]:
    changes = body.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(422, "nothing to change")
    with tx(request) as conn:
        cur = (
            conn.execute(
                text(f"SELECT {COLUMNS} FROM detection_rules WHERE id = :i FOR UPDATE"),  # noqa: S608
                {"i": rule_id},
            )
            .mappings()
            .first()
        )
        if cur is None:
            raise HTTPException(404, "no such rule")
        before = {k: cur[k] for k in (*TUNABLE, "params")}
        after = dict(before)
        for k in TUNABLE:
            if k in changes:
                after[k] = changes[k]
        if "params" in changes:
            after["params"] = check_params(cur["params"], changes["params"])
        diff = {k: v for k, v in after.items() if before[k] != v}
        if diff:
            conn.execute(
                text(
                    "UPDATE detection_rules SET enabled = :enabled, "
                    "severity = :severity, threshold = :threshold, "
                    "window_seconds = :window_seconds, cooldown_seconds = :cooldown_seconds, "
                    "params = CAST(:params AS jsonb), updated_by = :u, updated_at = now() "
                    "WHERE id = :i"
                ),
                {**after, "params": json.dumps(after["params"]), "u": user.id, "i": rule_id},
            )
            audit(
                conn,
                "rule.update",
                actor_user_id=user.id,
                source_ip=client_ip(request),
                target_type="rule",
                target_id=rule_id,
                details={"key": cur["key"], "before": {k: before[k] for k in diff}, "after": diff},
            )
        row = (
            conn.execute(
                text(f"SELECT {COLUMNS} FROM detection_rules WHERE id = :i"),  # noqa: S608
                {"i": rule_id},
            )
            .mappings()
            .one()
        )
    return dict(row)
