"""Query-parameter helpers shared by the list endpoints. Everything user-supplied is typed, bounded
and bound as a SQL parameter; only fixed fragments are ever concatenated into a statement."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Annotated, Any

from fastapi import HTTPException, Query

Limit = Annotated[int, Query(ge=1, le=200, description="page size")]
BeforeId = Annotated[int | None, Query(ge=1, description="older than this id (next page)")]
AfterId = Annotated[int | None, Query(ge=0, description="newer than this id (backfill)")]
SrcIp = Annotated[IPv4Address | None, Query(description="IPv4 address")]


def aware(dt: datetime | None) -> datetime | None:
    """Naive timestamps are taken as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def time_range(
    start: datetime | None, end: datetime | None, default: timedelta, maximum: timedelta
) -> tuple[datetime, datetime]:
    to = aware(end) or datetime.now(UTC)
    frm = aware(start) or (to - default)
    if frm >= to:
        raise HTTPException(422, "'from' must be earlier than 'to'")
    if to - frm > maximum:
        raise HTTPException(422, f"time range too long (maximum {maximum})")
    return frm, to


def keyset(
    column: str,
    before_id: int | None,
    after_id: int | None,
    params: dict[str, Any],
    where: list[str],
) -> bool:
    """Add keyset-pagination conditions. Returns True when results should be read oldest-first."""
    if before_id is not None and after_id is not None:
        raise HTTPException(422, "use either before_id or after_id, not both")
    if before_id is not None:
        where.append(f"{column} < :before_id")
        params["before_id"] = before_id
    if after_id is not None:
        where.append(f"{column} > :after_id")
        params["after_id"] = after_id
    return after_id is not None


def page(items: list[dict[str, Any]], limit: int, ascending: bool) -> dict[str, Any]:
    """Wrap rows read with LIMIT limit+1. Newest-first pages return the cursor for the next page."""
    more = len(items) > limit
    items = items[:limit]
    if ascending:  # backfill: oldest-first rows are returned newest-first for display consistency
        items.reverse()
        return {"items": items, "next_before_id": None, "has_more_newer": more}
    return {"items": items, "next_before_id": items[-1]["id"] if more and items else None}
