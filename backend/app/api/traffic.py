"""Traffic statistics. Per-second data is retained 24 h, per-minute flow aggregates 30 days."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import text

from app.api.common import time_range
from app.deps import CurrentUser, tx

router = APIRouter(prefix="/api/traffic", tags=["traffic"])

BUCKETS = {1, 5, 10, 30, 60, 300}
MAX_POINTS = 2000
From = Annotated[datetime | None, Query(alias="from")]
To = Annotated[datetime | None, Query(alias="to")]


@router.get("/series")
def series(
    request: Request,
    _: CurrentUser,
    frm: From = None,
    to: To = None,
    bucket: Annotated[int, Query(description="seconds per point: 1, 5, 10, 30, 60 or 300")] = 1,
) -> dict[str, Any]:
    if bucket not in BUCKETS:
        raise HTTPException(422, f"bucket must be one of {sorted(BUCKETS)}")
    start, end = time_range(frm, to, timedelta(minutes=15), timedelta(hours=24))
    if (end - start).total_seconds() / bucket > MAX_POINTS:
        raise HTTPException(422, f"too many points (maximum {MAX_POINTS}); use a larger bucket")
    with tx(request) as conn:
        rows = conn.execute(
            text(
                "SELECT date_bin(make_interval(secs => CAST(:b AS double precision)), "
                "bucket_start, TIMESTAMPTZ '2000-01-01') AS t, "
                "CAST(sum(packets) AS bigint) AS packets, CAST(sum(bytes) AS bigint) AS bytes, "
                "CAST(sum(new_connections) AS bigint) AS new_connections "
                "FROM traffic_stats_1s WHERE bucket_start >= :s AND bucket_start < :e "
                "GROUP BY 1 ORDER BY 1"
            ),
            {"b": bucket, "s": start, "e": end},
        ).mappings()
        points = [dict(r) for r in rows]
    return {"from": start, "to": end, "bucket_seconds": bucket, "points": points}


@router.get("/protocols")
def protocols(request: Request, _: CurrentUser, frm: From = None, to: To = None) -> dict[str, Any]:
    start, end = time_range(frm, to, timedelta(hours=1), timedelta(hours=24))
    with tx(request) as conn:
        rows = conn.execute(
            text(
                "SELECT protocol, CAST(sum(packets) AS bigint) AS packets, "
                "CAST(sum(bytes) AS bigint) AS bytes FROM traffic_stats_1s "
                "WHERE bucket_start >= :s AND bucket_start < :e GROUP BY 1 ORDER BY 3 DESC"
            ),
            {"s": start, "e": end},
        ).mappings()
        items = [dict(r) for r in rows]
    return {"from": start, "to": end, "items": items}


_TALKERS = {
    "src": "host(src_ip)",
    "dst": "host(dst_ip)",
}


@router.get("/top-talkers")
def top_talkers(
    request: Request,
    _: CurrentUser,
    frm: From = None,
    to: To = None,
    by: Literal["bytes", "packets"] = "bytes",
    direction: Literal["src", "dst"] = "src",
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> dict[str, Any]:
    start, end = time_range(frm, to, timedelta(hours=1), timedelta(days=30))
    key = _TALKERS[direction]
    order = "sum(b)" if by == "bytes" else "sum(p)"
    with tx(request) as conn:
        rows = conn.execute(
            # `key` and the ORDER BY term come from fixed choices above, never from request text.
            # Group by flow first, then count the flows per address: the same numbers as
            # count(DISTINCT (dst_ip, dst_port, transport)), but about 8x faster on a full 30-day
            # range (measured: 1251 ms -> 152 ms on 864,000 rows; see docs/evaluation.md).
            text(
                "SELECT ip, CAST(sum(b) AS bigint) AS bytes, "  # noqa: S608
                "CAST(sum(p) AS bigint) AS packets, count(*) AS flows FROM ("
                f"SELECT {key} AS ip, dst_ip, dst_port, transport, "
                "sum(bytes) AS b, sum(packets) AS p "
                "FROM connection_aggregates_1m WHERE bucket_start >= :s AND bucket_start < :e "
                "GROUP BY 1, 2, 3, 4) f "
                f"GROUP BY ip ORDER BY {order} DESC, 1 LIMIT :limit"
            ),
            {"s": start, "e": end, "limit": limit},
        ).mappings()
        items = [dict(r) for r in rows]
    return {"from": start, "to": end, "by": by, "direction": direction, "items": items}
