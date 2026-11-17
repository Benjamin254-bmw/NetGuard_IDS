#!/usr/bin/env python3
"""Fill a SCRATCH database with synthetic traffic rows up to the monitor's retention limits.

    NETGUARD_DB_NAME=netguard_scale .venv/bin/python lab/seed_scale.py [--hours 24] [--days 30] [--flows 20]

Purpose: measure how fast the API answers when the tables are as big as retention allows, which a fresh
database cannot show. The rows are SYNTHETIC (random counters on documented key patterns) and exist only to
give the queries realistic table sizes; they are not detection results and nothing here is evidence about
detection quality. It refuses to touch the database named in .env as the development database, or any name
that does not contain "scale". Use scripts/scale_db.sh to create and drop the scratch database.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_capture import ROOT, load_env  # noqa: E402

from netguard_common.config import load_settings  # noqa: E402
from netguard_common.db import make_engine  # noqa: E402

PER_SECOND = text(
    "INSERT INTO traffic_stats_1s (bucket_start, protocol, packets, bytes, new_connections) "
    "SELECT date_trunc('second', now()) - make_interval(secs => s), p, "
    "1 + floor(random() * 200)::bigint, 60 + floor(random() * 200000)::bigint, floor(random() * 5)::int "
    "FROM generate_series(0, :n - 1) AS s, unnest(ARRAY['tcp','udp','dns','https','icmp']) AS p "
    "ON CONFLICT DO NOTHING"
)
PER_MINUTE = text(
    "INSERT INTO connection_aggregates_1m "
    "(bucket_start, src_ip, dst_ip, dst_port, transport, app_protocol, packets, bytes, syn_count) "
    "SELECT date_trunc('minute', now()) - make_interval(mins => m), "
    "('10.10.10.' || (100 + f % 50))::inet, '10.10.10.10'::inet, 1000 + f, "
    "CASE WHEN f % 2 = 0 THEN 'tcp' ELSE 'udp' END, NULL, "
    "1 + floor(random() * 5000)::bigint, 60 + floor(random() * 5000000)::bigint, floor(random() * 20)::int "
    "FROM generate_series(0, :m - 1) AS m, generate_series(0, :f - 1) AS f "
    "ON CONFLICT DO NOTHING"
)
DEVICES = text(
    "INSERT INTO devices (mac, ip, status, discovery_source, first_seen, last_seen) "
    "SELECT ('02:00:00:00:' || lpad(to_hex(i / 256), 2, '0') || ':' || lpad(to_hex(i % 256), 2, '0'))::macaddr, "
    "('10.10.10.' || (100 + i))::inet, 'active', 'traffic', now(), now() "
    "FROM generate_series(0, :n - 1) AS i ON CONFLICT DO NOTHING"
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=int, default=24, help="per-second history (retention default 24)")
    ap.add_argument("--days", type=int, default=30, help="per-minute history (retention default 30)")
    ap.add_argument("--flows", type=int, default=20, help="distinct flows per minute (max 50 here)")
    ap.add_argument("--devices", type=int, default=20)
    args = ap.parse_args()
    if not 1 <= args.flows <= 50:
        print("--flows must be 1..50", file=sys.stderr)
        return 2
    dev = load_env(ROOT / ".env").get("NETGUARD_DB_NAME", "netguard")  # the file's value, not the override
    s = load_settings(ROOT / ".env").model_copy(update={"db_name": os.environ.get("NETGUARD_DB_NAME", dev)})
    if "scale" not in s.db_name or s.db_name == dev:
        print(f"refusing: '{s.db_name}' is not a scratch database (name must contain 'scale' and differ from .env)", file=sys.stderr)
        return 2
    eng = make_engine(s, "migrator", pool_size=1)
    t0 = time.time()
    with eng.begin() as c:
        c.execute(DEVICES, {"n": args.devices})
        c.execute(PER_SECOND, {"n": args.hours * 3600})
        c.execute(PER_MINUTE, {"m": args.days * 1440, "f": args.flows})
        counts = {
            t: c.execute(text(f"SELECT count(*) FROM {t}")).scalar()  # noqa: S608 - fixed names
            for t in ("traffic_stats_1s", "connection_aggregates_1m", "devices")
        }
        c.execute(text("ANALYZE traffic_stats_1s"))
        c.execute(text("ANALYZE connection_aggregates_1m"))
    print(f"seeded {s.db_name} in {time.time() - t0:.1f} s: {counts} (synthetic rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
