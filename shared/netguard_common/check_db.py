"""CLI: verify that a configured database role can connect and report key facts."""

from __future__ import annotations

import argparse
import sys
from typing import cast, get_args

from sqlalchemy.exc import SQLAlchemyError

from netguard_common.config import Role, load_settings
from netguard_common.db import check_connection, make_engine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check database connectivity for a role")
    parser.add_argument("--role", choices=get_args(Role), required=True)
    args = parser.parse_args(argv)
    role = cast(Role, args.role)
    try:
        settings = load_settings()
        info = check_connection(make_engine(settings, role, pool_size=1))
    except (ValueError, SQLAlchemyError) as exc:
        # Report the exception class only: driver messages can echo connection details.
        print(f"[{args.role}] FAIL: {type(exc).__name__}", file=sys.stderr)
        return 1
    flag = "  WARNING: collation version mismatch" if info["collation_mismatch"] else ""
    print(
        f"[{args.role}] OK  PostgreSQL {info['server_version']}  db={info['database']}  "
        f"user={info['role']}  tz={info['timezone']}  locale_provider={info['locale_provider']}"
        f"  collate={info['collate']}{flag}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
