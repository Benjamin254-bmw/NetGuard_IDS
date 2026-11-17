"""Administration from the server's command line (no default accounts exist).

    python -m app.cli create-user --username benjamin --role admin
    python -m app.cli unlock --username benjamin
    python -m app.cli reset-password --username benjamin

Passwords are read from the terminal (hidden) or, for scripted setups, from the environment
variable named by --password-env. They are never accepted as command-line arguments (those leak
into shell history and the process list).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from sqlalchemy import text

from app import security as sec
from netguard_common.config import load_settings
from netguard_common.db import make_engine


def _password(args: argparse.Namespace, username: str) -> str:
    if args.password_env:
        pw = os.environ.get(args.password_env)
        if not pw:
            sys.exit(f"environment variable {args.password_env} is empty or unset")
    else:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat password: "):
            sys.exit("passwords do not match")
    problem = sec.password_problem(pw, username)
    if problem:
        sys.exit(f"password {problem}")
    return pw


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("create-user", "reset-password", "unlock"):
        p = sub.add_parser(name)
        p.add_argument("--username", required=True)
        if name != "unlock":
            p.add_argument(
                "--password-env", help="read the password from this environment variable"
            )
        if name == "create-user":
            p.add_argument("--role", choices=("admin", "analyst"), default="admin")
            p.add_argument("--email")
    args = ap.parse_args(argv)
    engine = make_engine(load_settings(), "api", pool_size=1)
    with engine.begin() as conn:
        if args.cmd == "create-user":
            pw_hash = sec.hash_password(_password(args, args.username))
            conn.execute(
                text(
                    "INSERT INTO users (username, email, password_hash, role, password_changed_at) "
                    "VALUES (:u, :e, :h, :r, now())"
                ),
                {"u": args.username, "e": args.email, "h": pw_hash, "r": args.role},
            )
            conn.execute(
                text(
                    "INSERT INTO audit_logs (actor_type, action, target_type, details) VALUES "
                    "('system', 'user.created', 'user', CAST(:d AS jsonb))"
                ),
                {"d": json.dumps({"username": args.username, "via": "cli"})},
            )
            print(f"created {args.role} '{args.username}'")
        elif args.cmd == "reset-password":
            pw_hash = sec.hash_password(_password(args, args.username))
            n = conn.execute(
                text(
                    "UPDATE users SET password_hash = :h, password_changed_at = now(), "
                    "session_version = session_version + 1, failed_login_count = 0, "
                    "locked_until = NULL WHERE lower(username) = lower(:u)"
                ),
                {"h": pw_hash, "u": args.username},
            ).rowcount
            if n != 1:
                sys.exit(f"no such user: {args.username}")
            print(f"password reset for '{args.username}'; existing sessions revoked")
        else:
            n = conn.execute(
                text(
                    "UPDATE users SET failed_login_count = 0, locked_until = NULL "
                    "WHERE lower(username) = lower(:u)"
                ),
                {"u": args.username},
            ).rowcount
            if n != 1:
                sys.exit(f"no such user: {args.username}")
            print(f"unlocked '{args.username}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
