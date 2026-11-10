"""Command line: `check` (environment), `interfaces` (list), `run` (start monitoring)."""

from __future__ import annotations

import argparse
import importlib
import logging
import signal
import sys

from sqlalchemy.exc import SQLAlchemyError

from netguard_common.config import load_settings
from netguard_common.db import check_connection, make_engine
from netguard_common.logging_config import configure_logging
from netguard_monitor.capture.interfaces import capture_problems, get_interface, list_interfaces
from netguard_monitor.privileges import current_privileges
from netguard_monitor.service import MonitorService, PreflightError


def _check() -> int:
    ok = True
    settings = load_settings()
    configure_logging("monitor", settings.log_level, settings.log_format)

    for mod in ("scapy", "psutil"):
        try:
            m = importlib.import_module(mod)
            print(f"PASS  import {mod} {getattr(m, '__version__', '')}".rstrip())
        except ImportError:
            print(f"FAIL  import {mod}")
            ok = False

    try:
        info = check_connection(make_engine(settings, "monitor", pool_size=1))
        print(f"PASS  database role={info['role']} provider={info['locale_provider']}")
    except (ValueError, SQLAlchemyError) as exc:
        print(f"FAIL  database ({type(exc).__name__})")
        ok = False

    priv = current_privileges()
    print(f"INFO  root={priv.is_root} CAP_NET_RAW={priv.net_raw} CAP_NET_ADMIN={priv.net_admin}")
    if priv.is_root:
        print("WARN  running as root; use scripts/run-with-caps.sh or a systemd unit")
    if not priv.net_raw:
        print("INFO  no CAP_NET_RAW: packet capture will not be possible in this process")

    print(
        f"INFO  monitor_interface={settings.monitor_interface or '<unset>'} "
        f"authorized_subnet={settings.authorized_subnet or '<unset>'}"
    )
    iface = get_interface(settings.monitor_interface) if settings.monitor_interface else None
    problems = capture_problems(iface, settings.monitor_interface, settings.authorized_subnet)
    for p in problems:
        print(f"WARN  capture would be refused: {p}")
    if not problems:
        print("PASS  capture safeguards satisfied")
    return 0 if ok else 1


def _interfaces() -> int:
    for i in list_interfaces():
        addrs = ", ".join(str(a) for a in i.ipv4) or "-"
        flags = ("up" if i.is_up else "down") + (",loopback" if i.is_loopback else "")
        print(f"{i.name:<16} {flags:<14} mtu={i.mtu:<6} mac={i.mac or '-':<18} ipv4={addrs}")
    return 0


def _run(duration: float | None) -> int:
    settings = load_settings()
    configure_logging("monitor", settings.log_level, settings.log_format)
    service = MonitorService(settings)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: service.request_stop())
    try:
        service.run(duration)
    except PreflightError as exc:
        print("monitor will not start:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netguard-monitor")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="verify the environment")
    sub.add_parser("interfaces", help="list network interfaces")
    run = sub.add_parser("run", help="start monitoring (needs CAP_NET_RAW)")
    run.add_argument(
        "--duration", type=float, help="stop after N seconds (default: run until signalled)"
    )
    args = parser.parse_args(argv)
    logging.captureWarnings(True)
    if args.command == "check":
        return _check()
    if args.command == "interfaces":
        return _interfaces()
    return _run(args.duration)


if __name__ == "__main__":
    sys.exit(main())
