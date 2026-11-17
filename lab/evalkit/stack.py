"""Pure helpers for the full-stack resource measurement (no I/O, so they can be unit-tested)."""

from __future__ import annotations

from typing import Any

from .scoring import percentile

GROUPS = ("monitor", "api", "postgres")


def classify(name: str, cmdline: list[str], username: str) -> str | None:
    """Which part of NetGuard a process belongs to, or None.

    The monitor and the API are Python processes recognised by their `-m` module; PostgreSQL by the
    server's own process name and owner. Anything else (the load generator, a browser, this script)
    is deliberately not counted, so the figures are the cost of NetGuard itself.
    """
    # `make monitor-run` starts the monitor through sudo and setpriv, whose command lines END with the same
    # `python -m netguard_monitor.main run`. Only the Python process itself is counted, otherwise one
    # monitor would be found three times.
    is_python = name.startswith("python")
    joined = " ".join(cmdline)
    if is_python and "netguard_monitor.main" in joined and "-m" in cmdline:
        return "monitor"
    if is_python and cmdline[-2:] == ["-m", "app"]:
        return "api"
    if name == "postgres" and username == "postgres":
        return "postgres"
    return None


def summarise(cpu: list[float], mem_mb: list[float]) -> dict[str, Any]:
    """CPU is percent of ONE core (so 150 means one and a half cores); memory is in MB."""
    if not cpu:
        return {"samples": 0}
    return {
        "samples": len(cpu),
        "cpu_median": round(percentile(cpu, 0.5) or 0.0, 1),
        "cpu_p95": round(percentile(cpu, 0.95) or 0.0, 1),
        "cpu_max": round(max(cpu), 1),
        "mem_mb_median": round(percentile(mem_mb, 0.5) or 0.0, 1),
        "mem_mb_max": round(max(mem_mb), 1),
    }


def latency_ms(seconds: list[float]) -> dict[str, Any]:
    if not seconds:
        return {"n": 0}
    ms = [s * 1000 for s in seconds]
    return {
        "n": len(ms),
        "p50": round(percentile(ms, 0.5) or 0.0, 1),
        "p95": round(percentile(ms, 0.95) or 0.0, 1),
        "max": round(max(ms), 1),
    }
