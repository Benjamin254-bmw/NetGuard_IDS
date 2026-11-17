"""Unit tests for the full-stack resource helpers."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evalkit import stack  # noqa: E402


def test_each_part_of_the_stack_is_recognised_and_other_processes_are_not() -> None:
    py = "/home/u/netguard-ids/.venv/bin/python"
    assert stack.classify("python", [py, "-m", "netguard_monitor.main", "run"], "u") == "monitor"
    assert stack.classify("python", [py, "-m", "app"], "u") == "api"
    assert stack.classify("postgres", ["postgres: 16/main: writer"], "postgres") == "postgres"
    # not counted: the CLI, the load generator, a database client owned by someone else, a browser
    assert stack.classify("python", [py, "-m", "app.cli", "create-user"], "u") is None
    assert stack.classify("python", [py, "lab/evalkit/driver.py", "udp_rate"], "u") is None
    assert stack.classify("postgres", ["postgres"], "someone") is None
    assert stack.classify("chrome", ["chrome", "--type=renderer"], "u") is None


def test_the_sudo_and_setpriv_wrappers_around_the_monitor_are_not_counted_as_monitors() -> None:
    tail = ["/home/u/netguard-ids/.venv/bin/python", "-m", "netguard_monitor.main", "run"]
    assert stack.classify("sudo", ["sudo", "scripts/run-with-caps.sh", *tail], "root") is None
    assert stack.classify("setpriv", ["setpriv", "--reuid=1000", *tail], "root") is None
    assert stack.classify("python", tail, "u") == "monitor"


def test_summary_reports_median_p95_max_and_empty_input() -> None:
    assert stack.summarise([], []) == {"samples": 0}
    s = stack.summarise([float(x) for x in range(1, 101)], [50.0, 60.0, 70.0])
    assert (s["samples"], s["cpu_median"], s["cpu_max"]) == (100, 50.5, 100.0)
    assert s["cpu_p95"] == 95.05 or abs(s["cpu_p95"] - 95.1) < 0.1
    assert (s["mem_mb_median"], s["mem_mb_max"]) == (60.0, 70.0)


def test_latency_is_converted_to_milliseconds() -> None:
    assert stack.latency_ms([]) == {"n": 0}
    r = stack.latency_ms([0.010, 0.020, 0.030])
    assert (r["n"], r["p50"], r["max"]) == (3, 20.0, 30.0)
