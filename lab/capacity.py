#!/usr/bin/env python3
"""Phase 4B resource and capacity sweep: how much traffic can the monitor take before it loses packets?

    sudo .venv/bin/python lab/capacity.py [--seconds 15]

Sends UDP at increasing rates (and TCP connection bursts at increasing rates) from ng-attacker to the
victim while the real, capability-limited monitor runs, and records for each step: packets sent, packets
the monitor captured, kernel-dropped packets (AF_PACKET counter), monitor CPU % and resident memory.
"Sustained" below means: kernel drops == 0 AND captured >= 99.9 % of packets sent. Only tested rates
are reported; nothing is extrapolated. The sender is a Python process, so the highest rate is bounded by
what it can generate, and that bound is reported too (achieved vs requested).
Writes lab/results/capacity-<timestamp>.json.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from evaluate import DRIVER, RESULTS, Sampler, engines  # noqa: E402
from verify_capture import BR, PY, ROOT, SUBNET, load_env, sh, wait_until_quiet  # noqa: E402
from verify_detection import TCP_SINK, UDP_SINK  # noqa: E402

UDP_MB_S = [1, 2, 4, 8, 16, 32, 64, 128]
CONN_PER_S = [100, 300, 1000, 3000]
SRC = "10.10.10.30"


def status(mig: Any) -> tuple[int, int]:
    with mig.connect() as c:
        r = c.execute(text("SELECT packets_captured, packets_dropped FROM monitor_status")).one()
    return int(r[0]), int(r[1])


def run_step(mig: Any, sampler: Sampler, scenario: str, params: dict[str, Any]) -> dict[str, Any]:
    time.sleep(7.0)  # let the previous step's heartbeat settle
    c0, d0 = status(mig)
    i0 = len(sampler.cpu)
    r = subprocess.run(  # noqa: S603
        ["ip", "netns", "exec", "ng-attacker", PY, str(DRIVER), scenario, json.dumps(params), SRC],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    i1 = len(sampler.cpu)
    time.sleep(7.0)
    c1, d1 = status(mig)
    out: dict[str, Any] = {"scenario": scenario, "requested": params, "rc": r.returncode}
    if r.returncode != 0:
        out["error"] = (r.stdout + r.stderr)[-200:]
        return out
    drv = json.loads(r.stdout.strip().splitlines()[-1])
    cpu, rss = sampler.cpu[i0:i1], sampler.rss[i0:i1]
    sent = drv["packets"] if scenario == "udp_rate" else drv["attempts"] * 2  # SYN + RST (refused)
    out.update(
        driver=drv,
        sent_packets=sent,
        captured_delta=c1 - c0,
        kernel_dropped_delta=d1 - d0,
        capture_ratio=round((c1 - c0) / sent, 5) if sent else None,
        cpu_percent_median=sorted(cpu)[len(cpu) // 2] if cpu else None,
        cpu_percent_max=max(cpu, default=None),
        rss_mb_max=round(max(rss, default=0) / 1e6, 1),
    )
    out["sustained"] = out["kernel_dropped_delta"] == 0 and (out["capture_ratio"] or 0) >= 0.999
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=15)
    args = ap.parse_args()
    if os.geteuid() != 0 or sh("ip", "link", "show", BR).returncode != 0:
        print("run with sudo and with the lab up", file=sys.stderr)
        return 2
    settings, mig, _ = engines()
    with mig.begin() as c:
        c.execute(
            text(
                "TRUNCATE alerts, security_events, traffic_stats_1s, connection_aggregates_1m, devices, "
                "ingest_batches, monitor_status RESTART IDENTITY CASCADE"
            )
        )
    work = Path(tempfile.mkdtemp(prefix="ng-cap-"))
    os.chmod(work, 0o755)  # noqa: S103
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    least = bool(uid and uid != "0")
    env = {
        **os.environ,
        **load_env(ROOT / ".env"),
        "NETGUARD_DB_NAME": settings.db_name,
        "NETGUARD_MONITOR_INTERFACE": BR,
        "NETGUARD_AUTHORIZED_SUBNET": SUBNET,
        "NETGUARD_SPILL_DIR": str(work / "spill"),
        "NETGUARD_ACTIVE_DISCOVERY": "false",
        "NETGUARD_PROMISCUOUS": "true",
        "NETGUARD_RULES_RELOAD_SECONDS": "2",
    }
    cmd = [PY, "-m", "netguard_monitor.main", "run", "--duration", "3000"]
    if least:
        assert uid is not None
        shutil.chown(work, int(uid), int(gid or uid))
        cmd = [
            "setpriv",
            "--reuid",
            uid,
            "--regid",
            gid or uid,
            "--init-groups",
            "--inh-caps=+net_raw,+net_admin",
            "--ambient-caps=+net_raw,+net_admin",
            "--bounding-set=-all,+net_raw,+net_admin",
            "--",
            *cmd,
        ]
    if not wait_until_quiet():
        print("bridge never went quiet", file=sys.stderr)
        return 2
    steps: list[dict[str, Any]] = []
    procs: list[subprocess.Popen[bytes]] = []
    with open(work / "monitor.log", "w") as mlog:
        monitor = subprocess.Popen(cmd, env=env, cwd=work, stdout=mlog, stderr=subprocess.STDOUT)  # noqa: S603
        sampler: Sampler | None = None
        try:
            for code in (TCP_SINK, UDP_SINK):
                procs.append(subprocess.Popen(["ip", "netns", "exec", "ng-victim", PY, "-c", code]))  # noqa: S603, S607
            for _ in range(100):
                with mig.connect() as c:
                    row = c.execute(text("SELECT state FROM monitor_status")).first()
                if row and row[0] == "running":
                    break
                time.sleep(0.3)
            else:
                print("monitor never reported running", file=sys.stderr)
                return 2
            sampler = Sampler(monitor.pid)
            sampler.start()
            for mb in UDP_MB_S:
                s = run_step(
                    mig, sampler, "udp_rate", {"mbps": float(mb), "seconds": float(args.seconds)}
                )
                steps.append(s)
                print(
                    f"UDP {mb:>4} MB/s requested: "
                    + json.dumps(
                        {
                            k: s.get(k)
                            for k in (
                                "sent_packets",
                                "captured_delta",
                                "kernel_dropped_delta",
                                "capture_ratio",
                                "cpu_percent_median",
                                "cpu_percent_max",
                                "rss_mb_max",
                                "sustained",
                            )
                        }
                    )
                )
            for rate in CONN_PER_S:
                p = {"ports": [9002], "n": rate * 10, "seconds": 10.0}
                s = run_step(mig, sampler, "flood", p)
                steps.append(s)
                print(
                    f"TCP {rate:>5} conn/s requested: "
                    + json.dumps(
                        {
                            k: s.get(k)
                            for k in (
                                "sent_packets",
                                "captured_delta",
                                "kernel_dropped_delta",
                                "capture_ratio",
                                "cpu_percent_median",
                                "cpu_percent_max",
                                "rss_mb_max",
                                "sustained",
                            )
                        }
                    )
                )
        finally:
            if sampler:
                sampler.stop_flag.set()
            for p_ in procs:
                p_.terminate()
            monitor.send_signal(signal.SIGTERM)
            try:
                monitor.wait(timeout=40)
            except subprocess.TimeoutExpired:
                monitor.kill()
    out = {
        "when": datetime.now(UTC).isoformat(timespec="seconds"),
        "seconds_per_step": args.seconds,
        "monitor_privileges": "non-root, CAP_NET_RAW+CAP_NET_ADMIN only" if least else "ROOT",
        "cpus": os.cpu_count(),
        "criterion": "kernel drops == 0 and captured >= 99.9% of sent",
        "steps": steps,
    }
    path = RESULTS / f"capacity-{datetime.now(UTC):%Y%m%dT%H%M%S}.json"
    path.write_text(json.dumps(out, indent=1, default=float))
    print("wrote", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
