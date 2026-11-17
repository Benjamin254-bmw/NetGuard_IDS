#!/usr/bin/env python3
"""Phase 7: end-to-end latency, from a port scan starting to its alert arriving on the dashboard feed.

    sudo -E .venv/bin/python lab/e2e_latency.py --user <admin> [--trials 30]

What it needs running (it starts nothing itself, so it measures the system you actually run):
  * the lab (`make lab-up`) and the monitor on br-lab with NETGUARD_PROMISCUOUS=true (`make monitor-run`)
  * the API (`make run-api`)
Password: prompted (or NETGUARD_E2E_PASSWORD for unattended runs). It is never written anywhere.

Each trial: add a fresh source address in ng-attacker (so every trial opens its OWN event and no
cooldown can hide it), run `nmap -sS` of 40 ports from it against the lab victim, and record when the
alert for that source arrives on the same /api/ws WebSocket the dashboard uses. A trial that gets no
alert within --wait seconds counts as a MISS; it is reported, never dropped. A failed scan process makes
the trial INVALID (listed, excluded). Nothing is extrapolated and nothing is estimated.

Timestamps all come from one machine's clock (see lab/evalkit/e2e.py). Writes lab/results/e2e-<ts>.json.
"""

from __future__ import annotations

import argparse
import atexit
import getpass
import json
import os
import platform
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from websockets.sync.client import connect

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from evalkit import e2e  # noqa: E402

RESULTS = LAB / "results"
VICTIM = "10.10.10.10"
NS, DEV = "ng-attacker", "pattacker"
PREFIX = "10.10.10."
POOL = range(100, 180)  # the attacker's source pool (lab/evalkit/plan.py)
PORTS = "1-40"  # 40 distinct ports, above the port_scan threshold of 15, below the critical 150
SETTLE = 3.0


def sh(*cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)  # noqa: S603


class Feed(threading.Thread):
    """Receives /api/ws messages and stamps each alert with the arrival time as soon as it is read."""

    def __init__(self, url: str, cookie: str, origin: str) -> None:
        super().__init__(daemon=True)
        self.url, self.cookie, self.origin = url, cookie, origin
        self.arrivals: list[dict[str, Any]] = []
        self.hello = threading.Event()
        self.error = ""
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def run(self) -> None:
        try:
            with connect(
                self.url, additional_headers={"Cookie": self.cookie, "Origin": self.origin}, open_timeout=10
            ) as ws:
                self.ws = ws
                while not self._stop.is_set():
                    try:
                        raw = ws.recv(timeout=1.0)
                    except TimeoutError:
                        continue
                    t = time.time()
                    msg = json.loads(raw)
                    if msg.get("type") == "hello":
                        self.hello.set()
                    elif msg.get("type") == "alert":
                        a = msg["alert"]
                        with self._lock:
                            self.arrivals.append(
                                {
                                    "t_ws": t,
                                    "alert_id": a["id"],
                                    "event_id": a["event_id"],
                                    "severity": a["severity"],
                                    "created_at": a["created_at"],
                                }
                            )
        except Exception as exc:  # noqa: BLE001 - reported to the operator, not swallowed
            self.error = f"{type(exc).__name__}: {exc}"

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.arrivals)

    def close(self) -> None:
        self._stop.set()


def die(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 2


def run_trial(ip: str, feed: Feed, http: httpx.Client, wait: float, src_cache: dict[int, str]) -> dict[str, Any]:
    r = sh("ip", "-n", NS, "addr", "add", f"{ip}/24", "dev", DEV)
    if r.returncode != 0:
        return {"ip": ip, "invalid": f"could not add source address: {r.stderr.strip()}"}
    atexit.register(sh, "ip", "-n", NS, "addr", "del", f"{ip}/24", "dev", DEV)
    time.sleep(0.5)  # let the kernel finish duplicate-address handling
    cmd = ["ip", "netns", "exec", NS, "nmap", "-sS", "-Pn", "-n", "-T4", "--max-retries", "1",
           "-S", ip, "-e", DEV, "-p", PORTS, VICTIM]  # fmt: skip
    t_launch = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)  # noqa: S603
    scan_process = time.time() - t_launch  # how long the scan process itself ran (part of the total below)
    if proc.returncode != 0:
        return {"ip": ip, "invalid": f"nmap exited {proc.returncode}: {(proc.stdout + proc.stderr)[-150:]}"}
    deadline = t_launch + wait
    seen = 0
    while time.time() < deadline:
        arrivals = feed.snapshot()
        for a in arrivals[seen:]:
            if a["event_id"] not in src_cache:
                ev = http.get(f"/api/events/{a['event_id']}")
                src_cache[a["event_id"]] = ev.json().get("src_ip", "") if ev.status_code == 200 else ""
        seen = len(arrivals)
        hit = e2e.match_alert(ip, t_launch, arrivals, src_cache)
        if hit:
            return e2e.trial_record(ip, t_launch, hit) | {"scan_process": scan_process}
        time.sleep(0.05)
    return e2e.trial_record(ip, t_launch, None) | {"scan_process": scan_process}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--origin", default="http://127.0.0.1:5173", help="an allowed browser origin (the WebSocket checks it)")
    ap.add_argument("--user", required=True)
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--wait", type=float, default=15.0, help="seconds to wait for each alert before calling it a miss")
    args = ap.parse_args()
    if not 1 <= args.trials <= 30:
        return die("--trials must be between 1 and 30 (one fresh source address per trial)")
    if os.geteuid() != 0:
        return die("run with sudo: it needs `ip netns exec` (the monitor itself does not need root)")
    if NS not in sh("ip", "netns", "list").stdout:
        return die("the lab is not up: run `make lab-up`")

    password = os.environ.get("NETGUARD_E2E_PASSWORD") or getpass.getpass(f"password for {args.user}: ")
    http = httpx.Client(base_url=args.api, timeout=10)
    try:
        r = http.post("/api/auth/login", json={"username": args.user, "password": password})
    except httpx.HTTPError as exc:
        return die(f"API not reachable at {args.api}: {exc}")
    if r.status_code != 200:
        return die(f"login failed ({r.status_code})")
    status = http.get("/api/monitor/status").json()
    if status.get("effective_state") != "running":
        return die(f"the monitor is not running (state: {status.get('effective_state')})")
    cookie = "; ".join(f"{c.name}={c.value}" for c in http.cookies.jar)
    feed = Feed(args.api.replace("http", "ws", 1) + "/api/ws", cookie, args.origin)
    feed.start()
    if not feed.hello.wait(10):
        return die(f"WebSocket did not say hello: {feed.error or 'timeout'}")

    src_cache: dict[int, str] = {}
    # An address with a still-open event would merge a new scan into that event and raise no alert (the
    # one-open-event-per-key rule, ADR 0013), so only addresses with no open event are used.
    open_events = http.get("/api/events", params={"is_open": "true", "limit": 200}).json()["items"]
    busy = {e["src_ip"] for e in open_events}
    free = [f"{PREFIX}{n}" for n in POOL if f"{PREFIX}{n}" not in busy]
    if len(free) < args.trials + 1:
        return die(
            f"only {len(free)} source addresses are free of open events, {args.trials + 1} are needed. "
            "Wait for the open events to close (the port_scan cooldown is 300 s) and run again."
        )
    print("warm-up trial (not counted) ...", flush=True)
    warm = run_trial(free[0], feed, http, args.wait, src_cache)
    if not warm.get("detected"):
        return die(
            "the warm-up scan raised no alert in time. The usual cause is NETGUARD_PROMISCUOUS=true missing "
            f"from .env (the monitor then sees almost none of the lab traffic). Detail: {warm}"
        )

    records: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for i in range(args.trials):
        ip = free[1 + i]
        rec = run_trial(ip, feed, http, args.wait, src_cache)
        (invalid if "invalid" in rec else records).append(rec)
        flag = "MISS" if not rec.get("detected") and "invalid" not in rec else ("INVALID" if "invalid" in rec else f"{rec['total']:.2f}s")
        print(f"  trial {i + 1:2d}/{args.trials}  {ip:15s} {flag}", flush=True)
        time.sleep(SETTLE)
    feed.close()
    if feed.error:
        print(f"NOTE: WebSocket ended with {feed.error}", file=sys.stderr)

    summary = e2e.summarise(records)
    final = http.get("/api/monitor/status").json()
    out = {
        "when": datetime.now(UTC).isoformat(),
        "host": platform.node(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "scan": f"nmap -sS -T4 --max-retries 1, ports {PORTS} ({PORTS.split('-')[1]} ports), fresh source per trial",
        "wait_s": args.wait,
        "monitor": {k: final.get(k) for k in ("interface", "version", "packets_dropped", "degraded_reasons")},
        "summary": summary,
        "invalid": invalid,
        "trials": records,
        "notes": [
            "t_launch is taken just before the nmap process is spawned; total includes nmap start-up and the scan itself",
            "created_at is the database now(), the start of the committing transaction: delivery includes the commit",
            "single lab, single victim, one machine's clock; not a statement about other networks",
        ],
    }
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / f"e2e-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(out, indent=2))
    s = summary
    print(f"\n{s['detected']}/{s['trials']} alerts received on the WebSocket ({len(invalid)} invalid trials excluded)")
    for label, key in (("scan process duration (part of total)", "scan_process_s"), ("scan start -> alert on WebSocket", "total_s"), ("scan start -> alert row", "to_alert_row_s"), ("alert row -> WebSocket", "delivery_s")):
        v = s[key]
        if v["n"]:
            print(f"  {label:34s} median {v['median']:.3f}  p95 {v['p95']:.3f}  max {v['max']:.3f} s")
    if s["negative_delivery"]:
        print(f"  {s['negative_delivery']} trial(s) had delivery < 0 (timestamp resolution), counted as reported")
    print(f"written: {path}")
    return 0 if s["detected"] == s["trials"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
