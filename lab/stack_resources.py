#!/usr/bin/env python3
"""Phase 7: what the WHOLE NetGuard stack costs (monitor + API + PostgreSQL), and how fast the API answers.

    sudo -E .venv/bin/python lab/stack_resources.py --user <admin> [--phase-seconds 60]

Needs the same running system as lab/e2e_latency.py (lab up, monitor with NETGUARD_PROMISCUOUS=true, API).
Password: prompted, or NETGUARD_E2E_PASSWORD for unattended runs. Nothing is started or stopped by it.

Three measured phases, each --phase-seconds long, CPU and memory sampled once a second per part:
  idle     no dashboard open, no lab traffic
  clients  N simulated dashboard clients (a WebSocket plus the dashboard's own polling pattern)
  load     the clients, plus UDP at --mbps MB/s from ng-attacker through the lab bridge
Then API response times, request by request, for the endpoints the dashboard uses: once at idle and once
while the same UDP load runs. Row counts of the main tables are recorded because response times depend on them.

CPU is percent of ONE core (150 = one and a half cores). Memory is PSS (each shared page divided among the
processes that share it, so the PostgreSQL total is not inflated) when readable, else RSS; the figure used is
named in the output. Only NetGuard's own processes are counted (lab/evalkit/stack.py). Writes
lab/results/stack-<ts>.json. Everything measured here is one machine; nothing is extrapolated.
"""

from __future__ import annotations

import argparse
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
import psutil
from sqlalchemy import text
from websockets.sync.client import connect

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from evalkit import stack  # noqa: E402
from verify_capture import PY, ROOT  # noqa: E402
from verify_detection import UDP_SINK  # noqa: E402

from netguard_common.config import load_settings  # noqa: E402
from netguard_common.db import make_engine  # noqa: E402

RESULTS = LAB / "results"
DRIVER = LAB / "evalkit" / "driver.py"
NS, SRC = "ng-attacker", "10.10.10.30"
TABLES = ("traffic_stats_1s", "connection_aggregates_1m", "devices", "security_events", "alerts", "audit_logs")
ENDPOINTS = [
    "/api/overview",
    "/api/monitor/status",
    "/api/traffic/series?bucket=5&from={t15}&to={now}",
    "/api/traffic/protocols?from={t60}&to={now}",
    "/api/traffic/top-talkers?from={t60}&to={now}&by=bytes&limit=8",
    "/api/devices?limit=200",
    "/api/events?limit=25",
    "/api/alerts?limit=30",
    "/api/rules",
]


# The widest ranges the API allows (lab/../backend/app/api/traffic.py): the heaviest queries it can be asked.
WORST = [
    "/api/traffic/series?bucket=60&from={t24h}&to={now}",
    "/api/traffic/protocols?from={t24h}&to={now}",
    "/api/traffic/top-talkers?from={t30d}&to={now}&by=bytes&limit=8",
]


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Sampler(threading.Thread):
    """Once a second: CPU % and memory of each part of the stack, summed over its processes."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.stop_flag = threading.Event()
        self.cpu: dict[str, list[float]] = {g: [] for g in stack.GROUPS}
        self.mem: dict[str, list[float]] = {g: [] for g in stack.GROUPS}
        self.mem_kind = "pss"
        self._procs: dict[int, psutil.Process] = {}

    def _scan(self) -> dict[int, tuple[psutil.Process, str]]:
        found: dict[int, tuple[psutil.Process, str]] = {}
        for p in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                g = stack.classify(p.info["name"] or "", p.info["cmdline"] or [], p.info["username"] or "")
            except psutil.Error:
                continue
            if g:
                found[p.pid] = (self._procs.get(p.pid) or p, g)
        return found

    def _mem(self, p: psutil.Process) -> float:
        if self.mem_kind == "pss":
            try:
                return p.memory_full_info().pss / 1e6
            except (psutil.AccessDenied, AttributeError):
                self.mem_kind = "rss"
        return p.memory_info().rss / 1e6

    def run(self) -> None:
        procs = self._scan()
        for pid, (p, _) in procs.items():
            self._procs[pid] = p
            p.cpu_percent(None)
        while not self.stop_flag.wait(1.0):
            procs = self._scan()
            cpu = dict.fromkeys(stack.GROUPS, 0.0)
            mem = dict.fromkeys(stack.GROUPS, 0.0)
            seen = dict.fromkeys(stack.GROUPS, False)
            for pid, (p, g) in procs.items():
                try:
                    first = pid not in self._procs
                    self._procs[pid] = p
                    c = p.cpu_percent(None)
                    cpu[g] += 0.0 if first else c
                    mem[g] += self._mem(p)
                    seen[g] = True
                except psutil.Error:
                    continue
            for g in stack.GROUPS:
                if seen[g]:
                    self.cpu[g].append(cpu[g])
                    self.mem[g].append(mem[g])

    def process_counts(self) -> dict[str, int]:
        out = dict.fromkeys(stack.GROUPS, 0)
        for _, g in self._scan().values():
            out[g] += 1
        return out

    def mark(self) -> dict[str, int]:
        return {g: len(self.cpu[g]) for g in stack.GROUPS}

    def since(self, mark: dict[str, int]) -> dict[str, Any]:
        return {g: stack.summarise(self.cpu[g][mark[g] :], self.mem[g][mark[g] :]) for g in stack.GROUPS}


class Clients:
    """N simulated dashboard clients: each holds the WebSocket and polls like the Overview page does
    (overview and traffic series every 10 s; protocols, top talkers and devices every 30 s)."""

    def __init__(self, api: str, cookie: str, origin: str, n: int) -> None:
        self.api, self.cookie, self.origin, self.n = api, cookie, origin, n
        self.stop = threading.Event()
        self.threads: list[threading.Thread] = []
        self.errors: list[str] = []
        self.requests = 0
        self.ws_messages = 0

    def _poll(self, k: int) -> None:
        h = {"Cookie": self.cookie}
        with httpx.Client(base_url=self.api, headers=h, timeout=15) as c:
            tick = 0
            while not self.stop.is_set():
                now = time.time()
                urls = ["/api/overview", f"/api/traffic/series?bucket=5&from={iso(now - 900)}&to={iso(now)}"]
                if tick % 3 == 0:
                    urls += [
                        f"/api/traffic/protocols?from={iso(now - 3600)}&to={iso(now)}",
                        f"/api/traffic/top-talkers?from={iso(now - 3600)}&to={iso(now)}&by=bytes&limit=8",
                        "/api/devices?limit=200",
                    ]
                for u in urls:
                    r = c.get(u)
                    self.requests += 1
                    if r.status_code != 200:
                        self.errors.append(f"{u} -> {r.status_code}")
                tick += 1
                self.stop.wait(10.0 + k * 0.37)  # staggered so the clients do not fire in lockstep

    def _ws(self) -> None:
        try:
            with connect(
                self.api.replace("http", "ws", 1) + "/api/ws",
                additional_headers={"Cookie": self.cookie, "Origin": self.origin},
                open_timeout=10,
            ) as ws:
                while not self.stop.is_set():
                    try:
                        ws.recv(timeout=1.0)
                        self.ws_messages += 1
                    except TimeoutError:
                        continue
        except Exception as exc:  # noqa: BLE001 - recorded, and fails the run's validity check
            self.errors.append(f"websocket: {type(exc).__name__}: {exc}")

    def start(self) -> None:
        for k in range(self.n):
            for fn, args in ((self._poll, (k,)), (self._ws, ())):
                t = threading.Thread(target=fn, args=args, daemon=True)
                t.start()
                self.threads.append(t)

    def close(self) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(timeout=20)


def start_load(seconds: float, mbps: float) -> subprocess.Popen[str]:
    params = json.dumps({"mbps": mbps, "seconds": seconds})
    return subprocess.Popen(  # noqa: S603
        ["ip", "netns", "exec", NS, PY, str(DRIVER), "udp_rate", params, SRC],
        stdout=subprocess.PIPE,
        text=True,
    )


def finish_load(p: subprocess.Popen[str]) -> dict[str, Any]:
    out, _ = p.communicate(timeout=300)
    return json.loads(out.strip().splitlines()[-1]) if p.returncode == 0 and out.strip() else {"error": p.returncode}


def measure_api(c: httpx.Client, per_endpoint: int, endpoints: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for tmpl in endpoints or ENDPOINTS:
        times, bad = [], 0
        for _ in range(per_endpoint):
            now = time.time()
            url = tmpl.format(
                t15=iso(now - 900), t60=iso(now - 3600), t24h=iso(now - 86400), t30d=iso(now - 30 * 86400), now=iso(now)
            )
            t0 = time.perf_counter()
            r = c.get(url)
            times.append(time.perf_counter() - t0)
            bad += r.status_code != 200
        result[tmpl.split("?")[0]] = stack.latency_ms(times) | {"non_200": bad}
    return result


def row_counts(db_name: str | None) -> dict[str, Any]:
    s = load_settings(ROOT / ".env")
    if db_name:
        s = s.model_copy(update={"db_name": db_name})
    eng = make_engine(s, "migrator", pool_size=1)
    with eng.connect() as c:
        rows: dict[str, Any] = {"database": s.db_name}
        rows.update({t: c.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in TABLES})  # noqa: S608 - fixed list
    return rows


def api_only(args: argparse.Namespace, http: httpx.Client) -> int:
    """Idle response times against whatever database the API serves, with that database's row counts."""
    print("API response times, idle (api-only) ...", flush=True)
    resp = measure_api(http, args.requests)
    print("widest allowed ranges (24 h series and protocols, 30 d top talkers) ...", flush=True)
    worst = measure_api(http, max(10, args.requests // 2), WORST)
    rows = row_counts(args.db_name)
    out = {
        "when": datetime.now(UTC).isoformat(),
        "host": platform.node(),
        "mode": "api-only",
        "requests_per_endpoint": args.requests,
        "row_counts": rows,
        "api_response_idle": resp,
        "api_response_widest_ranges": worst,
        "notes": ["idle: no lab traffic generated by this script; single machine"],
    }
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / f"stack-apionly-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(out, indent=2))
    print(f"rows in {rows['database']}: { {k: v for k, v in rows.items() if k != 'database'} }")
    print("API response times, ms (p50 / p95 / max)")
    for ep, v in resp.items():
        print(f"  {ep:28s} {v['p50']:7.1f} {v['p95']:7.1f} {v['max']:7.1f}   non-200: {v['non_200']}")
    print("widest allowed ranges")
    for ep, v in worst.items():
        print(f"  {ep:28s} {v['p50']:7.1f} {v['p95']:7.1f} {v['max']:7.1f}   non-200: {v['non_200']}")
    print(f"written: {path}")
    return 0


def main() -> int:  # noqa: C901, PLR0912, PLR0915
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--origin", default="http://127.0.0.1:5173")
    ap.add_argument("--user", required=True)
    ap.add_argument("--phase-seconds", type=int, default=60)
    ap.add_argument("--clients", type=int, default=5)
    ap.add_argument("--mbps", type=float, default=8.0, help="UDP load, MB/s on the wire (the Kali sweep sustained 32)")
    ap.add_argument("--requests", type=int, default=50, help="requests per endpoint for the response-time test")
    ap.add_argument("--db-name", default=None, help="the database the API serves (for the row counts); default: .env")
    ap.add_argument(
        "--api-only",
        action="store_true",
        help="only the idle response-time test and row counts (no monitor, lab or load needed): "
        "point --api at an API serving a large database, e.g. the evaluation's netguard_test",
    )
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("ERROR: run with sudo (needs `ip netns exec` and to read other users' process memory)", file=sys.stderr)
        return 2
    if NS not in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, check=False).stdout:  # noqa: S603, S607
        print("ERROR: the lab is not up: run `make lab-up`", file=sys.stderr)
        return 2
    password = os.environ.get("NETGUARD_E2E_PASSWORD") or getpass.getpass(f"password for {args.user}: ")
    http = httpx.Client(base_url=args.api, timeout=15)
    if http.post("/api/auth/login", json={"username": args.user, "password": password}).status_code != 200:
        print("ERROR: login failed", file=sys.stderr)
        return 2
    if args.api_only:
        return api_only(args, http)
    st = http.get("/api/monitor/status").json()
    if st.get("effective_state") != "running":
        print(f"ERROR: the monitor is not running (state: {st.get('effective_state')})", file=sys.stderr)
        return 2
    cookie = "; ".join(f"{c.name}={c.value}" for c in http.cookies.jar)

    sink = subprocess.Popen(["ip", "netns", "exec", "ng-victim", PY, "-c", UDP_SINK])  # noqa: S603, S607
    sampler = Sampler()
    sampler.start()
    time.sleep(3)
    out: dict[str, Any] = {"phases": {}, "api_response": {}}
    clients: Clients | None = None
    cap0 = int(st.get("packets_captured") or 0)
    drop0 = int(st.get("packets_dropped") or 0)
    try:
        if not sampler.cpu["monitor"] or not sampler.cpu["api"] or not sampler.cpu["postgres"]:
            print("ERROR: could not find all of monitor, API and PostgreSQL processes", file=sys.stderr)
            return 2
        counts = sampler.process_counts()
        if counts["monitor"] != 1 or counts["api"] != 1:
            print(
                f"ERROR: expected exactly one monitor and one API process, found {counts['monitor']} and "
                f"{counts['api']}. A second copy (for example an API on another port) would be counted as "
                "NetGuard's own cost and inflate the figures: stop it and run again.",
                file=sys.stderr,
            )
            return 2
        print(f"phase 1/3 idle ({args.phase_seconds} s) ...", flush=True)
        m = sampler.mark()
        time.sleep(args.phase_seconds)
        out["phases"]["idle"] = sampler.since(m)

        clients = Clients(args.api, cookie, args.origin, args.clients)
        clients.start()
        time.sleep(3)
        print(f"phase 2/3 {args.clients} dashboard clients ({args.phase_seconds} s) ...", flush=True)
        m = sampler.mark()
        time.sleep(args.phase_seconds)
        out["phases"]["clients"] = sampler.since(m)

        print(f"phase 3/3 clients + UDP {args.mbps} MB/s ({args.phase_seconds} s) ...", flush=True)
        m = sampler.mark()
        load = start_load(args.phase_seconds, args.mbps)
        time.sleep(args.phase_seconds + 1)
        out["load_driver"] = finish_load(load)
        out["phases"]["load"] = sampler.since(m)
        out["clients"] = {
            "count": args.clients,
            "requests": clients.requests,
            "ws_messages": clients.ws_messages,
            "errors": clients.errors[:10],
        }
        clients.close()
        clients = None

        print("API response times, idle ...", flush=True)
        out["api_response"]["idle"] = measure_api(http, args.requests)
        print(f"API response times, under UDP {args.mbps} MB/s ...", flush=True)
        load = start_load(max(20, args.requests // 2), args.mbps)
        time.sleep(1)
        out["api_response"]["under_load"] = measure_api(http, args.requests)
        out["api_response"]["load_driver"] = finish_load(load)
    finally:
        if clients:
            clients.close()
        sampler.stop_flag.set()
        sink.terminate()

    st2 = http.get("/api/monitor/status").json()
    rows = row_counts(args.db_name)
    out.update(
        when=datetime.now(UTC).isoformat(),
        host=platform.node(),
        kernel=platform.release(),
        python=platform.python_version(),
        cpus=psutil.cpu_count(),
        ram_mb=round(psutil.virtual_memory().total / 1e6),
        memory_figure=sampler.mem_kind.upper(),
        udp_mbps=args.mbps,
        phase_seconds=args.phase_seconds,
        packets_captured_during_run=int(st2.get("packets_captured") or 0) - cap0,
        packets_dropped_during_run=int(st2.get("packets_dropped") or 0) - drop0,
        row_counts=rows,
        notes=[
            "CPU is percent of one core; memory is PSS when readable, else RSS (see memory_figure)",
            "idle = no dashboard and no lab traffic; the monitor still captures whatever reaches the bridge",
            "single machine, single lab; not a statement about other networks or other hardware",
        ],
    )
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / f"stack-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(out, indent=2))

    print(f"\n{platform.node()}: {out['cpus']} CPUs, {out['ram_mb']} MB RAM; memory = {out['memory_figure']}")
    print("CPU % of one core (median / p95 / max) and memory MB (median / max)")
    for ph, per in out["phases"].items():
        print(f"  {ph}")
        for g, v in per.items():
            if v.get("samples"):
                print(
                    f"    {g:9s} cpu {v['cpu_median']:6.1f} / {v['cpu_p95']:6.1f} / {v['cpu_max']:6.1f}   "
                    f"mem {v['mem_mb_median']:6.1f} / {v['mem_mb_max']:6.1f}"
                )
    print(f"packets captured during the run {out['packets_captured_during_run']}, dropped {out['packets_dropped_during_run']}")
    print("API response times, ms (p50 / p95 / max):  idle  |  under load")
    for ep, v in out["api_response"]["idle"].items():
        w = out["api_response"]["under_load"][ep]
        print(f"  {ep:28s} {v['p50']:7.1f} {v['p95']:7.1f} {v['max']:7.1f}  | {w['p50']:7.1f} {w['p95']:7.1f} {w['max']:7.1f}")
    print(f"rows: {rows}")
    if out["clients"]["errors"]:
        print(f"WARNING: client errors: {out['clients']['errors']}", file=sys.stderr)
    print(f"written: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
