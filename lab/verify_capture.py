#!/usr/bin/env python3
"""Phase 3 gate: does the monitor's database agree with an independent capture and with what was sent?

Run (lab must be up):  sudo .venv/bin/python lab/verify_capture.py [--active]
  1. starts tcpdump on br-lab (the independent oracle)
  2. starts the real monitor as YOUR user holding only CAP_NET_RAW/CAP_NET_ADMIN
  3. generates traffic with known counts from inside the lab namespaces
  4. compares sent / tcpdump / monitor database for each flow, and discovery against nmap -sn
Uses the '<NETGUARD_DB_NAME>_test' database (must be migrated: make test-integration does it).
Writes lab/results/phase3-capture-<timestamp>.json. Exit status 0 only if every check passes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import text

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from netguard_common.config import load_settings  # noqa: E402
from netguard_common.db import make_engine  # noqa: E402

BR, SUBNET = "br-lab", "10.10.10.0/24"
VICTIM, NORMAL, ATTACKER, HOST = "10.10.10.10", "10.10.10.20", "10.10.10.30", "10.10.10.1"
PY = os.environ.get("NETGUARD_LAB_PYTHON") or str(ROOT / ".venv" / "bin" / "python")

UDP_SINK = (
    "import socket, select\n"
    "socks = []\n"
    "for p in (9001, 53):\n"
    "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', p)); socks.append(s)\n"
    "while True:\n"
    "    for s in select.select(socks, [], [], 1)[0]: s.recvfrom(2048)\n"
)
SEND_UDP = (
    "import socket\n"
    "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    f"for _ in range(300): u.sendto(b'x' * 64, ('{VICTIM}', 9001))\n"
)
SEND_TCP = (
    "import socket\n"
    "for _ in range(100):\n"
    "    s = socket.socket(); s.settimeout(3)\n"
    f"    try: s.connect(('{VICTIM}', 9002))\n"
    "    except OSError: pass\n"
    "    s.close()\n"
)
SEND_DNS = (
    "import socket\n"
    "q = b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x03lab\\x04test\\x00\\x00\\x01\\x00\\x01'\n"
    "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    f"for _ in range(50): u.sendto(q, ('{VICTIM}', 53))\n"
)


def sh(*cmd: str, **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False, **kw)  # type: ignore[call-overload]  # noqa: S603


def netns(ns: str, *cmd: str) -> subprocess.CompletedProcess[str]:
    return sh("ip", "netns", "exec", ns, *cmd)


def pcap_count(pcap: Path, expr: str) -> int:
    out = sh("tcpdump", "-nr", str(pcap), expr).stdout
    return len([ln for ln in out.splitlines() if ln.strip()])


def wait_until_quiet(seconds: float = 2.0, limit: float = 30.0) -> bool:
    """Wait until the bridge carries no IPv4 for `seconds` (interface bring-up emits IGMP/ND chatter)."""
    end = time.time() + limit
    while time.time() < end:
        try:
            subprocess.run(
                ["tcpdump", "-i", BR, "-n", "-c", "1", "-w", "/dev/null", "ip"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return True  # nothing arrived for the whole interval
    return False


def load_env(path: Path) -> dict[str, str]:
    env = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^(NETGUARD_[A-Z0-9_]+)=([^#\s]*)", line)
        if m:
            env[m.group(1)] = m.group(2)
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--active", action="store_true", help="also enable active ARP discovery")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("run with sudo (needs namespaces and tcpdump)", file=sys.stderr)
        return 2
    if sh("ip", "link", "show", BR).returncode != 0:
        print("lab is not up: run 'make lab-up' first", file=sys.stderr)
        return 2

    base = load_settings(ROOT / ".env")
    test_db = f"{base.db_name}_test"
    settings = base.model_copy(update={"db_name": test_db})
    eng = make_engine(settings, "migrator", pool_size=1)
    with eng.begin() as c:
        c.execute(
            text(
                "TRUNCATE traffic_stats_1s, connection_aggregates_1m, devices, "
                "ingest_batches, monitor_status"
            )
        )

    work = Path(tempfile.mkdtemp(prefix="ng-verify-"))
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    env = {
        **os.environ,
        **load_env(ROOT / ".env"),
        "NETGUARD_DB_NAME": test_db,
        "NETGUARD_MONITOR_INTERFACE": BR,
        "NETGUARD_AUTHORIZED_SUBNET": SUBNET,
        "NETGUARD_SPILL_DIR": str(work / "spill"),
        "NETGUARD_ACTIVE_DISCOVERY": "true" if args.active else "false",
    }
    cmd = [PY, "-m", "netguard_monitor.main", "run", "--duration", "120"]
    least_privilege = bool(uid and uid != "0")
    if least_privilege:
        shutil.chown(work, int(uid), int(gid or uid))  # type: ignore[arg-type]
        cmd = [
            "setpriv",
            "--reuid",
            uid,
            "--regid",
            gid or uid,
            "--init-groups",  # type: ignore[list-item]
            "--inh-caps=+net_raw,+net_admin",
            "--ambient-caps=+net_raw,+net_admin",
            "--bounding-set=-all,+net_raw,+net_admin",
            "--",
            *cmd,
        ]
    else:
        print("NOTE: not invoked via sudo from a normal user; the monitor will run as root.")

    if not wait_until_quiet():
        print("the lab bridge never went quiet; cannot compare windows fairly", file=sys.stderr)
        return 2
    pcap = work / "oracle.pcap"
    tcpdump: subprocess.Popen[bytes] | None = None
    monitor = subprocess.Popen(
        cmd, env=env, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )  # noqa: S603
    sink = subprocess.Popen(["ip", "netns", "exec", "ng-victim", PY, "-c", UDP_SINK])  # noqa: S603, S607
    results: list[dict[str, object]] = []
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            with eng.connect() as c:
                row = c.execute(text("SELECT state FROM monitor_status")).first()
            if row and row[0] == "running":
                break
            if monitor.poll() is not None:
                print(monitor.stdout.read() if monitor.stdout else "", file=sys.stderr)
                return 2
            time.sleep(0.3)
        else:
            print("monitor did not report 'running' within 20 s", file=sys.stderr)
            return 2
        # The oracle starts only now, so its window is strictly inside the monitor's capture window.
        tcpdump = subprocess.Popen(
            ["tcpdump", "-i", BR, "-n", "-U", "-w", str(pcap), "ip or arp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5 if args.active else 0.8)

        netns("ng-attacker", PY, "-c", SEND_UDP)
        netns("ng-attacker", PY, "-c", SEND_TCP)
        netns("ng-normal", PY, "-c", SEND_DNS)
        netns("ng-normal", "ping", "-c", "20", "-i", "0.01", "-W", "1", VICTIM)
        nmap = sh("nmap", "-sn", "-n", SUBNET) if shutil.which("nmap") else None
        time.sleep(2.5)
        tcpdump.send_signal(
            signal.SIGINT
        )  # oracle stops first: its window nests inside the monitor's
        tcpdump.wait(timeout=10)
    finally:
        if tcpdump is not None and tcpdump.poll() is None:
            tcpdump.kill()
        sink.terminate()
        monitor.send_signal(signal.SIGTERM)
        try:
            log = monitor.communicate(timeout=40)[0]
        except subprocess.TimeoutExpired:
            monitor.kill()
            log = "monitor did not stop within 40 s"

    def db_flow(where: str) -> tuple[int, int]:
        with eng.connect() as c:
            r = c.execute(
                text(
                    "SELECT coalesce(sum(packets),0), coalesce(sum(syn_count),0) "
                    f"FROM connection_aggregates_1m WHERE {where}"
                )
            ).one()
        return int(r[0]), int(r[1])

    def check(name: str, sent: int | None, flt: str, where: str, field: int = 0) -> None:
        oracle = pcap_count(pcap, flt)
        mon = db_flow(where)[field]
        ok = oracle == mon and (sent is None or sent == oracle)
        results.append({"check": name, "sent": sent, "tcpdump": oracle, "monitor": mon, "pass": ok})

    a, v, n = f"host(src_ip)='{ATTACKER}'", f"host(dst_ip)='{VICTIM}'", f"host(src_ip)='{NORMAL}'"
    check(
        "UDP attacker->victim:9001",
        300,
        f"udp and src {ATTACKER} and dst {VICTIM} and dst port 9001",
        f"{a} AND {v} AND transport='udp' AND dst_port=9001",
    )
    check(
        "TCP SYN attacker->victim:9002",
        100,
        f"tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and src {ATTACKER} and dst port 9002",
        f"{a} AND {v} AND transport='tcp' AND dst_port=9002",
        field=1,
    )
    check(
        "TCP attacker->victim:9002 (all packets)",
        None,
        f"tcp and src {ATTACKER} and dst {VICTIM}",
        f"{a} AND {v} AND transport='tcp'",
    )
    check(
        "TCP RST victim->attacker",
        100,
        f"tcp and src {VICTIM} and dst {ATTACKER}",
        f"host(src_ip)='{VICTIM}' AND host(dst_ip)='{ATTACKER}' AND transport='tcp'",
    )
    check(
        "DNS normal->victim:53",
        50,
        f"udp and src {NORMAL} and dst {VICTIM} and dst port 53",
        f"{n} AND {v} AND transport='udp' AND dst_port=53 AND app_protocol='dns'",
    )
    check(
        "ICMP echo normal->victim",
        20,
        f"icmp[icmptype] = icmp-echo and src {NORMAL}",
        f"{n} AND {v} AND transport='icmp'",
    )
    check(
        "ICMP echo reply victim->normal",
        20,
        f"icmp[icmptype] = icmp-echoreply and src {VICTIM}",
        f"host(src_ip)='{VICTIM}' AND host(dst_ip)='{NORMAL}' AND transport='icmp'",
    )
    with eng.connect() as c:
        total_1s = int(
            c.execute(
                text(
                    "SELECT coalesce(sum(packets),0) FROM traffic_stats_1s WHERE protocol <> 'other'"
                )
            ).scalar_one()
        )
        total_1m = int(
            c.execute(
                text(
                    "SELECT coalesce(sum(packets),0) FROM connection_aggregates_1m WHERE transport <> 'other'"
                )
            ).scalar_one()
        )
        other_db = int(
            c.execute(
                text(
                    "SELECT coalesce(sum(packets),0) FROM traffic_stats_1s WHERE protocol = 'other'"
                )
            ).scalar_one()
        )
        hb = c.execute(
            text("SELECT state, packets_captured, packets_dropped FROM monitor_status")
        ).one()
        devices = {str(r[0]) for r in c.execute(text("SELECT host(ip) FROM devices"))}
    oracle_all = pcap_count(pcap, f"ip and net {SUBNET} and (tcp or udp or icmp)")
    other_oracle = pcap_count(pcap, f"ip and net {SUBNET} and not (tcp or udp or icmp)")
    results.append(
        {
            "check": "tcp/udp/icmp packets, all flows (per-second table)",
            "sent": None,
            "tcpdump": oracle_all,
            "monitor": total_1s,
            "pass": oracle_all == total_1s,
        }
    )
    results.append(
        {
            "check": "tcp/udp/icmp packets, all flows (per-flow table)",
            "sent": None,
            "tcpdump": oracle_all,
            "monitor": total_1m,
            "pass": oracle_all == total_1m,
        }
    )
    print(
        f"background (non-tcp/udp/icmp, e.g. IGMP) seen: tcpdump={other_oracle} monitor={other_db} - reported, not part of the workload totals"
    )
    results.append(
        {
            "check": "no packets dropped; clean shutdown",
            "sent": None,
            "tcpdump": 0,
            "monitor": int(hb[2]),
            "pass": hb[2] == 0 and hb[0] == "stopped",
        }
    )

    expected = {HOST, VICTIM, NORMAL, ATTACKER}
    nmap_hosts = (
        set(re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", nmap.stdout))
        if nmap
        else set()
    )
    results.append(
        {
            "check": f"devices vs nmap -sn ({'active' if args.active else 'passive'} discovery)",
            "sent": sorted(expected),
            "tcpdump": sorted(nmap_hosts) if nmap else "nmap not installed",
            "monitor": sorted(devices),
            "pass": devices == expected and (nmap is None or nmap_hosts == expected),
        }
    )

    width = max(len(str(r["check"])) for r in results)
    print(f"\n{'check':<{width}}  {'sent':>6}  {'tcpdump':>8}  {'monitor':>8}  result")
    for r in results:
        s = "-" if r["sent"] is None else r["sent"]
        if isinstance(r["monitor"], list):
            print(
                f"{r['check']:<{width}}\n    expected={r['sent']}\n    nmap    ={r['tcpdump']}\n    monitor ={r['monitor']}   {'PASS' if r['pass'] else 'FAIL'}"
            )
        else:
            print(
                f"{r['check']:<{width}}  {s!s:>6}  {r['tcpdump']!s:>8}  {r['monitor']!s:>8}  {'PASS' if r['pass'] else 'FAIL'}"
            )
    out = ROOT / "lab" / "results" / f"phase3-capture-{time.strftime('%Y%m%dT%H%M%S')}.json"
    out.write_text(
        json.dumps(
            {
                "least_privilege": least_privilege,
                "active_discovery": args.active,
                "results": results,
                "heartbeat": list(map(str, hb)),
                "monitor_log_tail": log.splitlines()[-6:],
            },
            indent=2,
            default=str,
        )
    )
    ok = all(bool(r["pass"]) for r in results)
    print(
        f"\n{'ALL CHECKS PASSED' if ok else 'FAILURES PRESENT'}  (least-privilege monitor: {least_privilege}; evidence: {out.name})"
    )
    if not ok and pcap.exists():  # keep the oracle capture so a mismatch can be analysed
        kept = out.with_suffix(".pcap")
        shutil.copy(pcap, kept)
        print(f"oracle capture kept: {kept.name}")
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
