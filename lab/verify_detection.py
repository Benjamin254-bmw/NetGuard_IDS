#!/usr/bin/env python3
"""Phase 4A demonstration: do all five detection rules fire on REAL lab traffic, and only then?

Run (lab must be up):  sudo .venv/bin/python lab/verify_detection.py [--standin-auth]

  1. starts the real monitor (as YOUR user with only CAP_NET_RAW/CAP_NET_ADMIN when run via sudo)
  2. benign phase from ng-normal (HTTP-like connections, DNS lookups, UDP, ping): expects ZERO events
  3. lowers the abnormal_traffic threshold THROUGH THE DATABASE (as the api role) and waits for the
     running monitor to pick it up (rule version 2)
  4. attack phase from ng-attacker with real tools: nmap -sS port scan, a connection flood, a DNS
     burst with an over-long label, a UDP volume burst, and real failed SSH logins against a real
     sshd in ng-victim (or --standin-auth: lines appended to the auth log, labelled as such)
  5. checks the database against what was actually sent and against an independent tcpdump capture:
     exactly the 7 expected events (one per dedup key), alerts, escalation, rule versions, latency,
     no dropped packets, nothing attributed to the benign host
Every scenario command's exit status and timing is recorded, so an attack that silently failed to
run cannot be mistaken for "no detection". Evidence: lab/results/phase4a-detection-<ts>.json.
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
from pathlib import Path
from typing import Any

from sqlalchemy import text

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from verify_capture import (  # noqa: E402
    ATTACKER,
    BR,
    NORMAL,
    PY,
    ROOT,
    SUBNET,
    VICTIM,
    lab_extra_addresses,
    load_env,
    pcap_count,
    sh,
    wait_until_quiet,
)

from netguard_common.config import load_settings  # noqa: E402
from netguard_common.db import make_engine  # noqa: E402
from netguard_monitor.ids.logsource import parse_auth_line  # noqa: E402

LATENCY_LIMIT = 3.0
# sshpass gives up after one wrong answer, so each attempt is about one failed login; the
# auth_failures threshold is 5. NETGUARD_LAB_SSH_ATTEMPTS lets a test lower it (negative control).
SSH_ATTEMPTS = int(os.environ.get("NETGUARD_LAB_SSH_ATTEMPTS", "6"))
SCAN_PORTS = "1-1000"
EXPECTED_KEYS = {
    f"port_scan|{ATTACKER}|{VICTIM}",
    f"excessive_connections|{ATTACKER}|{VICTIM}|9002",
    f"abnormal_traffic|{ATTACKER}",
    f"suspicious_dns|{ATTACKER}|query_rate",
    f"suspicious_dns|{ATTACKER}|distinct_names",
    f"suspicious_dns|{ATTACKER}|long_label",
    f"auth_failures|{ATTACKER}",
}

TCP_SINK = (  # HTTP-ish responder on :8080 (benign traffic) -- accepts, answers, closes
    "import socket, threading\n"
    "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    "s.bind(('0.0.0.0', 8080)); s.listen(128)\n"
    "def h(c):\n"
    "    try:\n"
    "        c.recv(1024); c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok')\n"
    "    finally: c.close()\n"
    "while True:\n"
    "    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()\n"
)
UDP_SINK = (
    "import socket, select\n"
    "socks = []\n"
    "for p in (9001, 53):\n"
    "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', p)); socks.append(s)\n"
    "while True:\n"
    "    for s in select.select(socks, [], [], 1)[0]: s.recvfrom(2048)\n"
)
BENIGN_HTTP = (
    "import socket\n"
    "for _ in range(20):\n"
    f"    s = socket.create_connection(('{VICTIM}', 8080), timeout=3)\n"
    "    s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); s.recv(100); s.close()\n"
)
BENIGN_DNS_UDP = (
    "import socket\n"
    "def q(name):\n"
    "    body = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.'))\n"
    "    return b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + body + b'\\x00\\x00\\x01\\x00\\x01'\n"
    "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    f"for i in range(10): u.sendto(q(f'www{{i}}.example.org'), ('{VICTIM}', 53))\n"
    f"for _ in range(30): u.sendto(b'x' * 64, ('{VICTIM}', 9001))\n"
)
FLOOD = (
    "import socket\n"
    "for _ in range(150):\n"
    "    s = socket.socket(); s.settimeout(3)\n"
    f"    try: s.connect(('{VICTIM}', 9002))\n"
    "    except OSError: pass\n"
    "    s.close()\n"
)
DNS_BURST = (
    "import socket\n"
    "def q(name):\n"
    "    body = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.'))\n"
    "    return b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + body + b'\\x00\\x00\\x01\\x00\\x01'\n"
    "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    f"for i in range(120): u.sendto(q(f'host{{i}}.lab.test'), ('{VICTIM}', 53))\n"
    f"u.sendto(q('{'a' * 60}.lab.test'), ('{VICTIM}', 53))\n"
)
UDP_VOLUME = (  # sustained ~4.2 MB/s for 5 s (~21 MB): ~2.1 MB/s over the window, above 1 MB/s
    "import socket, time\n"
    "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "t0 = time.time()\n"
    "for i in range(15000):\n"
    f"    u.sendto(b'z' * 1400, ('{VICTIM}', 9001))\n"
    "    if i % 100 == 99:\n"
    "        d = t0 + (i + 1) / 3000 - time.time()\n"
    "        if d > 0: time.sleep(d)\n"
)
STANDIN_LINE = (
    f"Nov  8 12:00:01 ng-victim sshd[1]: Failed password for root from {ATTACKER} port 40000 ssh2\n"
)


SSHD_NOTES: dict[str, Any] = {}


class Scenario:
    """Runs and records every attack/benign command: exit status, duration and output tail."""

    def __init__(self) -> None:
        self.log: list[dict[str, Any]] = []

    def run(
        self, label: str, ns: str, *cmd: str, timeout: float = 120
    ) -> subprocess.CompletedProcess[str]:
        t0 = time.time()
        try:
            r = subprocess.run(  # noqa: S603
                ["ip", "netns", "exec", ns, *cmd],  # noqa: S607
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
            rc, out = r.returncode, (r.stdout + r.stderr)[-300:]
        except subprocess.TimeoutExpired:
            r = subprocess.CompletedProcess(cmd, 124, "", "timeout")
            rc, out = 124, "timeout"
        dt = round(time.time() - t0, 2)
        self.log.append({"label": label, "ns": ns, "rc": rc, "seconds": dt, "tail": out.strip()})
        print(f"  [{ns}] {label}: exit={rc} ({dt}s)")
        return r


def start_sshd(work: Path, auth_log: Path) -> subprocess.Popen[bytes] | str:
    """A real sshd inside ng-victim, password auth only, logging to the monitored auth log."""
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd) or not shutil.which("sshpass") or not shutil.which("ssh-keygen"):
        return "sshd/sshpass/ssh-keygen not installed"
    os.makedirs("/run/sshd", exist_ok=True)
    key = work / "host_ed25519"
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    conf = work / "sshd_config"
    base = (
        f"HostKey {key}\nListenAddress {VICTIM}\nPort 22\nUsePAM no\nPasswordAuthentication yes\n"
        "PubkeyAuthentication no\nPermitRootLogin yes\nMaxAuthTries 6\nLoginGraceTime 20\n"
        f"PidFile {work / 'sshd.pid'}\nLogLevel INFO\n"
    )
    # OpenSSH >= 9.8 refuses a source after a few failed logins (PerSourcePenalties, on by default).
    # That is a good production default, but in this demo it would stop the attacker's later attempts
    # before sshd logs them, leaving the IDS fewer failures than its threshold. Switch it off for the
    # lab sshd only, if this OpenSSH knows the option (older versions do not and need no change).
    conf.write_text(base + "PerSourcePenalties no\n")
    if (
        subprocess.run([sshd, "-t", "-f", str(conf)], capture_output=True, check=False).returncode
        == 0
    ):  # noqa: S603
        SSHD_NOTES["penalties_disabled"] = True
    else:
        conf.write_text(base)
        SSHD_NOTES["penalties_disabled"] = False
    proc = subprocess.Popen(  # noqa: S603
        [
            "ip",
            "netns",
            "exec",
            "ng-victim",
            sshd,
            "-D",
            "-e",
            "-f",
            str(conf),
            "-E",
            str(auth_log),
        ],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    if proc.poll() is not None:
        return "sshd exited at start-up"
    return proc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--standin-auth",
        action="store_true",
        help="append failed-login lines to the auth log instead of using a real sshd",
    )
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("run with sudo (needs namespaces, tcpdump, nmap)", file=sys.stderr)
        return 2
    if sh("ip", "link", "show", BR).returncode != 0:
        print("lab is not up: run 'make lab-up' first", file=sys.stderr)
        return 2
    extra = lab_extra_addresses()
    if extra:
        print(
            f"the lab has {len(extra)} extra addresses (left by an evaluation run?), e.g. {extra[:3]}.\n"
            "run 'make lab-down && make lab-up' for a clean lab",
            file=sys.stderr,
        )
        return 2
    for tool in ("nmap", "tcpdump"):
        if not shutil.which(tool):
            print(f"required tool missing: {tool}", file=sys.stderr)
            return 2

    base = load_settings(ROOT / ".env")
    test_db = f"{base.db_name}_test"
    settings = base.model_copy(update={"db_name": test_db})
    mig = make_engine(settings, "migrator", pool_size=1)
    api = make_engine(settings, "api", pool_size=1)
    with mig.begin() as c:
        c.execute(
            text(
                "TRUNCATE alerts, security_events, detection_rule_versions, detection_rules, "
                "traffic_stats_1s, connection_aggregates_1m, devices, ingest_batches, "
                "monitor_status RESTART IDENTITY CASCADE"
            )
        )

    work = Path(tempfile.mkdtemp(prefix="ng-detect-"))
    auth_log = work / "auth.log"
    auth_log.write_text("")
    os.chmod(work, 0o755)  # noqa: S103 - the unprivileged monitor must traverse it
    os.chmod(auth_log, 0o644)
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    least_privilege = bool(uid and uid != "0")
    env = {
        **os.environ,
        **load_env(ROOT / ".env"),
        "NETGUARD_DB_NAME": test_db,
        "NETGUARD_MONITOR_INTERFACE": BR,
        "NETGUARD_AUTHORIZED_SUBNET": SUBNET,
        "NETGUARD_SPILL_DIR": str(work / "spill"),
        "NETGUARD_AUTH_LOG_PATH": str(auth_log),
        "NETGUARD_RULES_RELOAD_SECONDS": "2",
        "NETGUARD_ACTIVE_DISCOVERY": "false",
        # Lab frames cross a bridge and are not addressed to it: the monitor itself must hold the
        # interface promiscuous. (Earlier versions of this script passed only because the tcpdump
        # oracle switched promiscuous mode on as a side effect.)
        "NETGUARD_PROMISCUOUS": os.environ.get("NETGUARD_LAB_PROMISCUOUS", "true"),
    }
    cmd = [PY, "-m", "netguard_monitor.main", "run", "--duration", "300"]
    if least_privilege:
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
    else:
        print("NOTE: not run via sudo from a normal user; the monitor will run as root.")

    if not wait_until_quiet():
        print("the lab bridge never went quiet", file=sys.stderr)
        return 2

    sc = Scenario()
    monitor_log = work / "monitor.log"
    pcap = work / "oracle.pcap"
    procs: list[subprocess.Popen[bytes]] = []
    tcpdump: subprocess.Popen[bytes] | None = None
    sshd: subprocess.Popen[bytes] | str | None = None
    problems: list[str] = []
    checks: list[dict[str, Any]] = []
    t_start = time.time()

    def count_events() -> int:
        with mig.connect() as c:
            return int(c.execute(text("SELECT count(*) FROM security_events")).scalar_one())

    with open(monitor_log, "w") as mlog:
        monitor = subprocess.Popen(cmd, env=env, cwd=work, stdout=mlog, stderr=subprocess.STDOUT)  # noqa: S603
        try:
            for ns, code in (("ng-victim", TCP_SINK), ("ng-victim", UDP_SINK)):
                procs.append(subprocess.Popen(["ip", "netns", "exec", ns, PY, "-c", code]))  # noqa: S603, S607
            if not args.standin_auth:
                sshd = start_sshd(work, auth_log)
                if isinstance(sshd, str):
                    problems.append(f"real sshd unavailable ({sshd}); use --standin-auth")
                    print("ERROR:", problems[-1], file=sys.stderr)
                    return 2
            deadline = time.time() + 30
            while time.time() < deadline:
                with mig.connect() as c:
                    row = c.execute(text("SELECT state FROM monitor_status")).first()
                if row and row[0] == "running":
                    break
                if monitor.poll() is not None:
                    print(monitor_log.read_text(), file=sys.stderr)
                    return 2
                time.sleep(0.3)
            else:
                print("monitor did not report 'running' within 30 s", file=sys.stderr)
                return 2
            tcpdump = subprocess.Popen(
                ["tcpdump", "-i", BR, "-n", "-U", "-w", str(pcap), "ip or arp"],  # noqa: S607
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1.0)

            # ---------------------------------------------------------------- benign phase
            print("benign phase (ng-normal):")
            sc.run("20 HTTP GETs to :8080", "ng-normal", PY, "-c", BENIGN_HTTP)
            sc.run("10 DNS lookups + 30 UDP", "ng-normal", PY, "-c", BENIGN_DNS_UDP)
            sc.run("ping x5", "ng-normal", "ping", "-c", "5", "-i", "0.2", "-W", "1", VICTIM)
            time.sleep(4.0)
            benign_events = count_events()
            checks.append(
                {
                    "check": "benign traffic raises no events",
                    "expected": 0,
                    "actual": benign_events,
                    "pass": benign_events == 0,
                }
            )

            # ---------------------------------------------------------------- live rule change
            with api.begin() as c:
                c.execute(
                    text(
                        "UPDATE detection_rules SET threshold = 1000000 "
                        "WHERE key = 'abnormal_traffic'"
                    )
                )
            time.sleep(5.0)  # > rules_reload_seconds (2 s) so the running monitor has the change

            # ---------------------------------------------------------------- attack phase
            print("attack phase (ng-attacker):")
            sc.run(
                f"nmap -sS -p {SCAN_PORTS}",
                "ng-attacker",
                "nmap",
                "-sS",
                "-Pn",
                "-n",
                "-p",
                SCAN_PORTS,
                "-T4",
                VICTIM,
            )
            sc.run("150-connection flood to :9002", "ng-attacker", PY, "-c", FLOOD)
            sc.run("DNS burst (120 names + 60-char label)", "ng-attacker", PY, "-c", DNS_BURST)
            sc.run("UDP volume, paced 3000 pps x 5 s (~21 MB)", "ng-attacker", PY, "-c", UDP_VOLUME)
            if args.standin_auth:
                with open(auth_log, "a") as f:
                    f.write(STANDIN_LINE * 6)
                sc.log.append(
                    {
                        "label": "STAND-IN: 6 failed-login lines appended to auth log",
                        "ns": "-",
                        "rc": 0,
                        "seconds": 0,
                        "tail": "not a real sshd",
                    }
                )
                print("  [stand-in] 6 failed-login lines appended (NOT real SSH traffic)")
            else:
                for i in range(SSH_ATTEMPTS):
                    sc.run(
                        f"ssh login attempt {i + 1} with wrong password",
                        "ng-attacker",
                        "sshpass",
                        "-p",
                        "definitely-wrong",
                        "ssh",
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-o",
                        "PreferredAuthentications=password",
                        "-o",
                        "PubkeyAuthentication=no",
                        "-o",
                        "ConnectTimeout=5",
                        f"root@{VICTIM}",
                        "true",
                        timeout=40,
                    )
            end = time.time() + 25
            while time.time() < end:
                with mig.connect() as c:
                    keys = {r[0] for r in c.execute(text("SELECT dedup_key FROM security_events"))}
                if keys >= EXPECTED_KEYS:
                    break
                time.sleep(0.5)
            time.sleep(3.0)  # let late hits / escalation land
            tcpdump.send_signal(signal.SIGINT)
            tcpdump.wait(timeout=10)
        finally:
            if tcpdump is not None and tcpdump.poll() is None:
                tcpdump.kill()
            for p in procs:
                p.terminate()
            if isinstance(sshd, subprocess.Popen):
                sshd.terminate()
            monitor.send_signal(signal.SIGTERM)
            try:
                monitor.wait(timeout=40)
            except subprocess.TimeoutExpired:
                monitor.kill()
                problems.append("monitor did not stop within 40 s")

    # -------------------------------------------------------------------- verification
    with mig.connect() as c:
        events = [
            dict(r._mapping)
            for r in c.execute(
                text(
                    "SELECT e.id, e.dedup_key, e.category, e.severity, e.hit_count, e.rule_version, "
                    "host(e.src_ip) AS src, e.is_open, e.evidence, "
                    "extract(epoch FROM e.created_at) AS created, extract(epoch FROM e.detected_at) AS detected, "
                    "(SELECT count(*) FROM alerts a WHERE a.event_id = e.id) AS alerts "
                    "FROM security_events e ORDER BY e.id"
                )
            )
        ]
        hb = c.execute(
            text("SELECT state, packets_captured, packets_dropped FROM monitor_status")
        ).one()
        versions = {r[0]: r[1] for r in c.execute(text("SELECT key, version FROM detection_rules"))}
        notified_alerts = int(c.execute(text("SELECT count(*) FROM alerts")).scalar_one())
    by_key = {e["dedup_key"]: e for e in events}
    failed_lines = [
        ln
        for ln in auth_log.read_text(errors="replace").splitlines()
        if parse_auth_line(ln, 0.0) is not None
    ]
    with mig.connect() as c:
        auth_threshold = int(
            c.execute(
                text("SELECT threshold FROM detection_rules WHERE key = 'auth_failures'")
            ).scalar_one()
        )
    checks.append(
        {
            "check": "precondition: the sshd log holds at least `threshold` failed logins to detect",
            "failed_logins_in_log": len(failed_lines),
            "threshold": auth_threshold,
            "sshd_penalties_disabled": SSHD_NOTES.get("penalties_disabled"),
            "hint": "if this fails, sshd throttled the attacker before logging (OpenSSH >= 9.8 "
            "PerSourcePenalties) - the IDS cannot detect failures that were never logged",
            "pass": len(failed_lines) >= auth_threshold,
        }
    )
    got = set(by_key)
    checks.append(
        {
            "check": "exactly the 7 expected events (one per dedup key)",
            "expected": sorted(EXPECTED_KEYS),
            "actual": sorted(got),
            "pass": got == EXPECTED_KEYS and len(events) == len(EXPECTED_KEYS),
        }
    )
    checks.append(
        {
            "check": "every event is attributed to the attacker",
            "pass": all(e["src"] == ATTACKER for e in events),
        }
    )
    checks.append(
        {
            "check": "nothing is attributed to the benign host",
            "pass": not any(e["src"] == NORMAL for e in events),
        }
    )
    checks.append(
        {
            "check": "every event raised at least one alert",
            "pass": bool(events) and all(e["alerts"] >= 1 for e in events),
        }
    )
    scan = by_key.get(f"port_scan|{ATTACKER}|{VICTIM}")
    checks.append(
        {
            "check": "port scan escalated to critical (>=10x threshold) with 2 alerts",
            "actual": scan and (scan["severity"], scan["alerts"]),
            "pass": bool(scan) and scan["severity"] == "critical" and scan["alerts"] == 2,
        }
    )
    oracle_ports = int(
        sh(
            "bash",
            "-c",
            f"tcpdump -nr {pcap} 'tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and src {ATTACKER} "
            f"and dst {VICTIM}' 2>/dev/null | grep -o '> {VICTIM}\\.[0-9]*' | sort -u | wc -l",
        ).stdout.strip()
        or 0
    )
    seen = int(scan["evidence"].get("distinct_ports", 0)) if scan else 0
    checks.append(
        {
            "check": "port scan evidence agrees with independent tcpdump (distinct SYN ports)",
            "tcpdump_distinct_ports": oracle_ports,
            "event_distinct_ports": seen,
            "pass": bool(scan) and 15 <= seen <= oracle_ports,
        }
    )
    flood = by_key.get(f"excessive_connections|{ATTACKER}|{VICTIM}|9002")
    flood_syn = pcap_count(
        pcap, f"tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn and src {ATTACKER} and dst port 9002"
    )
    checks.append(
        {
            "check": "flood: 150 SYNs sent; tcpdump agrees; event counted them",
            "tcpdump_syn": flood_syn,
            "event_connections": flood["evidence"].get("connections") if flood else None,
            "pass": flood_syn == 150
            and bool(flood)
            and flood["evidence"].get("connections", 0) >= 100
            and flood["hit_count"] >= 2,
        }
    )
    ab = by_key.get(f"abnormal_traffic|{ATTACKER}")
    checks.append(
        {
            "check": "abnormal_traffic ran under the live-changed rule (version 2)",
            "actual": ab and ab["rule_version"],
            "pass": bool(ab) and ab["rule_version"] == 2 and versions.get("abnormal_traffic") == 2,
        }
    )
    checks.append(
        {
            "check": "other rules ran under version 1",
            "pass": all(
                e["rule_version"] == 1 for e in events if e["category"] != "abnormal_traffic"
            ),
        }
    )
    lat = {}
    for e in events:
        crossed = e["evidence"].get("crossed_at")
        if crossed is not None:
            lat[e["dedup_key"]] = round(float(e["created"]) - float(crossed), 3)
    checks.append(
        {
            "check": f"latency: threshold crossing -> committed in the database <= {LATENCY_LIMIT}s",
            "latencies_seconds": lat,
            "pass": bool(lat)
            and len(lat) == len(events)
            and all(-0.5 <= v <= LATENCY_LIMIT for v in lat.values()),
        }
    )
    oracle_all = pcap_count(pcap, f"ip and net {SUBNET} and (tcp or udp or icmp)")
    checks.append(
        {
            "check": "capture path alive: monitor saw at least every packet tcpdump saw",
            "tcpdump_packets": oracle_all,
            "monitor_captured": hb[1],
            "pass": oracle_all > 0 and hb[1] >= oracle_all,
        }
    )
    checks.append(
        {
            "check": "no packets dropped; monitor stopped cleanly",
            "actual": {"state": hb[0], "captured": hb[1], "dropped": hb[2]},
            "pass": hb[0] == "stopped" and hb[2] == 0 and monitor.returncode == 0,
        }
    )
    failed_scn = [s for s in sc.log if s["rc"] not in (0, 1) and "ssh login" not in s["label"]]
    checks.append(
        {
            "check": "every scenario command ran (no silent failures)",
            "failures": failed_scn,
            "pass": not failed_scn,
        }
    )

    ok = all(c["pass"] for c in checks) and not problems
    print()
    print(f"{'check':<82} result")
    for c in checks:
        print(f"{c['check'][:82]:<82} {'PASS' if c['pass'] else 'FAIL'}")
        if not c["pass"]:
            print("    ", {k: v for k, v in c.items() if k not in ("check", "pass")})
    print("\nevents:")
    for e in events:
        print(
            f"  {e['dedup_key']:<62} {e['severity']:<9} hits={e['hit_count']:<5} "
            f"alerts={e['alerts']} v{e['rule_version']} open={e['is_open']}"
        )
    out = LAB / "results" / f"phase4a-detection-{time.strftime('%Y%m%dT%H%M%S')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "result": "PASS" if ok else "FAIL",
                "least_privilege_monitor": least_privilege,
                "real_sshd": not args.standin_auth,
                "duration_seconds": round(time.time() - t_start, 1),
                "checks": checks,
                "events": [
                    {k: (float(v) if k in ("created", "detected") else v) for k, v in e.items()}
                    for e in events
                ],
                "scenario": sc.log,
                "alerts_total": notified_alerts,
                "problems": problems,
                "monitor_log_tail": monitor_log.read_text().splitlines()[-25:],
                "sshd_log_tail": auth_log.read_text(errors="replace").splitlines()[-12:],
                "sshd_notes": SSHD_NOTES,
            },
            indent=2,
            default=str,
        )
    )
    print(
        f"\n{'ALL CHECKS PASSED' if ok else 'FAILED'}  (least-privilege monitor: {least_privilege}; "
        f"evidence: {out.name})"
    )
    if not ok:
        print("--- monitor log tail ---")
        print("\n".join(monitor_log.read_text().splitlines()[-15:]))
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
