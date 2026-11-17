#!/usr/bin/env python3
"""Phase 4B evaluation runner: real attacks and normal traffic in the lab, scored against ground truth.

  python lab/evaluate.py plan                          write the ground truth (do this BEFORE any run)
  sudo python lab/evaluate.py reset-rules              rules back to code defaults (+ DNS watch list)
  python lab/evaluate.py show-rules
  python lab/evaluate.py set-rule KEY FIELD VALUE      change a threshold etc. (records a new rule version)
  python lab/evaluate.py set-param KEY NAME JSON       change a rule parameter
  sudo python lab/evaluate.py run --split tuning [--limit-per-group 1]   (1 = quick smoke run)
  python lab/evaluate.py freeze --tuning-run DIR       lock the rules; required before the evaluation split
  sudo python lab/evaluate.py run --split evaluation   refuses unless rules == frozen rules
  python lab/evaluate.py score DIR                     re-compute metrics from a finished run (no lab needed)

Method (full write-up in docs/evaluation.md): every trial uses its own source address, so the events it
caused are found afterwards by (source address, time slot) -- the monitor is never told what is an attack.
Scoring is trial-level with independent per-category confusion matrices. Results are written to
lab/results/eval-<timestamp>/ and are the only source of the numbers reported.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import psutil
from sqlalchemy import text

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from evalkit import scoring  # noqa: E402
from evalkit.plan import CATEGORIES, WATCHLIST, make_plan, plan_sha, select  # noqa: E402
from evalkit.support import IpAllocator, diff_rules, invalid_reason, rule_snapshot  # noqa: E402
from verify_capture import BR, PY, ROOT, SUBNET, VICTIM, load_env, sh, wait_until_quiet  # noqa: E402
from verify_detection import TCP_SINK, UDP_SINK, start_sshd  # noqa: E402

from netguard_common.config import load_settings  # noqa: E402
from netguard_common.db import make_engine  # noqa: E402
from netguard_monitor.ids.logsource import parse_auth_line  # noqa: E402
from netguard_monitor.ids.registry import sync_rules  # noqa: E402

EVAL_DIR = LAB / "eval"
RESULTS = LAB / "results"
DRIVER = LAB / "evalkit" / "driver.py"
SETTLE = 3.0  # seconds after a trial for hits to be coalesced and committed
DEVICES = {"ng-attacker": "pattacker", "ng-normal": "pnormal"}
RULE_COLUMNS = {
    "threshold": int,
    "window_seconds": int,
    "cooldown_seconds": int,
    "severity": str,
    "enabled": lambda v: str(v).lower() in ("1", "true", "yes"),
}
EVENTS_SQL = text(
    "SELECT e.id, e.dedup_key, e.category, e.severity, e.hit_count, e.rule_version, "
    "host(e.src_ip) AS src, e.is_open, "
    "extract(epoch FROM e.created_at) AS created, extract(epoch FROM e.detected_at) AS detected, "
    "(e.evidence->>'crossed_at')::float8 AS crossed_at, "
    "(SELECT count(*) FROM alerts a WHERE a.event_id = e.id) AS alerts "
    "FROM security_events e ORDER BY e.id"
)
RULES_SQL = text(
    "SELECT key, version, enabled, severity::text AS severity, threshold, window_seconds, "
    "cooldown_seconds, params FROM detection_rules ORDER BY key"
)


def engines() -> tuple[Any, Any, Any]:
    base = load_settings(ROOT / ".env")
    s = base.model_copy(update={"db_name": f"{base.db_name}_test"})
    return s, make_engine(s, "migrator", pool_size=2), make_engine(s, "api", pool_size=1)


def _floats(row: dict[str, Any]) -> dict[str, Any]:
    """PostgreSQL returns numeric/extract() values as Decimal; all arithmetic here is on floats."""
    return {k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}


def live_rules(mig: Any) -> list[dict[str, Any]]:
    with mig.connect() as c:
        return rule_snapshot([dict(r._mapping) for r in c.execute(RULES_SQL)])


# ---------------------------------------------------------------------------------- simple commands
def cmd_plan(args: argparse.Namespace) -> int:
    plan = make_plan()
    sha = plan_sha(plan)
    EVAL_DIR.mkdir(exist_ok=True)
    shaf = EVAL_DIR / "plan.sha256"
    if shaf.exists() and shaf.read_text().strip() != sha and not args.force:
        print(
            f"REFUSED: the committed plan hash {shaf.read_text().strip()[:12]} differs from the "
            f"regenerated {sha[:12]}. The ground truth must not change after it is published.",
            file=sys.stderr,
        )
        return 1
    (EVAL_DIR / "ground_truth.jsonl").write_text(
        "".join(json.dumps(t, sort_keys=True) + "\n" for t in plan)
    )
    shaf.write_text(sha + "\n")
    from collections import Counter

    print(f"plan sha256 {sha}")
    for split in ("tuning", "evaluation"):
        c = Counter(t["kind"] for t in plan if t["split"] == split)
        print(f"  {split}: {sum(c.values())} trials {dict(c)}")
    return 0


def cmd_reset_rules(_: argparse.Namespace) -> int:
    _, mig, api = engines()
    with mig.begin() as c:
        c.execute(text("TRUNCATE detection_rules RESTART IDENTITY CASCADE"))
    sync_rules(mig)
    with api.begin() as c:
        c.execute(
            text(
                "UPDATE detection_rules SET params = params || CAST(:p AS jsonb) WHERE key = 'suspicious_dns'"
            ),
            {"p": json.dumps({"watchlist": WATCHLIST})},
        )
    return cmd_show_rules(_)


def cmd_show_rules(_: argparse.Namespace) -> int:
    _, mig, _ = engines()
    for r in live_rules(mig):
        print(
            f"{r['key']:<22} v{r['version']} enabled={r['enabled']!s:<5} {r['severity']:<8} "
            f"threshold={r['threshold']:<9} window={r['window_seconds']:<4} cooldown={r['cooldown_seconds']:<4} "
            f"params={json.dumps(r['params'])}"
        )
    return 0


def cmd_set_rule(args: argparse.Namespace) -> int:
    if args.field not in RULE_COLUMNS:
        print(f"field must be one of {sorted(RULE_COLUMNS)}", file=sys.stderr)
        return 2
    _, mig, api = engines()
    with api.begin() as c:  # column name is whitelisted above, value is bound
        n = c.execute(
            text(f"UPDATE detection_rules SET {args.field} = :v WHERE key = :k"),  # noqa: S608
            {"v": RULE_COLUMNS[args.field](args.value), "k": args.key},
        ).rowcount
    if n != 1:
        print(f"no such rule: {args.key}", file=sys.stderr)
        return 2
    return cmd_show_rules(args)


def cmd_set_param(args: argparse.Namespace) -> int:
    _, mig, api = engines()
    with api.begin() as c:
        n = c.execute(
            text("UPDATE detection_rules SET params = params || CAST(:p AS jsonb) WHERE key = :k"),
            {"p": json.dumps({args.name: json.loads(args.value)}), "k": args.key},
        ).rowcount
    if n != 1:
        print(f"no such rule: {args.key}", file=sys.stderr)
        return 2
    return cmd_show_rules(args)


def cmd_freeze(args: argparse.Namespace) -> int:
    tdir = Path(args.tuning_run)
    m = json.loads((tdir / "metrics.json").read_text())
    if m["meta"]["split"] != "tuning" or m["meta"].get("smoke"):
        print("freeze needs a full TUNING run (not smoke, not evaluation)", file=sys.stderr)
        return 1
    _, mig, _ = engines()
    plan = make_plan()
    frozen = {
        "frozen_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "plan_sha256": plan_sha(plan),
        "tuning_run": tdir.name,
        "rules": live_rules(mig),
    }
    (EVAL_DIR / "frozen_rules.json").write_text(json.dumps(frozen, indent=2) + "\n")
    print("frozen:")
    return cmd_show_rules(args)


def cmd_score(args: argparse.Namespace) -> int:
    d = Path(args.dir)
    trials = [json.loads(ln) for ln in (d / "trials.jsonl").read_text().splitlines() if ln.strip()]
    events = json.loads((d / "events.json").read_text())
    old = json.loads((d / "metrics.json").read_text())
    result = scoring.score(trials, events, CATEGORIES)
    new = scoring.report_markdown(result, old["meta"])
    print(new)
    same = json.dumps(result["per_category"], sort_keys=True) == json.dumps(
        old["result"]["per_category"], sort_keys=True
    )
    print("re-scored metrics identical to the stored ones:", same)
    return 0 if same else 1


# ------------------------------------------------------------------------------------------- run
class Sampler(threading.Thread):
    """CPU% and resident memory of the monitor process, once a second."""

    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.proc = psutil.Process(pid)
        self.stop_flag = threading.Event()
        self.cpu: list[float] = []
        self.rss: list[int] = []

    def run(self) -> None:
        self.proc.cpu_percent(None)
        while not self.stop_flag.wait(1.0):
            try:
                self.cpu.append(self.proc.cpu_percent(None))
                self.rss.append(self.proc.memory_info().rss)
            except psutil.Error:
                return

    def summary(self) -> dict[str, Any]:
        mb = [r / 1e6 for r in self.rss]
        return {
            "samples": len(self.cpu),
            "cpu_percent_median": scoring.percentile(self.cpu, 0.5),
            "cpu_percent_p95": scoring.percentile(self.cpu, 0.95),
            "cpu_percent_max": max(self.cpu, default=None),
            "rss_mb_median": scoring.percentile(mb, 0.5),
            "rss_mb_max": max(mb, default=None),
        }


def execute(trial: dict[str, Any], ip: str, auth_log: Path) -> dict[str, Any]:
    ns, sc, p = trial["ns"], trial["scenario"], trial["params"]
    out: dict[str, Any] = {}
    if sc == "ssh_fail":
        rcs = []
        for i in range(p["attempts"]):
            r = subprocess.run(  # noqa: S603
                [
                    "ip",
                    "netns",
                    "exec",
                    ns,
                    "sshpass",
                    "-p",
                    "wrong-password",
                    "ssh",  # noqa: S607
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
                    "-o",
                    f"BindAddress={ip}",
                    f"root@{VICTIM}",
                    "true",
                ],
                capture_output=True,
                text=True,
                timeout=40,
                check=False,
            )
            rcs.append(r.returncode)
            if p["gap"] and i < p["attempts"] - 1:
                time.sleep(p["gap"])
        out["ssh_rcs"] = rcs
        return out
    if sc == "nmap":
        cmd = [
            "nmap",
            f"-{p['scan']}",
            "-Pn",
            "-n",
            "-T4",
            "--max-retries",
            "1",
            "-S",
            ip,
            "-e",
            DEVICES[ns],
            "-p",
            ",".join(map(str, p["ports"])),
            VICTIM,
        ]
    else:
        cmd = [PY, str(DRIVER), sc, json.dumps(p), ip]
    try:
        r = subprocess.run(
            ["ip", "netns", "exec", ns, *cmd],
            capture_output=True,
            text=True,  # noqa: S603, S607
            timeout=200,
            check=False,
        )
        out.update(rc=r.returncode, tail=(r.stdout + r.stderr)[-300:])
        if sc != "nmap" and r.returncode == 0:
            out["driver"] = json.loads(r.stdout.strip().splitlines()[-1])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, IndexError) as exc:
        out.update(rc=124, tail=f"{type(exc).__name__}: {exc}")
    return out


def cmd_run(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        print("run with sudo (network namespaces, nmap -S, raw sockets)", file=sys.stderr)
        return 2
    if sh("ip", "link", "show", BR).returncode != 0:
        print("lab is not up: make lab-up", file=sys.stderr)
        return 2
    for tool in ("nmap", "sshpass", "sshd"):
        if not shutil.which(tool):
            print(f"required tool missing: {tool}", file=sys.stderr)
            return 2
    plan = make_plan()
    sha = plan_sha(plan)
    shaf = EVAL_DIR / "plan.sha256"
    if not shaf.exists() or shaf.read_text().strip() != sha:
        print(
            "the committed ground truth is missing or differs from the plan: run `evaluate.py plan`",
            file=sys.stderr,
        )
        return 1
    settings, mig, _ = engines()
    before = live_rules(mig)
    smoke = args.limit_per_group is not None
    if args.split == "evaluation":
        if smoke:
            print(
                "REFUSED: the evaluation split is run once, in full, never as a peek.",
                file=sys.stderr,
            )
            return 1
        ff = EVAL_DIR / "frozen_rules.json"
        if not ff.exists():
            print(
                "REFUSED: no frozen_rules.json. Tune, then `evaluate.py freeze --tuning-run DIR`.",
                file=sys.stderr,
            )
            return 1
        frozen = json.loads(ff.read_text())
        problems = diff_rules(frozen["rules"], before)
        if frozen["plan_sha256"] != sha:
            problems.append("the plan changed after the rules were frozen")
        if problems:
            print(
                "REFUSED: rules differ from the frozen set:\n  " + "\n  ".join(problems),
                file=sys.stderr,
            )
            return 1
    trials = select(plan, args.split, args.limit_per_group)
    out_dir = (
        RESULTS / f"eval-{args.split}{'-smoke' if smoke else ''}-{datetime.now(UTC):%Y%m%dT%H%M%S}"
    )
    out_dir.mkdir(parents=True)
    print(f"{len(trials)} trials -> {out_dir}")

    with mig.begin() as c:
        c.execute(
            text(
                "TRUNCATE alerts, security_events, traffic_stats_1s, connection_aggregates_1m, devices, "
                "ingest_batches, monitor_status RESTART IDENTITY CASCADE"
            )
        )
    sync_rules(mig)

    alloc = IpAllocator()

    def remove_addresses() -> None:
        for ns_, dev_ in DEVICES.items():
            for ip_ in alloc.addresses(ns_):
                sh("ip", "-n", ns_, "addr", "del", f"{ip_}/24", "dev", dev_)

    atexit.register(remove_addresses)  # leave the lab as found, even if the run fails
    for ns, dev in DEVICES.items():
        for ip in alloc.addresses(ns):
            sh("ip", "-n", ns, "addr", "add", f"{ip}/24", "dev", dev)

    work = Path(tempfile.mkdtemp(prefix="ng-eval-"))
    auth_log = work / "auth.log"
    auth_log.write_text("")
    os.chmod(work, 0o755)  # noqa: S103 - the unprivileged monitor must traverse it
    os.chmod(auth_log, 0o644)
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    least_privilege = bool(uid and uid != "0")
    env = {
        **os.environ,
        **load_env(ROOT / ".env"),
        "NETGUARD_DB_NAME": settings.db_name,
        "NETGUARD_MONITOR_INTERFACE": BR,
        "NETGUARD_AUTHORIZED_SUBNET": SUBNET,
        "NETGUARD_SPILL_DIR": str(work / "spill"),
        "NETGUARD_AUTH_LOG_PATH": str(auth_log),
        "NETGUARD_RULES_RELOAD_SECONDS": "2",
        "NETGUARD_ACTIVE_DISCOVERY": "false",
        # Lab traffic is namespace-to-namespace across a bridge, i.e. not addressed to the bridge
        # itself, so the monitor must hold the interface promiscuous (as for a mirror port). It
        # must not depend on another tool (tcpdump) having switched promiscuous mode on.
        "NETGUARD_PROMISCUOUS": os.environ.get("NETGUARD_LAB_PROMISCUOUS", "true"),
    }
    cmd = [PY, "-m", "netguard_monitor.main", "run", "--duration", str(int(len(trials) * 90 + 900))]
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
        print("NOTE: not started via sudo from a normal user: the monitor will run as root.")
    if not wait_until_quiet():
        print("the lab bridge never went quiet", file=sys.stderr)
        return 2

    records: list[dict[str, Any]] = []
    procs: list[subprocess.Popen[bytes]] = []
    sshd: Any = None
    sampler: Sampler | None = None
    started = time.time()
    aborted = ""
    with open(work / "monitor.log", "w") as mlog:
        monitor = subprocess.Popen(cmd, env=env, cwd=work, stdout=mlog, stderr=subprocess.STDOUT)  # noqa: S603
        try:
            for code in (TCP_SINK, UDP_SINK):
                procs.append(subprocess.Popen(["ip", "netns", "exec", "ng-victim", PY, "-c", code]))  # noqa: S603, S607
            if any(t["scenario"] == "ssh_fail" for t in trials):
                sshd = start_sshd(work, auth_log)
                if isinstance(sshd, str):
                    print("ERROR: real sshd unavailable:", sshd, file=sys.stderr)
                    return 2
            deadline = time.time() + 30
            while time.time() < deadline:
                with mig.connect() as c:
                    row = c.execute(text("SELECT state FROM monitor_status")).first()
                if row and row[0] == "running":
                    break
                if monitor.poll() is not None:
                    print((work / "monitor.log").read_text(), file=sys.stderr)
                    return 2
                time.sleep(0.3)
            else:
                print("monitor did not report 'running' within 30 s", file=sys.stderr)
                return 2
            sampler = Sampler(monitor.pid)
            sampler.start()
            time.sleep(1.0)
            with open(out_dir / "trials.jsonl", "w") as tf:
                for n, t in enumerate(trials, 1):
                    if monitor.poll() is not None:
                        aborted = (
                            f"monitor exited (code {monitor.returncode}) during {t['trial_id']}"
                        )
                        break
                    ip, wait = alloc.acquire(t["ns"], time.time())
                    if wait:
                        print(f"  (waiting {wait:.0f}s so {ip} is not reused inside the cooldown)")
                        time.sleep(wait)
                    t0 = time.time()
                    outcome = execute(t, ip, auth_log)
                    t1 = time.time()
                    alloc.release(ip, t1)
                    time.sleep(SETTLE)
                    if t["scenario"] == "ssh_fail":
                        outcome["logged_failures"] = sum(
                            1
                            for ln in auth_log.read_text(errors="replace").splitlines()
                            if (f := parse_auth_line(ln, 0.0)) is not None and f.src_ip == ip
                        )
                    reason = invalid_reason(t, outcome)
                    rec = {
                        **t,
                        "src_ip": ip,
                        "t_start": t0,
                        "t_end": t1,
                        "outcome": outcome,
                        "valid": reason is None,
                        **({"invalid_reason": reason} if reason else {}),
                    }
                    records.append(rec)
                    tf.write(json.dumps(rec) + "\n")
                    tf.flush()
                    print(
                        f"[{n}/{len(trials)}] {t['trial_id']} {t['kind']:<13} {t['category']:<22} "
                        f"{t['description'][:38]:<38} {'ok' if reason is None else 'INVALID: ' + reason}"
                    )
            time.sleep(6.0)  # late hits / commits
        finally:
            if sampler:
                sampler.stop_flag.set()
            for p in procs:
                p.terminate()
            if isinstance(sshd, subprocess.Popen):
                sshd.terminate()
            monitor.send_signal(signal.SIGTERM)
            try:
                monitor.wait(timeout=40)
            except subprocess.TimeoutExpired:
                monitor.kill()
                aborted = aborted or "monitor did not stop within 40 s"

    with mig.connect() as c:
        events = [_floats(dict(r._mapping)) for r in c.execute(EVENTS_SQL)]
        st = c.execute(
            text("SELECT state, packets_captured, packets_dropped FROM monitor_status")
        ).first()
    (out_dir / "events.json").write_text(json.dumps(events, default=float, indent=1))
    result = scoring.score(records, events, CATEGORIES)
    meta = {
        "split": args.split,
        "smoke": smoke,
        "started": datetime.fromtimestamp(started, UTC).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started),
        "plan_sha256": sha,
        "rules_frozen": args.split == "evaluation",
        "monitor_privileges": "non-root, CAP_NET_RAW+CAP_NET_ADMIN only"
        if least_privilege
        else "ROOT (not least-privilege)",
        "aborted": aborted or None,
        "kernel": platform.release(),
        "nmap": subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True, check=False
        ).stdout.split("\n")[0],  # noqa: S607
    }
    metrics = {
        "meta": meta,
        "rules": live_rules(mig),
        "rules_at_start": before,
        "result": result,
        "monitor": {
            "final_state": st[0] if st else None,
            "packets_captured": st[1] if st else None,
            "packets_dropped": st[2] if st else None,
        },
        "resources": sampler.summary() if sampler else {},
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=1, default=float))
    report = scoring.report_markdown(result, meta) + (
        f"\nMonitor: captured {metrics['monitor']['packets_captured']}, kernel-dropped "
        f"{metrics['monitor']['packets_dropped']}. Resources: {json.dumps(metrics['resources'], default=float)}\n"
    )
    (out_dir / "report.md").write_text(report)
    if args.split == "evaluation":
        with open(EVAL_DIR / "evaluation_runs.log", "a") as f:
            f.write(
                f"{meta['started']} {out_dir.name} plan={sha[:12]} "
                f"rules={[(r['key'], r['version']) for r in metrics['rules']]}\n"
            )
    print(report)
    if aborted:
        print("RUN ABORTED:", aborted, file=sys.stderr)
        return 1
    print(f"results: {out_dir}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_plan)
    sub.add_parser("reset-rules").set_defaults(fn=cmd_reset_rules)
    sub.add_parser("show-rules").set_defaults(fn=cmd_show_rules)
    p = sub.add_parser("set-rule")
    p.add_argument("key")
    p.add_argument("field")
    p.add_argument("value")
    p.set_defaults(fn=cmd_set_rule)
    p = sub.add_parser("set-param")
    p.add_argument("key")
    p.add_argument("name")
    p.add_argument("value")
    p.set_defaults(fn=cmd_set_param)
    p = sub.add_parser("freeze")
    p.add_argument("--tuning-run", required=True)
    p.set_defaults(fn=cmd_freeze)
    p = sub.add_parser("score")
    p.add_argument("dir")
    p.set_defaults(fn=cmd_score)
    p = sub.add_parser("run")
    p.add_argument("--split", choices=("tuning", "evaluation"), required=True)
    p.add_argument(
        "--limit-per-group", type=int, default=None, help="smoke mode: first N trials of each group"
    )
    p.set_defaults(fn=cmd_run)
    args = ap.parse_args()
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
