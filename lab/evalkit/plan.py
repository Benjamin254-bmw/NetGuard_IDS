"""Seeded evaluation plan: every trial, its parameters and what it is expected to trigger.

The plan is generated BEFORE anything runs and is deterministic for a given seed, so the ground truth
cannot be adjusted after seeing results. Trials are of four kinds:

  positive       a real attack of the rule's category; the rule is expected to fire (core recall)
  hard_negative  benign or sub-threshold behaviour designed to sit just below a rule; expect nothing
  evasion        a real attack technique the rules are KNOWN not to cover (documented limitation);
                 reported separately so it neither inflates nor deflates core recall
  normal         ordinary small-network activity; expect nothing

Each category's trials are split into a TUNING part (used to set thresholds) and an EVALUATION part
(used for the final numbers and never for tuning).
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from typing import Any

SEED = 20261110
CATEGORIES = (
    "port_scan",
    "excessive_connections",
    "auth_failures",
    "abnormal_traffic",
    "suspicious_dns",
)
# (tuning, evaluation) trial counts
COUNTS = {"positive": (15, 30), "hard_negative": (5, 10), "normal": (15, 30)}
EVASION_TYPES = ("udp_scan", "fin_scan", "xmas_scan", "null_scan", "slow_scan")
EVASION_COUNTS = (2, 4)
POOLS = {"ng-attacker": (100, 179), "ng-normal": (180, 230)}  # last octet ranges of source pools
SUBNET_PREFIX = "10.10.10."
WATCHLIST = ["malware-eval.test"]  # administrator-configured watch list used by the DNS trials
MIN_REUSE_GAP = 330.0  # seconds before a source address may be reused (> longest cooldown, 300 s)


def _rng(*parts: object) -> random.Random:
    return random.Random("|".join(str(p) for p in (SEED, *parts)))  # noqa: S311  seeded on purpose


def _ports(rng: random.Random, n: int) -> list[int]:
    return sorted(rng.sample(range(1, 1001), n))


def _logint(rng: random.Random, lo: int, hi: int) -> int:
    return int(round(math.exp(rng.uniform(math.log(lo), math.log(hi)))))


# ---------------------------------------------------------------------------------------- positives
def _pos_port_scan(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    n = [16, 17, 18, 20][i] if i < 4 else _logint(rng, 16, 1000)
    ports = _ports(rng, n)
    if i % 2 == 0:
        return "nmap", {"scan": "sS", "ports": ports}, f"nmap -sS of {n} ports"
    return (
        "connect_ports",
        {"ports": ports, "interval": min(0.25, 7.0 / n), "repeat": 1},
        f"connect() scan of {n} ports",
    )


def _pos_flood(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    n = [105, 110, 120, 150][i] if i < 4 else _logint(rng, 105, 2500)
    port = 8080 if rng.random() < 0.8 else 9002
    seconds = round(rng.uniform(2.0, 8.0), 1)
    return "flood", {"ports": [port], "n": n, "seconds": seconds}, f"{n} connections to :{port}"


def _pos_auth(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    k = [5, 6, 5][i] if i < 3 else rng.randint(5, 12)
    gap = rng.choice([0.0, 0.2, 1.0])
    return "ssh_fail", {"attempts": k, "gap": gap}, f"{k} failed ssh logins"


def _pos_volume(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    mbps = round(rng.uniform(6.0, 16.0), 1)
    return "udp_rate", {"mbps": mbps, "seconds": 12.0}, f"UDP at {mbps} MB/s for 12 s"


def _pos_dns(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    variant = i % 4
    if variant == 0:
        q = rng.randint(110, 400)
        return (
            "dns",
            {"queries": q, "distinct": rng.randint(3, 30), "seconds": round(rng.uniform(3, 10), 1)},
            f"{q} DNS queries (query_rate)",
        )
    if variant == 1:
        n = rng.randint(55, 200)
        return "dns", {"queries": n, "distinct": n, "seconds": 5.0}, f"{n} distinct names"
    if variant == 2:
        ln = rng.randint(53, 63)
        return "dns", {"queries": 1, "distinct": 1, "label": ln, "seconds": 0.0}, f"{ln}-char label"
    name = f"c2-{rng.randint(1, 999)}.{WATCHLIST[0]}"
    return (
        "dns",
        {"queries": rng.randint(1, 3), "names": [name], "seconds": 0.0},
        "watch-listed name",
    )


POSITIVE = {
    "port_scan": _pos_port_scan,
    "excessive_connections": _pos_flood,
    "auth_failures": _pos_auth,
    "abnormal_traffic": _pos_volume,
    "suspicious_dns": _pos_dns,
}


# ---------------------------------------------------------------------------------- hard negatives
def _neg_port_scan(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    v = i % 5
    if v == 0:
        n = rng.randint(4, 13)
        return (
            "connect_ports",
            {"ports": _ports(rng, n), "interval": 0.05, "repeat": 1},
            f"{n} ports",
        )
    if v == 1:
        return (
            "connect_ports",
            {"ports": _ports(rng, 14), "interval": 0.05, "repeat": 1},
            "14 ports (1 below)",
        )
    if v == 2:
        reps = rng.randint(40, 90)
        return (
            "connect_ports",
            {"ports": [8080], "interval": 0.02, "repeat": reps},
            f"{reps}x one port",
        )
    if v == 3:
        return (
            "connect_ports",
            {"ports": [22, 53, 80, 443, 8080, 9001], "interval": 0.05, "repeat": 3},
            "6-service mix",
        )
    return "connect_ports", {"ports": _ports(rng, 14), "interval": 0.01, "repeat": 5}, "14 ports x5"


def _neg_flood(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    v = i % 3
    if v == 0:
        n = rng.randint(40, 95)
        return (
            "flood",
            {"ports": [8080], "n": n, "seconds": round(rng.uniform(1, 4), 1)},
            f"{n} connections burst",
        )
    if v == 1:
        return "flood", {"ports": [8080], "n": 120, "seconds": 30.0}, "120 connections over 30 s"
    return (
        "flood",
        {"ports": [8080, 9002], "n": 180, "seconds": 5.0},
        "180 connections over 2 ports",
    )


def _neg_auth(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    if i % 5 == 4:
        return "ssh_fail", {"attempts": 5, "gap": 16.0}, "5 failures spread over 64 s"
    k = rng.randint(1, 4)
    return "ssh_fail", {"attempts": k, "gap": 0.2}, f"{k} failed ssh logins"


def _neg_volume(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    if i % 2 == 0:
        mbps = round(rng.uniform(2.0, 4.0), 1)
        return "udp_rate", {"mbps": mbps, "seconds": 12.0}, f"UDP at {mbps} MB/s sustained"
    return "udp_rate", {"mbps": 12.0, "seconds": 2.5}, "12 MB/s burst for 2.5 s"


def _neg_dns(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    v = i % 3
    if v == 0:
        q = rng.randint(40, 95)
        return (
            "dns",
            {"queries": q, "distinct": rng.randint(5, min(45, q)), "seconds": 6.0},
            f"{q} queries",
        )
    if v == 1:
        return "dns", {"queries": 90, "distinct": 1, "seconds": 6.0}, "one name x90"
    return (
        "dns",
        {"queries": rng.randint(1, 5), "distinct": 1, "label": rng.randint(40, 52), "seconds": 0.0},
        "long-ish label",
    )


HARD_NEGATIVE = {
    "port_scan": _neg_port_scan,
    "excessive_connections": _neg_flood,
    "auth_failures": _neg_auth,
    "abnormal_traffic": _neg_volume,
    "suspicious_dns": _neg_dns,
}


# ------------------------------------------------------------------------------------------ evasion
def _evasion(kind: str, rng: random.Random) -> tuple[str, dict[str, Any], str]:
    if kind == "udp_scan":
        return "nmap", {"scan": "sU", "ports": _ports(rng, 40)}, "nmap -sU, 40 ports"
    if kind == "slow_scan":
        return (
            "connect_ports",
            {"ports": _ports(rng, 20), "interval": 2.0, "repeat": 1},
            "20 ports, 1 per 2 s",
        )
    flag = {"fin_scan": "sF", "xmas_scan": "sX", "null_scan": "sN"}[kind]
    return "nmap", {"scan": flag, "ports": _ports(rng, 100)}, f"nmap -{flag}, 100 ports"


# ---------------------------------------------------------------------------------------- normal
def _normal(rng: random.Random, i: int) -> tuple[str, dict[str, Any], str]:
    bulk = round(rng.uniform(0.5, 2.0), 1) if rng.random() < 0.3 else 0.0
    p = {
        "http": rng.randint(5, 40),
        "dns": rng.randint(3, 30),
        "dns_names": rng.randint(2, 10),
        "udp": rng.randint(10, 200),
        "ping": rng.randint(3, 10),
        "bulk_mbps": bulk,
        "bulk_seconds": 5.0,
    }
    return "normal_mix", p, f"{p['http']} HTTP, {p['dns']} DNS, bulk {bulk} MB/s"


# ---------------------------------------------------------------------------------------- the plan
def _trial(
    kind: str,
    category: str,
    scenario: str,
    params: dict[str, Any],
    desc: str,
    expect: list[str],
    ns: str,
    label: str = "",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "category": category,
        "scenario": scenario,
        "params": params,
        "description": desc,
        "expect": expect,
        "ns": ns,
        "variant": label,
    }


def make_plan(seed: int = SEED) -> list[dict[str, Any]]:
    """The complete ordered plan (tuning and evaluation trials interleaved, shuffled by seed)."""
    trials: list[dict[str, Any]] = []

    def add_group(
        kind: str,
        category: str,
        counts: tuple[int, int],
        gen: Any,
        expect: list[str],
        ns: str = "ng-attacker",
        evasion: str = "",
    ) -> None:
        tune, ev = counts
        rng = _rng(seed, kind, category, evasion)
        group = []
        for i in range(tune + ev):
            scenario, params, desc = gen(rng, i)
            group.append(_trial(kind, category, scenario, params, desc, expect, ns, evasion))
        tuning = set(_rng(seed, "split", kind, category, evasion).sample(range(tune + ev), tune))
        for i, t in enumerate(group):
            t["split"] = "tuning" if i in tuning else "evaluation"
        trials.extend(group)

    for c in CATEGORIES:
        add_group("positive", c, COUNTS["positive"], POSITIVE[c], [c])
        add_group("hard_negative", c, COUNTS["hard_negative"], HARD_NEGATIVE[c], [])
    for e in EVASION_TYPES:
        add_group(
            "evasion",
            "port_scan",
            EVASION_COUNTS,
            lambda rng, i, e=e: _evasion(e, rng),
            ["port_scan"],
            evasion=e,
        )
    add_group("normal", "none", COUNTS["normal"], _normal, [], ns="ng-normal")

    order = list(range(len(trials)))
    _rng(seed, "order").shuffle(order)
    plan = []
    for n, idx in enumerate(order, 1):
        t = dict(trials[idx])
        t["trial_id"] = f"T{n:04d}"
        plan.append(t)
    return plan


def plan_sha(plan: list[dict[str, Any]]) -> str:
    blob = "\n".join(json.dumps(t, sort_keys=True) for t in plan)
    return hashlib.sha256(blob.encode()).hexdigest()


def select(
    plan: list[dict[str, Any]], split: str, limit_per_group: int | None = None
) -> list[dict[str, Any]]:
    """Trials of one split in plan order; `limit_per_group` keeps the first N of each group (smoke)."""
    chosen = [t for t in plan if t["split"] == split]
    if limit_per_group is None:
        return chosen
    seen: dict[tuple[str, str, str], int] = {}
    out = []
    for t in chosen:
        key = (t["kind"], t["category"], t["variant"])
        seen[key] = seen.get(key, 0) + 1
        if seen[key] <= limit_per_group:
            out.append(t)
    return out
