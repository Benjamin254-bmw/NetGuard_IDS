"""Trial-level scoring. Pure functions: no I/O, no clock, so the arithmetic is unit-testable.

Definitions (per detection category c, evaluated INDEPENDENTLY of every other category):
  positive trial for c : a core attack of category c   (kind == "positive", c in expect)
  negative trial for c : any trial where c is not expected (benign, hard negative, normal, and the
                         attacks of other categories - an attack should not trip an unrelated rule)
  TP  positive trial with >= 1 event of category c from the trial's source
  FN  positive trial with none
  FP  negative trial with >= 1 event of category c from the trial's source
  TN  negative trial with none
  recall = TP/(TP+FN)   precision = TP/(TP+FP)   FPR = FP/(FP+TN)
"Evasion" trials (real attack techniques the rules are documented not to cover) are neither positives
nor negatives for the category they target; they get their own table so limitations are visible.
Confidence intervals are 95 % Wilson intervals: with 30 trials a point estimate alone overstates
certainty.
"""

from __future__ import annotations

import math
from typing import Any

ATTRIBUTION_SECONDS = 330.0  # a source address is not reused within this time (plan.MIN_REUSE_GAP)
PRE_SLACK = 1.0


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    pos = (len(xs) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def _ratio(k: int, n: int) -> dict[str, Any]:
    ci = wilson(k, n)
    return {
        "k": k,
        "n": n,
        "value": (k / n) if n else None,
        "ci95": [round(ci[0], 4), round(ci[1], 4)] if ci else None,
    }


def attribute(trial: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Events caused by this trial: same source address, created within the trial's own time slot."""
    t0 = float(trial["t_start"])
    return [
        e
        for e in events
        if e["src"] == trial["src_ip"]
        and t0 - PRE_SLACK <= float(e["created"]) < t0 + ATTRIBUTION_SECONDS
    ]


def _stats(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "median": round(percentile(values, 0.5) or 0, 3),
        "p95": round(percentile(values, 0.95) or 0, 3),
        "max": round(max(values), 3),
    }


def score(
    trials: list[dict[str, Any]], events: list[dict[str, Any]], categories: tuple[str, ...]
) -> dict[str, Any]:
    """Score executed trials against the events found in the database."""
    valid = [t for t in trials if t.get("valid", True) and "t_start" in t]
    excluded = [
        {"trial_id": t["trial_id"], "reason": t.get("invalid_reason", "not executed")}
        for t in trials
        if t not in valid
    ]
    detail: dict[str, dict[str, Any]] = {}
    for t in valid:
        mine = attribute(t, events)
        detail[t["trial_id"]] = {
            "kind": t["kind"],
            "category": t["category"],
            "variant": t.get("variant", ""),
            "expect": t["expect"],
            "src_ip": t["src_ip"],
            "detected": sorted({e["category"] for e in mine}),
            "events": mine,
        }

    per_cat: dict[str, Any] = {}
    unexpected: list[dict[str, Any]] = []
    for c in categories:
        tp = fn = fp = tn = 0
        fp_by_type = {"normal": [0, 0], "hard_negative": [0, 0], "other_attack": [0, 0]}
        delays: list[float] = []
        commits: list[float] = []
        sev: dict[str, int] = {}
        for t in valid:
            d = detail[t["trial_id"]]
            hit = c in d["detected"]
            if c in t["expect"]:
                if t["kind"] != "positive":
                    continue  # evasion trials are reported separately
                if hit:
                    tp += 1
                    first = min(
                        (e for e in d["events"] if e["category"] == c), key=lambda e: e["created"]
                    )
                    delays.append(float(first["created"]) - float(t["t_start"]))
                    if first.get("crossed_at") is not None:
                        commits.append(float(first["created"]) - float(first["crossed_at"]))
                    sev[first["severity"]] = sev.get(first["severity"], 0) + 1
                else:
                    fn += 1
                continue
            if t["kind"] == "normal":
                bucket = "normal"
            elif t["kind"] == "hard_negative" and t["category"] == c:
                bucket = "hard_negative"
            else:
                bucket = "other_attack"
            fp_by_type[bucket][1] += 1
            if hit:
                fp += 1
                fp_by_type[bucket][0] += 1
                unexpected.append(
                    {
                        "trial_id": t["trial_id"],
                        "category": c,
                        "trial_kind": t["kind"],
                        "trial_category": t["category"],
                        "variant": t.get("variant", ""),
                    }
                )
            else:
                tn += 1
        per_cat[c] = {
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "recall": _ratio(tp, tp + fn),
            "precision": _ratio(tp, tp + fp),
            "fpr": _ratio(fp, fp + tn),
            "fp_by_negative_type": {k: _ratio(v[0], v[1]) for k, v in fp_by_type.items()},
            "detection_delay_s": _stats(delays),
            "crossing_to_commit_s": _stats(commits),
            "tp_event_severity": sev,
        }

    evasion: dict[str, Any] = {}
    for t in valid:
        if t["kind"] != "evasion":
            continue
        e = evasion.setdefault(t["variant"], {"n": 0, "detected": 0})
        e["n"] += 1
        e["detected"] += int(t["category"] in detail[t["trial_id"]]["detected"])
    for v in evasion.values():
        v["recall"] = _ratio(v["detected"], v["n"])

    counts: dict[str, int] = {}
    for t in valid:
        counts[t["kind"]] = counts.get(t["kind"], 0) + 1
    return {
        "trials_scored": len(valid),
        "trials_by_kind": counts,
        "trials_excluded": excluded,
        "per_category": per_cat,
        "evasion": evasion,
        "unexpected_events": unexpected,
        "trial_detail": detail,
    }


def _pct(r: dict[str, Any]) -> str:
    if r["value"] is None:
        return "n/a"
    ci = r["ci95"]
    return (
        f"{r['value'] * 100:.1f}% ({r['k']}/{r['n']}, 95% CI {ci[0] * 100:.0f}-{ci[1] * 100:.0f}%)"
    )


def report_markdown(result: dict[str, Any], meta: dict[str, Any]) -> str:
    L = [f"# NetGuard IDS evaluation: {meta.get('split', '?')} split", ""]
    for k in ("started", "plan_sha256", "rules_frozen", "monitor_privileges", "smoke"):
        if k in meta:
            L.append(f"- {k}: {meta[k]}")
    L += ["", f"Trials scored: {result['trials_scored']} {result['trials_by_kind']}"]
    if result["trials_excluded"]:
        L.append(
            f"**Excluded trials: {len(result['trials_excluded'])}** (see metrics.json for reasons)"
        )
    L += [
        "",
        "## Per category (independent confusion matrices)",
        "",
        "| category | TP | FN | FP | TN | recall | precision | FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c, m in result["per_category"].items():
        L.append(
            f"| {c} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} | {_pct(m['recall'])} | "
            f"{_pct(m['precision'])} | {_pct(m['fpr'])} |"
        )
    L += [
        "",
        "## False positives by kind of negative trial",
        "",
        "| category | normal traffic | own hard negatives | other attacks |",
        "|---|---|---|---|",
    ]
    for c, m in result["per_category"].items():
        b = m["fp_by_negative_type"]
        L.append(
            f"| {c} | {b['normal']['k']}/{b['normal']['n']} | {b['hard_negative']['k']}/"
            f"{b['hard_negative']['n']} | {b['other_attack']['k']}/{b['other_attack']['n']} |"
        )
    L += [
        "",
        "## Latency of true positives (seconds)",
        "",
        "| category | attack start to event committed (median / p95 / max) | threshold crossing to commit (median / p95 / max) |",
        "|---|---|---|",
    ]
    for c, m in result["per_category"].items():
        a, b = m["detection_delay_s"], m["crossing_to_commit_s"]
        f = lambda s: "n/a" if not s["n"] else f"{s['median']} / {s['p95']} / {s['max']}"  # noqa: E731
        L.append(f"| {c} | {f(a)} | {f(b)} |")
    L += [
        "",
        "## Known-evasion techniques (documented limitations; not part of core recall)",
        "",
        "| technique | trials | detected |",
        "|---|---|---|",
    ]
    for v, e in sorted(result["evasion"].items()):
        L.append(f"| {v} | {e['n']} | {e['detected']} ({_pct(e['recall'])}) |")
    if result["unexpected_events"]:
        L += ["", "## Unexpected events (each counted as a false positive)", ""]
        for u in result["unexpected_events"]:
            L.append(
                f"- {u['trial_id']}: {u['category']} event during a {u['trial_kind']} trial "
                f"({u['trial_category']} {u['variant']})"
            )
    return "\n".join(L) + "\n"
