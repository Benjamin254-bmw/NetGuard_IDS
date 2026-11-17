"""Unit tests for the evaluation plan and scoring arithmetic (no lab needed)."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

import pytest
from evalkit import plan as P
from evalkit import scoring as S

CATS = P.CATEGORIES


# ------------------------------------------------------------------ plan
def test_plan_is_deterministic_and_hashable() -> None:
    a, b = P.make_plan(), P.make_plan()
    assert a == b and P.plan_sha(a) == P.plan_sha(b)
    assert P.plan_sha(P.make_plan(seed=1)) != P.plan_sha(a)  # a different seed is a different plan
    assert len({t["trial_id"] for t in a}) == len(a)


def test_plan_counts_meet_the_requirements() -> None:
    plan = P.make_plan()
    c = Counter((t["kind"], t["category"], t["split"]) for t in plan)
    for cat in CATS:
        assert c[("positive", cat, "evaluation")] == 30  # >= 30 core trials per category
        assert c[("positive", cat, "tuning")] == 15
        assert c[("hard_negative", cat, "evaluation")] == 10
    assert c[("normal", "none", "evaluation")] == 30 and c[("normal", "none", "tuning")] == 15
    evasion = Counter(t["variant"] for t in plan if t["kind"] == "evasion")
    assert set(evasion) == set(P.EVASION_TYPES) and all(v == 6 for v in evasion.values())


def test_every_trial_states_its_expectation_and_is_json_serialisable() -> None:
    for t in P.make_plan():
        json.dumps(t)
        assert t["split"] in ("tuning", "evaluation")
        if t["kind"] in ("hard_negative", "normal"):
            assert t["expect"] == []
        else:
            assert t["expect"] == [t["category"]]
        assert (t["ns"] == "ng-normal") == (t["kind"] == "normal")


def test_negatives_really_sit_below_the_default_thresholds() -> None:
    from netguard_monitor.ids.rules import ALL_RULES

    d = {r.key: r.defaults for r in ALL_RULES}
    for t in P.make_plan():
        p = t["params"]
        if t["kind"] == "hard_negative":
            if t["category"] == "port_scan":
                assert len(set(p["ports"])) < d["port_scan"].threshold
            if t["category"] == "excessive_connections":
                per_port = p["n"] / len(p["ports"])
                assert (
                    per_port / max(p["seconds"], 10) * 10 < d["excessive_connections"].threshold
                    or per_port < 100
                )
            if t["category"] == "auth_failures":
                assert p["attempts"] < 5 or p["gap"] >= 16
            if t["category"] == "abnormal_traffic":
                assert p["mbps"] * min(p["seconds"], 10) / 10 < 5.0
            if t["category"] == "suspicious_dns":
                assert p["queries"] < 100 and p.get("distinct", 1) < 50 and p.get("label", 0) <= 52
        if t["kind"] == "positive":
            if t["category"] == "port_scan":
                assert len(set(p["ports"])) >= d["port_scan"].threshold
            if t["category"] == "excessive_connections":
                assert p["n"] >= 105 and p["seconds"] <= 8
            if t["category"] == "auth_failures":
                assert p["attempts"] >= 5
            if t["category"] == "abnormal_traffic":
                assert p["mbps"] > 5.0 and p["seconds"] >= 10


def test_select_filters_by_split_and_limit() -> None:
    plan = P.make_plan()
    ev = P.select(plan, "evaluation")
    assert all(t["split"] == "evaluation" for t in ev) and len(ev) == 150 + 50 + 30 + 20
    smoke = P.select(plan, "tuning", limit_per_group=1)
    groups = Counter((t["kind"], t["category"], t["variant"]) for t in smoke)
    assert max(groups.values()) == 1 and len(smoke) < 25


def test_tuning_and_evaluation_trials_are_different_trials() -> None:
    plan = P.make_plan()
    tune = {t["trial_id"] for t in plan if t["split"] == "tuning"}
    ev = {t["trial_id"] for t in plan if t["split"] == "evaluation"}
    assert not tune & ev and len(tune) + len(ev) == len(plan)


# ------------------------------------------------------------------ scoring helpers
def trial(
    i: int, kind: str, cat: str, expect: list[str], variant: str = "", t0: float = 1000.0
) -> dict[str, Any]:
    return {
        "trial_id": f"T{i}",
        "kind": kind,
        "category": cat,
        "expect": expect,
        "variant": variant,
        "src_ip": f"10.10.10.{i}",
        "t_start": t0 + i * 400,
        "t_end": t0 + i * 400 + 5,
        "valid": True,
    }


def ev(
    i: int,
    cat: str,
    dt: float = 1.5,
    crossed: float | None = 1.0,
    sev: str = "high",
    t0: float = 1000.0,
) -> dict[str, Any]:
    return {
        "src": f"10.10.10.{i}",
        "category": cat,
        "severity": sev,
        "created": t0 + i * 400 + dt,
        "crossed_at": (t0 + i * 400 + crossed) if crossed is not None else None,
    }


def test_wilson_interval_known_values() -> None:
    lo, hi = S.wilson(30, 30)
    assert hi == 1.0 and 0.88 < lo < 0.89  # 30/30 is NOT "100% for sure"
    lo, hi = S.wilson(0, 30)
    assert lo == 0.0 and 0.11 < hi < 0.12
    lo, hi = S.wilson(15, 30)
    assert 0.33 < lo < 0.34 and 0.66 < hi < 0.67
    assert S.wilson(0, 0) is None


def test_percentile() -> None:
    assert S.percentile([1, 2, 3, 4], 0.5) == 2.5
    assert S.percentile([5], 0.95) == 5 and S.percentile([], 0.5) is None
    assert S.percentile([1, 2, 3, 4, 5], 1.0) == 5


def test_confusion_matrix_counts_per_category() -> None:
    trials = [
        trial(1, "positive", "port_scan", ["port_scan"]),  # detected -> TP
        trial(2, "positive", "port_scan", ["port_scan"]),  # missed   -> FN
        trial(3, "hard_negative", "port_scan", []),  # quiet    -> TN
        trial(4, "hard_negative", "port_scan", []),  # alerted  -> FP (own hard negative)
        trial(5, "normal", "none", []),  # alerted  -> FP (normal)
        trial(6, "normal", "none", []),  # quiet    -> TN
        trial(7, "positive", "auth_failures", ["auth_failures"]),  # an attack of another category
    ]
    events = [ev(1, "port_scan"), ev(4, "port_scan"), ev(5, "port_scan"), ev(7, "auth_failures")]
    r = S.score(trials, events, ("port_scan", "auth_failures"))
    m = r["per_category"]["port_scan"]
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 2, 3)  # TN: trials 3, 6, 7 (+ none else)
    assert m["recall"]["value"] == 0.5 and m["precision"]["value"] == pytest.approx(1 / 3)
    assert m["fpr"]["value"] == pytest.approx(2 / 5)
    assert m["fp_by_negative_type"]["normal"]["k"] == 1
    assert m["fp_by_negative_type"]["hard_negative"]["k"] == 1
    assert m["fp_by_negative_type"]["other_attack"] == {
        "k": 0,
        "n": 1,
        "value": 0.0,
        "ci95": m["fp_by_negative_type"]["other_attack"]["ci95"],
    }
    a = r["per_category"]["auth_failures"]
    assert (a["tp"], a["fn"], a["fp"], a["tn"]) == (1, 0, 0, 6)


def test_categories_are_independent() -> None:
    # A port-scan trial that also trips the flood rule: TP for port_scan AND a false positive for the flood rule.
    trials = [trial(1, "positive", "port_scan", ["port_scan"])]
    events = [ev(1, "port_scan"), ev(1, "excessive_connections")]
    r = S.score(trials, events, ("port_scan", "excessive_connections"))
    assert r["per_category"]["port_scan"]["tp"] == 1
    assert r["per_category"]["excessive_connections"]["fp"] == 1
    assert (
        r["per_category"]["excessive_connections"]["fp_by_negative_type"]["other_attack"]["k"] == 1
    )
    assert r["unexpected_events"][0]["category"] == "excessive_connections"


def test_events_are_attributed_by_source_and_time_slot_only() -> None:
    t = trial(1, "positive", "port_scan", ["port_scan"])
    other_src = ev(2, "port_scan")
    too_late = ev(1, "port_scan", dt=400)  # after this trial's 330 s slot: belongs to a reuse
    too_early = ev(1, "port_scan", dt=-50)
    r = S.score([t], [other_src, too_late, too_early], ("port_scan",))
    assert r["per_category"]["port_scan"]["tp"] == 0 and r["per_category"]["port_scan"]["fn"] == 1


def test_evasion_trials_are_reported_separately_and_not_in_core_recall() -> None:
    trials = [
        trial(1, "evasion", "port_scan", ["port_scan"], "fin_scan"),
        trial(2, "evasion", "port_scan", ["port_scan"], "fin_scan"),
        trial(3, "positive", "port_scan", ["port_scan"]),
    ]
    events = [ev(2, "port_scan"), ev(3, "port_scan")]
    r = S.score(trials, events, ("port_scan", "excessive_connections"))
    m = r["per_category"]["port_scan"]
    assert (m["tp"], m["fn"]) == (1, 0)  # evasion trials do not enter core recall
    assert m["fp"] == 0 and m["tn"] == 0  # nor the negatives
    assert r["evasion"]["fin_scan"]["n"] == 2 and r["evasion"]["fin_scan"]["detected"] == 1
    # for an unrelated category the same evasion trials ARE negatives
    assert r["per_category"]["excessive_connections"]["tn"] == 3


def test_invalid_trials_are_excluded_visibly_not_silently() -> None:
    bad = trial(1, "positive", "port_scan", ["port_scan"])
    bad.update(valid=False, invalid_reason="nmap exited 1")
    never = {"trial_id": "T9", "kind": "positive", "category": "port_scan", "expect": ["port_scan"]}
    r = S.score([bad, never, trial(2, "normal", "none", [])], [], ("port_scan",))
    assert r["trials_scored"] == 1
    assert {e["trial_id"] for e in r["trials_excluded"]} == {"T1", "T9"}
    assert "nmap exited 1" in json.dumps(r["trials_excluded"])


def test_latency_uses_the_first_event_of_the_category() -> None:
    trials = [trial(1, "positive", "port_scan", ["port_scan"])]
    events = [ev(1, "port_scan", dt=4.0, crossed=3.0), ev(1, "port_scan", dt=2.0, crossed=1.5)]
    m = S.score(trials, events, ("port_scan",))["per_category"]["port_scan"]
    assert m["detection_delay_s"]["median"] == 2.0 and m["crossing_to_commit_s"]["median"] == 0.5


def test_report_mentions_every_category_and_flags_exclusions() -> None:
    trials = [trial(1, "positive", "port_scan", ["port_scan"]), trial(2, "normal", "none", [])]
    r = S.score(trials, [ev(1, "port_scan")], ("port_scan",))
    text = S.report_markdown(r, {"split": "tuning"})
    assert "port_scan" in text and "95% CI" in text and "Known-evasion" in text


def test_attribution_window_edges() -> None:
    t = trial(1, "positive", "port_scan", ["port_scan"])
    t0 = t["t_start"]
    on_lower = {
        "src": t["src_ip"],
        "category": "port_scan",
        "severity": "high",
        "created": t0 - S.PRE_SLACK,
        "crossed_at": None,
    }
    at_upper = {**on_lower, "created": t0 + S.ATTRIBUTION_SECONDS}
    just_inside = {**on_lower, "created": t0 + S.ATTRIBUTION_SECONDS - 0.001}
    assert S.attribute(t, [on_lower]) == [on_lower]  # lower edge inclusive
    assert (
        S.attribute(t, [at_upper]) == []
    )  # upper edge exclusive: that instant belongs to the next reuse
    assert S.attribute(t, [just_inside]) == [just_inside]


# ------------------------------------------------------------------ runner support
from evalkit import support as U  # noqa: E402


def test_allocator_never_reuses_an_address_inside_the_gap() -> None:
    a = U.IpAllocator(gap=330.0, pools={"x": (1, 3)})
    now, seen = 0.0, []
    for _ in range(3):
        ip, wait = a.acquire("x", now)
        assert wait == 0.0 and ip not in seen
        seen.append(ip)
        a.release(ip, now + 10)
        now += 10
    ip, wait = a.acquire("x", now)  # all three used within the gap: must wait for the oldest
    assert ip == seen[0] and wait == pytest.approx(330 - 20)
    ip, wait = a.acquire("x", now + 400)
    assert wait == 0.0


def test_allocator_pools_are_disjoint_and_inside_the_subnet() -> None:
    a = U.IpAllocator()
    atk, nrm = set(a.addresses("ng-attacker")), set(a.addresses("ng-normal"))
    assert not atk & nrm
    reserved = {f"10.10.10.{n}" for n in (1, 10, 20, 30)}
    assert not (atk | nrm) & reserved and all(x.startswith("10.10.10.") for x in atk | nrm)


def _rule(**kw: Any) -> dict[str, Any]:
    r = {
        "key": "port_scan",
        "version": 1,
        "enabled": True,
        "severity": "high",
        "threshold": 15,
        "window_seconds": 10,
        "cooldown_seconds": 60,
        "params": {},
    }
    return {**r, **kw}


def test_diff_rules_detects_every_kind_of_drift() -> None:
    base = [_rule(), _rule(key="auth_failures")]
    assert U.diff_rules(base, [dict(r) for r in base]) == []
    for change in (
        {"threshold": 16},
        {"version": 2},
        {"enabled": False},
        {"severity": "low"},
        {"window_seconds": 11},
        {"cooldown_seconds": 1},
        {"params": {"a": 1}},
    ):
        assert U.diff_rules(base, [_rule(**change), _rule(key="auth_failures")]), change
    assert U.diff_rules(base, base[:1]) and U.diff_rules(base[:1], base)


def test_invalid_reason_flags_generators_that_did_not_deliver() -> None:
    flood = {"scenario": "flood", "params": {"n": 100}}
    assert U.invalid_reason(flood, {"rc": 0, "driver": {"attempts": 100}}) is None
    assert "99 of 100" in (U.invalid_reason(flood, {"rc": 0, "driver": {"attempts": 99}}) or "")
    assert U.invalid_reason(flood, {"rc": 1, "tail": "boom"}) is not None
    vol = {"scenario": "udp_rate", "params": {"mbps": 10.0}}
    assert U.invalid_reason(vol, {"rc": 0, "driver": {"achieved_mbps": 9.0}}) is None
    assert U.invalid_reason(vol, {"rc": 0, "driver": {"achieved_mbps": 8.9}}) is not None
    ssh = {"scenario": "ssh_fail", "params": {"attempts": 5}}
    ok = {"ssh_rcs": [5] * 5, "logged_failures": 5}
    assert U.invalid_reason(ssh, ok) is None
    assert U.invalid_reason(ssh, {**ok, "logged_failures": 4}) is not None
    assert U.invalid_reason(ssh, {**ok, "ssh_rcs": [5, 5, 5, 5, 255]}) is not None
    nm = {"scenario": "normal_mix", "params": {"http": 10, "bulk_mbps": 1.0}}
    assert (
        U.invalid_reason(nm, {"rc": 0, "driver": {"http_ok": 9, "bulk": {"achieved_mbps": 1.0}}})
        is not None
    )
    assert (
        U.invalid_reason(nm, {"rc": 0, "driver": {"http_ok": 10, "bulk": {"achieved_mbps": 1.0}}})
        is None
    )


def test_scoring_accepts_decimal_values_from_postgres() -> None:
    from decimal import Decimal

    t = trial(1, "positive", "port_scan", ["port_scan"])
    e = ev(1, "port_scan")
    e["created"], e["crossed_at"] = Decimal(str(e["created"])), Decimal(str(e["crossed_at"]))
    m = S.score([t], [e], ("port_scan",))["per_category"]["port_scan"]
    assert m["tp"] == 1 and m["detection_delay_s"]["median"] == 1.5
