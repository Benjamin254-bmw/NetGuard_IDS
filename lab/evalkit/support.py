"""Pure helpers for the evaluation runner (no I/O, injectable clock) so they can be unit-tested."""

from __future__ import annotations

from typing import Any

from .plan import MIN_REUSE_GAP, POOLS, SUBNET_PREFIX

RULE_FIELDS = (
    "key",
    "version",
    "enabled",
    "severity",
    "threshold",
    "window_seconds",
    "cooldown_seconds",
    "params",
)
SSH_WRONG_PASSWORD_RC = 5  # sshpass: "invalid/incorrect password"
MIN_ACHIEVED = 0.9  # a generator must deliver at least this share of the requested rate


class IpAllocator:
    """Hands out a source address per trial and never reuses one within `gap` seconds of its last use.

    A source address is the join key between a trial and the events it caused, so two trials sharing
    an address inside the rules' cooldown would be indistinguishable. The allocator picks the
    longest-idle address; if even that is too recent it reports how long to wait.
    """

    def __init__(
        self, gap: float = MIN_REUSE_GAP, pools: dict[str, tuple[int, int]] | None = None
    ) -> None:
        self.gap = gap
        self._pools = pools or POOLS
        self._last: dict[str, float] = {}

    def addresses(self, ns: str) -> list[str]:
        lo, hi = self._pools[ns]
        return [f"{SUBNET_PREFIX}{n}" for n in range(lo, hi + 1)]

    def acquire(self, ns: str, now: float) -> tuple[str, float]:
        """(address, seconds to wait before using it)."""
        ip = min(self.addresses(ns), key=lambda a: self._last.get(a, float("-inf")))
        last = self._last.get(ip)
        wait = 0.0 if last is None else max(0.0, last + self.gap - now)
        return ip, wait

    def release(self, ip: str, t_end: float) -> None:
        self._last[ip] = t_end


def rule_snapshot(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(({k: r[k] for k in RULE_FIELDS} for r in rows), key=lambda r: r["key"])


def diff_rules(frozen: list[dict[str, Any]], live: list[dict[str, Any]]) -> list[str]:
    """Human-readable differences between the frozen rule set and the live one (empty = identical)."""
    f = {r["key"]: r for r in frozen}
    v = {r["key"]: r for r in live}
    out = [f"rule {k} is missing from the live configuration" for k in sorted(f.keys() - v.keys())]
    out += [
        f"rule {k} exists live but is not in the frozen set" for k in sorted(v.keys() - f.keys())
    ]
    for k in sorted(f.keys() & v.keys()):
        for field in RULE_FIELDS:
            if f[k][field] != v[k][field]:
                out.append(f"rule {k}: {field} frozen={f[k][field]!r} live={v[k][field]!r}")
    return out


def invalid_reason(trial: dict[str, Any], outcome: dict[str, Any]) -> str | None:
    """Why a trial did not do what the plan says (None = it did). Invalid trials are excluded from the
    metrics but listed in the report, never silently dropped."""
    p, sc = trial["params"], trial["scenario"]
    if sc == "ssh_fail":
        rcs = outcome.get("ssh_rcs", [])
        if len(rcs) != p["attempts"] or any(rc != SSH_WRONG_PASSWORD_RC for rc in rcs):
            return f"ssh attempts did not all reach a password rejection (exit codes {rcs})"
        if outcome.get("logged_failures", 0) < p["attempts"]:
            return f"sshd logged {outcome.get('logged_failures', 0)} failures for {p['attempts']} attempts"
        return None
    if outcome.get("rc") != 0:
        return f"generator exited {outcome.get('rc')}: {str(outcome.get('tail', ''))[-120:]}"
    d = outcome.get("driver") or {}
    if sc == "flood" and d.get("attempts") != p["n"]:
        return f"flood made {d.get('attempts')} of {p['n']} connections"
    if sc == "udp_rate" and d.get("achieved_mbps", 0) < MIN_ACHIEVED * p["mbps"]:
        return f"achieved {d.get('achieved_mbps')} MB/s of requested {p['mbps']} MB/s"
    if sc == "normal_mix":
        if d.get("http_ok") != p["http"]:
            return f"only {d.get('http_ok')} of {p['http']} HTTP requests succeeded"
        if (
            p["bulk_mbps"]
            and d.get("bulk", {}).get("achieved_mbps", 0) < MIN_ACHIEVED * p["bulk_mbps"]
        ):
            return "bulk transfer below requested rate"
    return None
