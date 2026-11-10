"""R3 repeated authentication failures from one source, read from the sshd authentication log.

Network metadata alone cannot see a failed login (the payload is encrypted), so this rule is
log-based: it consumes AuthFailure records produced by the log tailer. Only the source address is
kept; usernames and any secrets in the log line are discarded.
"""

from __future__ import annotations

from collections import deque

from netguard_common.enums import DetectionCategory, Protocol, Severity
from netguard_monitor.ids.base import (
    MAX_STATE_KEYS,
    AuthFailure,
    Detection,
    Rule,
    RuleDefaults,
)

MAX_TIMES_PER_KEY = 5_000


class AuthFailures(Rule):
    key = "auth_failures"
    name = "Repeated authentication failures"
    category = DetectionCategory.AUTH_FAILURES
    description = (
        "A single source produced repeated failed logins within the window "
        "(from the SSH authentication log)."
    )
    defaults = RuleDefaults(Severity.HIGH, 5, 60, 300)

    def __init__(self, cfg):  # type: ignore[no-untyped-def]
        super().__init__(cfg)
        self._w: dict[str, deque[float]] = {}
        self._crossed: dict[str, float] = {}

    def on_auth_failure(self, f: AuthFailure) -> list[Detection]:
        c = self.cfg
        q = self._w.get(f.src_ip)
        if q is None:
            if len(self._w) >= MAX_STATE_KEYS:
                self.capped += 1
                return []
            q = self._w[f.src_ip] = deque()
        cutoff = f.ts_utc - c.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        q.append(f.ts_utc)
        if len(q) > MAX_TIMES_PER_KEY:
            q.popleft()
        n = len(q)
        if n < c.threshold:
            self._crossed.pop(f.src_ip, None)
            return []
        crossed = self._crossed.setdefault(f.src_ip, f.ts_utc)
        return [
            Detection(
                self.key,
                f.ts_utc,
                f.src_ip,
                None,
                22,
                Protocol.SSH,
                c.severity,
                f"Repeated authentication failures from {f.src_ip}",
                f"{n} failed logins from {f.src_ip} within {c.window_seconds}s.",
                {
                    "failures": n,
                    "window_seconds": c.window_seconds,
                    "threshold": c.threshold,
                    "crossed_at": crossed,
                },
                f"{self.key}|{f.src_ip}",
            )
        ]

    def evaluate(self, now: float) -> list[Detection]:
        if self.sweep_due(now):
            cutoff = now - self.cfg.window_seconds
            for ip in [k for k, q in self._w.items() if not q or q[-1] < cutoff]:
                del self._w[ip]
                self._crossed.pop(ip, None)
        return []
