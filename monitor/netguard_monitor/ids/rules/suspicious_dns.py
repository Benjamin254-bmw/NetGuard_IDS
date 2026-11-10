"""R5 suspicious DNS: query-rate bursts, many distinct names, over-long labels, watch-listed names.

Works on DNS *query names* only (metadata). Each indicator is a separate event per source so an
analyst can see which one fired:
  query_rate     >= threshold queries within the window
  distinct_names >= params.distinct_names different names within the window
  long_label     any label longer than params.max_label_length (tunnelling / DGA-like names)
  watchlist      the name equals or is a subdomain of an entry in params.watchlist
"""

from __future__ import annotations

from collections import Counter, deque
from typing import Any

from netguard_common.enums import DetectionCategory, Protocol, Severity
from netguard_monitor.capture.parser import Packet
from netguard_monitor.ids.base import (
    MAX_STATE_KEYS,
    Detection,
    Rule,
    RuleConfig,
    RuleDefaults,
    int_param,
    severity_rank,
)

MAX_NAMES_PER_SRC = 5_000


class _Src:
    __slots__ = ("crossed", "names", "q")

    def __init__(self) -> None:
        self.q: deque[tuple[float, str]] = deque()
        self.names: Counter[str] = Counter()
        self.crossed: dict[str, float] = {}


class SuspiciousDns(Rule):
    key = "suspicious_dns"
    name = "Suspicious DNS activity"
    category = DetectionCategory.SUSPICIOUS_DNS
    description = (
        "DNS behaviour that is unusual for a small network: query bursts, many distinct names, "
        "very long labels or names on the watch list."
    )
    defaults = RuleDefaults(
        Severity.LOW,
        100,
        60,
        300,
        {
            "distinct_names": 50,
            "max_label_length": 52,
            "watchlist": [],
            "watchlist_severity": "medium",
        },
    )

    def __init__(self, cfg: RuleConfig) -> None:
        super().__init__(cfg)
        self._s: dict[str, _Src] = {}
        self._watch: tuple[str, ...] = ()
        self.reconfigure(cfg)

    def reconfigure(self, cfg: RuleConfig) -> None:
        super().reconfigure(cfg)
        raw: Any = cfg.params.get("watchlist", [])
        self._watch = tuple(
            sorted({w.strip().lower().rstrip(".") for w in raw if isinstance(w, str) and w.strip()})
            if isinstance(raw, list)
            else ()
        )

    def _watched(self, name: str) -> str | None:
        for w in self._watch:
            if name == w or name.endswith("." + w):
                return w
        return None

    def on_packet(self, p: Packet) -> list[Detection]:
        name = p.dns_qname
        if name is None or p.protocol is not Protocol.DNS:
            return []
        c = self.cfg
        s = self._s.get(p.src_ip)
        if s is None:
            if len(self._s) >= MAX_STATE_KEYS:
                self.capped += 1
                return []
            s = self._s[p.src_ip] = _Src()
        ts = p.ts_utc
        cutoff = ts - c.window_seconds
        while s.q and s.q[0][0] < cutoff:
            _, old = s.q.popleft()
            s.names[old] -= 1
            if s.names[old] <= 0:
                del s.names[old]
        s.q.append((ts, name))
        s.names[name] += 1
        while len(s.q) > MAX_NAMES_PER_SRC:
            _, old = s.q.popleft()
            s.names[old] -= 1
            if s.names[old] <= 0:
                del s.names[old]

        out: list[Detection] = []
        rate, distinct = len(s.q), len(s.names)
        if rate >= c.threshold:
            out.append(
                self._det(
                    p,
                    "query_rate",
                    c.severity,
                    f"{rate} DNS queries within {c.window_seconds}s",
                    {"queries": rate, "threshold": c.threshold},
                    s,
                )
            )
        else:
            s.crossed.pop("query_rate", None)
        limit = int_param(c.params, "distinct_names", 50, 2, 100_000)
        if distinct >= limit:
            out.append(
                self._det(
                    p,
                    "distinct_names",
                    c.severity,
                    f"{distinct} distinct names queried within {c.window_seconds}s",
                    {"distinct_names": distinct, "threshold": limit},
                    s,
                )
            )
        else:
            s.crossed.pop("distinct_names", None)
        max_label = int_param(c.params, "max_label_length", 52, 16, 63)
        longest = max((len(x) for x in name.split(".")), default=0)
        if longest > max_label:
            out.append(
                self._det(
                    p,
                    "long_label",
                    c.severity,
                    f"a query label of {longest} characters (limit {max_label})",
                    {
                        "longest_label": longest,
                        "max_label_length": max_label,
                        "example_name": name[:80],
                    },
                    s,
                )
            )
        hit = self._watched(name)
        if hit is not None:
            ws = str(c.params.get("watchlist_severity", "medium"))
            try:
                severity_rank(ws)
            except ValueError:
                ws = "medium"
            out.append(
                self._det(
                    p,
                    "watchlist",
                    ws,
                    f"a query for watch-listed name {hit}",
                    {"watchlist_entry": hit, "name": name[:80]},
                    s,
                )
            )
        return out

    def _det(
        self,
        p: Packet,
        indicator: str,
        severity: str,
        what: str,
        evidence: dict[str, Any],
        s: _Src,
    ) -> Detection:
        crossed = s.crossed.setdefault(indicator, p.ts_utc)
        evidence = {
            **evidence,
            "indicator": indicator,
            "window_seconds": self.cfg.window_seconds,
            "crossed_at": crossed,
        }
        return Detection(
            self.key,
            p.ts_utc,
            p.src_ip,
            p.dst_ip,
            p.dst_port,
            Protocol.DNS,
            severity,
            f"Suspicious DNS ({indicator}) from {p.src_ip}",
            f"{p.src_ip} made {what}.",
            evidence,
            f"{self.key}|{p.src_ip}|{indicator}",
        )

    def evaluate(self, now: float) -> list[Detection]:
        if self.sweep_due(now):
            cutoff = now - self.cfg.window_seconds
            for ip in [k for k, s in self._s.items() if not s.q or s.q[-1][0] < cutoff]:
                del self._s[ip]
        return []
