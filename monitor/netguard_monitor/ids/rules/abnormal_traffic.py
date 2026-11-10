"""R4 abnormal traffic volume: a local host sends far more data than the configured limit.

Average bytes per second sent by each source inside the authorised subnet over the window,
from per-second buckets. Inbound traffic (source outside the subnet) is ignored: the rule is about
hosts we are responsible for, and external sources cannot be baselined. The threshold is an
absolute limit chosen by the administrator, not a learned baseline (see ADR).
"""

from __future__ import annotations

from collections import deque

from netguard_common.enums import DetectionCategory, Severity
from netguard_monitor.capture.parser import DIRECTION_INBOUND, Packet
from netguard_monitor.ids.base import MAX_STATE_KEYS, Detection, Rule, RuleDefaults, bump

ESCALATE_FACTOR = 4


class AbnormalTraffic(Rule):
    key = "abnormal_traffic"
    name = "Abnormal traffic volume"
    category = DetectionCategory.ABNORMAL_TRAFFIC
    description = (
        "A local host sent data at a sustained rate above the configured limit "
        "(average bytes per second over the window)."
    )
    defaults = RuleDefaults(Severity.MEDIUM, 5_000_000, 10, 60)

    def __init__(self, cfg):  # type: ignore[no-untyped-def]
        super().__init__(cfg)
        self._b: dict[str, deque[list[int]]] = {}  # src -> [[second, bytes], ...] ascending
        self._crossed: dict[str, float] = {}

    def on_packet(self, p: Packet) -> list[Detection]:
        if p.direction == DIRECTION_INBOUND:
            return []
        q = self._b.get(p.src_ip)
        if q is None:
            if len(self._b) >= MAX_STATE_KEYS:
                self.capped += 1
                return []
            q = self._b[p.src_ip] = deque()
        sec = int(p.ts_utc)
        if q and q[-1][0] == sec:
            q[-1][1] += p.size
        else:
            q.append([sec, p.size])
        return []

    def evaluate(self, now: float) -> list[Detection]:
        c = self.cfg
        cutoff = int(now) - c.window_seconds
        out: list[Detection] = []
        for src in list(self._b):
            q = self._b[src]
            while q and q[0][0] <= cutoff:
                q.popleft()
            if not q:
                del self._b[src]
                self._crossed.pop(src, None)
                continue
            total = sum(b for _, b in q)
            avg = total / c.window_seconds
            if avg < c.threshold:
                self._crossed.pop(src, None)
                continue
            crossed = self._crossed.setdefault(src, now)
            sev = bump(c.severity) if avg >= ESCALATE_FACTOR * c.threshold else c.severity
            out.append(
                Detection(
                    self.key,
                    now,
                    src,
                    None,
                    None,
                    None,
                    sev,
                    f"Abnormal traffic volume from {src}",
                    f"{src} sent {avg:,.0f} bytes/s on average over {c.window_seconds}s "
                    f"(limit {c.threshold:,} bytes/s).",
                    {
                        "avg_bytes_per_second": round(avg),
                        "peak_bytes_per_second": max(b for _, b in q),
                        "window_seconds": c.window_seconds,
                        "threshold": c.threshold,
                        "crossed_at": crossed,
                    },
                    f"{self.key}|{src}",
                )
            )
        return out
