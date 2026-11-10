"""Detection engine: feeds rules, deduplicates their detections into events, emits persistence ops.

One *open event* exists per dedup key. Repeated detections update it instead of creating new rows:
hits are coalesced and flushed at most every HIT_FLUSH_SECONDS, except an escalation (higher
severity), which is sent immediately. An event closes after `cooldown_seconds` without a hit;
a later detection then opens a new event. Ops are plain JSON-serialisable dicts so the existing
exactly-once batch/spill machinery can carry them.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from netguard_monitor.capture.parser import Packet
from netguard_monitor.ids.base import AuthFailure, Detection, Rule, RuleConfig, severity_rank
from netguard_monitor.ids.rules import ALL_RULES

log = logging.getLogger(__name__)

HIT_FLUSH_SECONDS = 2.0


@dataclass
class _Open:
    event_uuid: str
    dedup_key: str
    rule_key: str
    severity: str
    last_ts: float
    unflushed: int
    last_flush: float
    evidence: dict[str, Any]
    title: str


class IdsEngine:
    def __init__(self, configs: Sequence[RuleConfig]) -> None:
        self.rules: dict[str, Rule] = {}
        by_key = {c.key: c for c in configs}
        for cls in ALL_RULES:
            cfg = by_key.get(cls.key)
            if cfg is not None:
                self.rules[cls.key] = cls(cfg)
        self._open: dict[str, _Open] = {}
        self._ops: list[dict[str, Any]] = []
        self.detections = 0

    # ------------------------------------------------------------------ inputs

    def on_packet(self, p: Packet) -> None:
        for rule in self.rules.values():
            if rule.cfg.enabled:
                for det in rule.on_packet(p):
                    self._handle(det)

    def on_auth_failure(self, f: AuthFailure) -> None:
        for rule in self.rules.values():
            if rule.cfg.enabled:
                for det in rule.on_auth_failure(f):
                    self._handle(det)

    def tick(self, now: float) -> None:
        """Time-driven work: rule evaluation, hit flushing and event closing."""
        for rule in self.rules.values():
            if rule.cfg.enabled:
                for det in rule.evaluate(now):
                    self._handle(det)
        for key, st in list(self._open.items()):
            owner = self.rules.get(st.rule_key)
            cooldown = owner.cfg.cooldown_seconds if owner else 0
            if now - st.last_ts >= cooldown:
                self._flush_hits(st)
                self._ops.append({"op": "close", "dedup_key": key, "closed_at": now})
                del self._open[key]
            elif st.unflushed and now - st.last_flush >= HIT_FLUSH_SECONDS:
                self._flush_hits(st)
                st.last_flush = now

    def drain_ops(self) -> list[dict[str, Any]]:
        ops, self._ops = self._ops, []
        return ops

    def flush(self) -> None:
        """Shutdown: write pending hits but leave events open (they resume after a restart)."""
        for st in self._open.values():
            self._flush_hits(st)

    # ------------------------------------------------------------------ internals

    def _flush_hits(self, st: _Open) -> None:
        if st.unflushed:
            self._ops.append(
                {
                    "op": "hit",
                    "dedup_key": st.dedup_key,
                    "hits": st.unflushed,
                    "last_seen": st.last_ts,
                    "evidence": st.evidence,
                    "severity": st.severity,
                    "escalate": False,
                    "title": st.title,
                }
            )
            st.unflushed = 0

    def _handle(self, det: Detection) -> None:
        self.detections += 1
        rule = self.rules[det.rule_key]
        st = self._open.get(det.dedup_key)
        if st is None:
            ev_uuid = str(uuid.uuid4())
            self._open[det.dedup_key] = _Open(
                ev_uuid,
                det.dedup_key,
                det.rule_key,
                det.severity,
                det.ts,
                0,
                det.ts,
                det.evidence,
                det.title,
            )
            self._ops.append(
                {
                    "op": "open",
                    "event_uuid": ev_uuid,
                    "rule_id": rule.cfg.rule_id,
                    "rule_version": rule.cfg.version,
                    "category": rule.category.value,
                    "severity": det.severity,
                    "src_ip": det.src_ip,
                    "dst_ip": det.dst_ip,
                    "dst_port": det.dst_port,
                    "protocol": det.protocol.value if det.protocol else None,
                    "title": det.title,
                    "description": det.description,
                    "evidence": det.evidence,
                    "dedup_key": det.dedup_key,
                    "detected_at": det.ts,
                    "hits": 1,
                }
            )
            return
        st.unflushed += 1
        st.last_ts = max(st.last_ts, det.ts)
        st.evidence = det.evidence
        st.title = det.title
        if severity_rank(det.severity) > severity_rank(st.severity):
            st.severity = det.severity
            self._ops.append(
                {
                    "op": "hit",
                    "dedup_key": st.dedup_key,
                    "hits": st.unflushed,
                    "last_seen": st.last_ts,
                    "evidence": st.evidence,
                    "severity": st.severity,
                    "escalate": True,
                    "title": det.title,
                }
            )
            st.unflushed = 0
            st.last_flush = det.ts

    # ------------------------------------------------------------------ configuration / restart

    def reconfigure(self, configs: Iterable[RuleConfig]) -> None:
        for cfg in configs:
            rule = self.rules.get(cfg.key)
            if rule is not None and (rule.cfg != cfg):
                rule.reconfigure(cfg)

    def restore_open(self, rows: Iterable[dict[str, Any]]) -> None:
        """Adopt events still open in the database after a restart, so they keep coalescing."""
        for r in rows:
            key = r["dedup_key"]
            if key in self._open or r["rule_key"] not in self.rules:
                continue
            self._open[key] = _Open(
                str(r["event_uuid"]),
                key,
                r["rule_key"],
                r["severity"],
                float(r["last_seen"]),
                0,
                float(r["last_seen"]),
                r.get("evidence") or {},
                r.get("title") or "",
            )

    @property
    def open_events(self) -> int:
        return len(self._open)

    @property
    def capped_total(self) -> int:
        return sum(r.capped for r in self.rules.values())
