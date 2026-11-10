"""Rule framework: configuration, detections and the abstract Rule.

Rules are small state machines fed with parsed packets (or log-derived auth failures). They only
*detect*; deduplication, escalation, cooldown and persistence belong to the engine. All state is
bounded: a rule never keeps more than MAX_STATE_KEYS keys, so an attacker cannot exhaust memory
by varying source addresses.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from typing import Any, ClassVar, NamedTuple

from netguard_common.enums import DetectionCategory, Protocol, Severity
from netguard_monitor.capture.parser import Packet

SEVERITY_ORDER: tuple[str, ...] = tuple(s.value for s in Severity)
MAX_STATE_KEYS = 10_000
SWEEP_EVERY = 30.0


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(str(severity))


def bump(severity: str, steps: int = 1) -> str:
    """Raise a severity by `steps` levels, capped at critical."""
    return SEVERITY_ORDER[min(severity_rank(severity) + steps, len(SEVERITY_ORDER) - 1)]


def int_param(params: dict[str, Any], name: str, default: int, lo: int, hi: int) -> int:
    """Read an integer rule parameter, clamped to [lo, hi]. Bad types fall back to the default."""
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        value = default
    return max(lo, min(hi, value))


@dataclass(frozen=True)
class RuleDefaults:
    severity: Severity
    threshold: int
    window_seconds: int
    cooldown_seconds: int
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleConfig:
    """The effective configuration of one rule, as stored in detection_rules."""

    rule_id: int
    version: int
    key: str
    enabled: bool
    severity: str
    threshold: int
    window_seconds: int
    cooldown_seconds: int
    params: dict[str, Any] = field(default_factory=dict)


class AuthFailure(NamedTuple):
    """One failed login read from the authentication log. The username is deliberately not kept."""

    ts_utc: float
    src_ip: str


@dataclass
class Detection:
    """A rule's statement that its condition holds right now. The engine coalesces repeats."""

    rule_key: str
    ts: float
    src_ip: str
    dst_ip: str | None
    dst_port: int | None
    protocol: Protocol | None
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    dedup_key: str


class Rule(ABC):
    key: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[DetectionCategory]
    defaults: ClassVar[RuleDefaults]

    def __init__(self, cfg: RuleConfig) -> None:
        self.cfg = cfg
        self.capped = 0  # keys refused because the state cap was reached (visible, not silent)
        self._last_sweep = 0.0

    def reconfigure(self, cfg: RuleConfig) -> None:
        self.cfg = cfg

    def on_packet(self, p: Packet) -> list[Detection]:
        return []

    def on_auth_failure(self, f: AuthFailure) -> list[Detection]:
        return []

    def evaluate(self, now: float) -> list[Detection]:
        """Time-driven checks and housekeeping; called every engine tick."""
        return []

    def sweep_due(self, now: float) -> bool:
        if now - self._last_sweep >= SWEEP_EVERY:
            self._last_sweep = now
            return True
        return False
