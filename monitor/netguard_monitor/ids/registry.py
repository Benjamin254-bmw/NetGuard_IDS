"""Rule registry: keeps detection_rules in step with the code without overwriting admin tuning."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Engine, text

from netguard_monitor.ids.base import RuleConfig
from netguard_monitor.ids.engine import IdsEngine
from netguard_monitor.ids.rules import ALL_RULES

_SYNC = text(
    """
    INSERT INTO detection_rules
      (key, name, category, description, severity, threshold, window_seconds,
       cooldown_seconds, params)
    VALUES (:key, :name, :category, :description, :severity, :threshold, :window,
            :cooldown, CAST(:params AS jsonb))
    ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
    """
)
_LOAD = text(
    """
    SELECT id, version, key, enabled, severity, threshold, window_seconds, cooldown_seconds, params
    FROM detection_rules ORDER BY id
    """
)
_OPEN = text(
    """
    SELECT e.event_uuid, e.dedup_key, r.key AS rule_key, e.severity, e.evidence,
           extract(epoch FROM e.last_seen_at) AS last_seen
    FROM security_events e JOIN detection_rules r ON r.id = e.rule_id
    WHERE e.is_open
    """
)


def sync_rules(engine: Engine) -> None:
    """Insert rules that do not exist yet (with code defaults). Existing thresholds, severity,
    enabled flag and params are the administrator's and are never overwritten here."""
    with engine.begin() as conn:
        for cls in ALL_RULES:
            d = cls.defaults
            conn.execute(
                _SYNC,
                {
                    "key": cls.key,
                    "name": cls.name,
                    "category": cls.category.value,
                    "description": cls.description,
                    "severity": d.severity.value,
                    "threshold": d.threshold,
                    "window": d.window_seconds,
                    "cooldown": d.cooldown_seconds,
                    "params": json.dumps(d.params),
                },
            )


def load_configs(engine: Engine) -> list[RuleConfig]:
    with engine.connect() as conn:
        rows = conn.execute(_LOAD).all()
    return [
        RuleConfig(
            rule_id=r.id,
            version=r.version,
            key=r.key,
            enabled=r.enabled,
            severity=str(r.severity),
            threshold=int(r.threshold),
            window_seconds=r.window_seconds,
            cooldown_seconds=r.cooldown_seconds,
            params=dict(r.params),
        )
        for r in rows
    ]


def load_open_windows(engine: Engine) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        return [
            {
                "event_uuid": r.event_uuid,
                "dedup_key": r.dedup_key,
                "rule_key": r.rule_key,
                "severity": str(r.severity),
                "evidence": dict(r.evidence),
                "last_seen": float(r.last_seen),
            }
            for r in conn.execute(_OPEN)
        ]


def build_engine(engine: Engine) -> IdsEngine:
    ids = IdsEngine(load_configs(engine))
    ids.restore_open(load_open_windows(engine))
    return ids
