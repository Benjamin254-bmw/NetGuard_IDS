"""Least-privilege matrix for the runtime roles, as data. Applied by migrations and verified by
tests against the live database. The migrator role owns the objects and is not listed."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

# table -> role ("monitor" | "api") -> privileges. "UPDATE(a,b)" is a column-level grant.
GRANTS: dict[str, dict[str, tuple[str, ...]]] = {
    "users": {"api": ("SELECT", "INSERT", "UPDATE")},
    "devices": {"monitor": ("SELECT", "INSERT", "UPDATE"), "api": ("SELECT",)},
    "traffic_stats_1s": {"monitor": ("SELECT", "INSERT", "UPDATE", "DELETE"), "api": ("SELECT",)},
    "connection_aggregates_1m": {
        "monitor": ("SELECT", "INSERT", "UPDATE", "DELETE"),
        "api": ("SELECT",),
    },
    "detection_rules": {
        "monitor": ("SELECT", "INSERT", "UPDATE(name,description)"),
        "api": (
            "SELECT",
            "UPDATE(enabled,severity,threshold,window_seconds,cooldown_seconds,params,updated_by,updated_at)",
        ),
    },
    "detection_rule_versions": {"monitor": ("SELECT",), "api": ("SELECT",)},
    "security_events": {
        "monitor": ("SELECT", "INSERT", "UPDATE(severity,evidence,hit_count,last_seen_at,is_open)"),
        "api": ("SELECT", "UPDATE(status,status_updated_at,status_updated_by)"),
    },
    "alerts": {
        "monitor": ("SELECT", "INSERT"),
        "api": ("SELECT", "UPDATE(status,acknowledged_by,acknowledged_at)"),
    },
    "settings": {"monitor": ("SELECT",), "api": ("SELECT", "INSERT", "UPDATE")},
    "audit_logs": {"monitor": ("INSERT",), "api": ("SELECT", "INSERT")},
    "ingest_batches": {"monitor": ("SELECT", "INSERT", "DELETE")},
    "monitor_status": {"monitor": ("SELECT", "INSERT", "UPDATE"), "api": ("SELECT",)},
}


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def grant_statements(
    role_names: Mapping[str, str], tables: Iterable[str] | None = None
) -> list[str]:
    """REVOKE ALL then GRANT, per table and role. Idempotent; safe to re-run.
    Migrations pass the tables that exist at their revision so history stays reproducible."""
    only = set(tables) if tables is not None else None
    out: list[str] = []
    for table, per_role in GRANTS.items():
        if only is not None and table not in only:
            continue
        for role_key, role in role_names.items():
            out.append(f"REVOKE ALL ON {_q(table)} FROM {_q(role)}")
            for priv in per_role.get(role_key, ()):
                if "(" in priv:
                    verb, cols = priv.split("(", 1)
                    col_sql = ", ".join(_q(c.strip()) for c in cols.rstrip(")").split(","))
                    out.append(f"GRANT {verb} ({col_sql}) ON {_q(table)} TO {_q(role)}")
                else:
                    out.append(f"GRANT {priv} ON {_q(table)} TO {_q(role)}")
    return out
