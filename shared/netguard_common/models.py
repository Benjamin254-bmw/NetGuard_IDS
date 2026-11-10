"""SQLAlchemy schema. Migrations (migrations/) are the source of truth for deployed databases;
`alembic check` fails if these models and the migrations drift apart."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from netguard_common import enums as e

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = sa.MetaData(naming_convention=NAMING)


def enum_type(cls: type[enum.StrEnum], name: str) -> sa.Enum:
    """Text column + named CHECK (not a PG enum type, which cannot drop values)."""
    return sa.Enum(
        cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        validate_strings=True,
        values_callable=lambda c: [m.value for m in c],
    )


def tstz() -> TIMESTAMP:
    return TIMESTAMP(timezone=True)


NOW = sa.text("now()")
EMPTY_OBJ = sa.text("'{}'::jsonb")
SEVERITY_RANK_SQL = (
    "CASE severity WHEN 'informational' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 "
    "WHEN 'high' THEN 3 WHEN 'critical' THEN 4 ELSE -1 END"
)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        sa.CheckConstraint("username ~ '^[A-Za-z0-9_.-]{3,64}$'", name="username_format"),
        sa.Index("uq_users_username_lower", sa.func.lower(sa.text("username")), unique=True),
        sa.Index(
            "uq_users_email_lower",
            sa.func.lower(sa.text("email")),
            unique=True,
            postgresql_where=sa.text("email IS NOT NULL"),
        ),
    )
    id: Mapped[int] = mapped_column(sa.BigInteger, sa.Identity(), primary_key=True)
    username: Mapped[str] = mapped_column(sa.Text)
    email: Mapped[str | None] = mapped_column(sa.Text)
    password_hash: Mapped[str] = mapped_column(sa.Text)  # Argon2id encoded hash
    role: Mapped[e.UserRole] = mapped_column(
        enum_type(e.UserRole, "role"), server_default=e.UserRole.ADMIN.value
    )
    is_active: Mapped[bool] = mapped_column(server_default=sa.true())
    created_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    last_login_at: Mapped[datetime | None] = mapped_column(tstz())


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        sa.CheckConstraint("family(ip) = 4 AND masklen(ip) = 32", name="ip_v4_host"),
        sa.CheckConstraint("last_seen >= first_seen", name="seen_order"),
        sa.CheckConstraint("hostname IS NULL OR length(hostname) <= 255", name="hostname_len"),
        sa.Index("uq_devices_mac", "mac", unique=True, postgresql_where=sa.text("mac IS NOT NULL")),
        sa.Index("ix_devices_ip", "ip"),
        sa.Index("ix_devices_status_last_seen", "status", "last_seen"),
    )
    id: Mapped[int] = mapped_column(sa.BigInteger, sa.Identity(), primary_key=True)
    ip: Mapped[str] = mapped_column(INET)
    mac: Mapped[str | None] = mapped_column(MACADDR)
    hostname: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[e.DeviceStatus] = mapped_column(
        enum_type(e.DeviceStatus, "status"), server_default=e.DeviceStatus.ACTIVE.value
    )
    discovery_source: Mapped[e.DiscoverySource] = mapped_column(
        enum_type(e.DiscoverySource, "discovery_source")
    )
    first_seen: Mapped[datetime] = mapped_column(tstz())
    last_seen: Mapped[datetime] = mapped_column(tstz())
    created_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)


class TrafficStat1s(Base):
    """Global per-protocol traffic counters, 1-second buckets (short retention, e.g. 24 h)."""

    __tablename__ = "traffic_stats_1s"
    __table_args__ = (
        sa.CheckConstraint(
            "packets >= 0 AND bytes >= 0 AND new_connections >= 0", name="non_negative"
        ),
    )
    bucket_start: Mapped[datetime] = mapped_column(tstz(), primary_key=True)
    protocol: Mapped[e.Protocol] = mapped_column(
        enum_type(e.Protocol, "protocol"), primary_key=True
    )
    packets: Mapped[int] = mapped_column(sa.BigInteger)
    bytes: Mapped[int] = mapped_column(sa.BigInteger)
    new_connections: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("0"))


class ConnectionAggregate1m(Base):
    """Per-flow-key counters, 1-minute buckets (longer retention, e.g. 30 days).
    The monitor caps distinct keys per bucket so a scan cannot create unbounded rows."""

    __tablename__ = "connection_aggregates_1m"
    __table_args__ = (
        sa.CheckConstraint(
            "date_trunc('minute', bucket_start) = bucket_start", name="minute_aligned"
        ),
        sa.CheckConstraint("dst_port BETWEEN 0 AND 65535", name="port_range"),
        sa.CheckConstraint("packets >= 0 AND bytes >= 0 AND syn_count >= 0", name="non_negative"),
        sa.Index("ix_connection_aggregates_1m_src_ip_bucket_start", "src_ip", "bucket_start"),
        sa.Index("ix_connection_aggregates_1m_dst_port_bucket_start", "dst_port", "bucket_start"),
    )
    bucket_start: Mapped[datetime] = mapped_column(tstz(), primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET, primary_key=True)
    dst_ip: Mapped[str] = mapped_column(INET, primary_key=True)
    dst_port: Mapped[int] = mapped_column(sa.Integer, primary_key=True)  # 0 when portless (ICMP)
    transport: Mapped[e.Transport] = mapped_column(
        enum_type(e.Transport, "transport"), primary_key=True
    )
    app_protocol: Mapped[e.AppProtocol | None] = mapped_column(
        enum_type(e.AppProtocol, "app_protocol")
    )
    packets: Mapped[int] = mapped_column(sa.BigInteger)
    bytes: Mapped[int] = mapped_column(sa.BigInteger)
    syn_count: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("0"))


class DetectionRule(Base):
    """Current rule configuration. A DB trigger bumps `version` and snapshots every config change
    into detection_rule_versions, whoever makes the change. Rows are created by the monitor's rule
    registry (Phase 4), not by migrations."""

    __tablename__ = "detection_rules"
    __table_args__ = (
        sa.CheckConstraint("key ~ '^[a-z][a-z0-9_]{2,40}$'", name="key_format"),
        sa.CheckConstraint("threshold > 0", name="threshold_positive"),
        sa.CheckConstraint("window_seconds BETWEEN 1 AND 86400", name="window_range"),
        sa.CheckConstraint("cooldown_seconds BETWEEN 0 AND 86400", name="cooldown_range"),
        sa.CheckConstraint("jsonb_typeof(params) = 'object'", name="params_object"),
        sa.CheckConstraint("version >= 1", name="version_positive"),
    )
    id: Mapped[int] = mapped_column(sa.Integer, sa.Identity(), primary_key=True)
    key: Mapped[str] = mapped_column(sa.Text, unique=True)
    name: Mapped[str] = mapped_column(sa.Text)
    category: Mapped[e.DetectionCategory] = mapped_column(
        enum_type(e.DetectionCategory, "category")
    )
    description: Mapped[str] = mapped_column(sa.Text)
    enabled: Mapped[bool] = mapped_column(server_default=sa.true())
    severity: Mapped[e.Severity] = mapped_column(enum_type(e.Severity, "severity"))
    threshold: Mapped[int] = mapped_column(sa.BigInteger)
    window_seconds: Mapped[int] = mapped_column(sa.Integer)
    cooldown_seconds: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("60"))
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=EMPTY_OBJ)
    version: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("1"))
    created_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    updated_by: Mapped[int | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))


class DetectionRuleVersion(Base):
    """Immutable history of rule configuration (written only by the versioning trigger)."""

    __tablename__ = "detection_rule_versions"
    rule_id: Mapped[int] = mapped_column(
        sa.ForeignKey("detection_rules.id", ondelete="RESTRICT"), primary_key=True
    )
    version: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column()
    severity: Mapped[e.Severity] = mapped_column(enum_type(e.Severity, "severity"))
    threshold: Mapped[int] = mapped_column(sa.BigInteger)
    window_seconds: Mapped[int] = mapped_column(sa.Integer)
    cooldown_seconds: Mapped[int] = mapped_column(sa.Integer)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB)
    changed_by: Mapped[int | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))
    changed_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)


class SecurityEvent(Base):
    """One row per detection window. Repeated hits in an open window update the same row
    (hit_count/last_seen_at) via the partial unique index on dedup_key. The configuration that
    produced the event is preserved by the (rule_id, rule_version) reference."""

    __tablename__ = "security_events"
    __table_args__ = (
        sa.ForeignKeyConstraint(
            ["rule_id", "rule_version"],
            ["detection_rule_versions.rule_id", "detection_rule_versions.version"],
            name="fk_security_events_rule_version",
        ),
        sa.CheckConstraint("hit_count >= 1", name="hit_count_positive"),
        sa.CheckConstraint("last_seen_at >= detected_at", name="seen_order"),
        sa.CheckConstraint("dst_port IS NULL OR dst_port BETWEEN 0 AND 65535", name="port_range"),
        sa.CheckConstraint("family(src_ip) = 4", name="src_v4"),
        sa.Index(
            "uq_security_events_open_dedup",
            "dedup_key",
            unique=True,
            postgresql_where=sa.text("is_open"),
        ),
        sa.Index("ix_security_events_detected_at", sa.text("detected_at DESC")),
        sa.Index("ix_security_events_status_detected_at", "status", sa.text("detected_at DESC")),
        sa.Index("ix_security_events_src_ip_detected_at", "src_ip", sa.text("detected_at DESC")),
        sa.Index(
            "ix_security_events_category_detected_at", "category", sa.text("detected_at DESC")
        ),
        sa.Index(
            "ix_security_events_severity_rank_detected_at",
            sa.text("severity_rank DESC"),
            sa.text("detected_at DESC"),
        ),
        sa.Index("ix_security_events_rule_id_detected_at", "rule_id", sa.text("detected_at DESC")),
    )
    id: Mapped[int] = mapped_column(sa.BigInteger, sa.Identity(), primary_key=True)
    event_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), unique=True, server_default=sa.text("gen_random_uuid()")
    )
    category: Mapped[e.DetectionCategory] = mapped_column(
        enum_type(e.DetectionCategory, "category")
    )
    rule_id: Mapped[int] = mapped_column(sa.Integer)
    rule_version: Mapped[int] = mapped_column(sa.Integer)
    severity: Mapped[e.Severity] = mapped_column(enum_type(e.Severity, "severity"))
    severity_rank: Mapped[int] = mapped_column(
        sa.SmallInteger, sa.Computed(SEVERITY_RANK_SQL, persisted=True)
    )
    src_ip: Mapped[str] = mapped_column(INET)
    dst_ip: Mapped[str | None] = mapped_column(INET)
    dst_port: Mapped[int | None] = mapped_column(sa.Integer)
    protocol: Mapped[e.Protocol | None] = mapped_column(enum_type(e.Protocol, "protocol"))
    description: Mapped[str] = mapped_column(sa.Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=EMPTY_OBJ)
    dedup_key: Mapped[str] = mapped_column(sa.Text)
    is_open: Mapped[bool] = mapped_column(server_default=sa.true())
    hit_count: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("1"))
    detected_at: Mapped[datetime] = mapped_column(tstz())  # first detection, set by the monitor
    last_seen_at: Mapped[datetime] = mapped_column(tstz())
    created_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)  # DB insert time
    status: Mapped[e.EventStatus] = mapped_column(
        enum_type(e.EventStatus, "status"), server_default=e.EventStatus.NEW.value
    )
    status_updated_at: Mapped[datetime | None] = mapped_column(tstz())
    status_updated_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )


class Alert(Base):
    """Notification about an event (workflow: new -> acknowledged/dismissed). The investigation
    workflow lives on security_events.status."""

    __tablename__ = "alerts"
    __table_args__ = (
        sa.CheckConstraint("status = 'new' OR acknowledged_at IS NOT NULL", name="ack_timestamp"),
        sa.Index("ix_alerts_status_created_at", "status", sa.text("created_at DESC")),
        sa.Index("ix_alerts_event_id", "event_id"),
        sa.Index("ix_alerts_created_at", sa.text("created_at DESC")),
    )
    id: Mapped[int] = mapped_column(sa.BigInteger, sa.Identity(), primary_key=True)
    event_id: Mapped[int] = mapped_column(sa.ForeignKey("security_events.id", ondelete="CASCADE"))
    severity: Mapped[e.Severity] = mapped_column(enum_type(e.Severity, "severity"))
    title: Mapped[str] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    status: Mapped[e.AlertStatus] = mapped_column(
        enum_type(e.AlertStatus, "status"), server_default=e.AlertStatus.NEW.value
    )
    acknowledged_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(tstz())


class Setting(Base):
    __tablename__ = "settings"
    __table_args__ = (sa.CheckConstraint("key ~ '^[a-z][a-z0-9_.]{1,63}$'", name="key_format"),)
    key: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    updated_by: Mapped[int | None] = mapped_column(sa.ForeignKey("users.id", ondelete="SET NULL"))


class AuditLog(Base):
    """Append-only: runtime roles have INSERT and SELECT only."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        sa.CheckConstraint("action ~ '^[a-z_]+([.][a-z_]+)+$'", name="action_format"),
        sa.Index("ix_audit_logs_occurred_at", sa.text("occurred_at DESC")),
        sa.Index(
            "ix_audit_logs_actor_user_id_occurred_at", "actor_user_id", sa.text("occurred_at DESC")
        ),
        sa.Index("ix_audit_logs_action_occurred_at", "action", sa.text("occurred_at DESC")),
    )
    id: Mapped[int] = mapped_column(sa.BigInteger, sa.Identity(), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    actor_type: Mapped[e.ActorType] = mapped_column(enum_type(e.ActorType, "actor_type"))
    actor_user_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(sa.Text)
    target_type: Mapped[str | None] = mapped_column(sa.Text)
    target_id: Mapped[str | None] = mapped_column(sa.Text)
    source_ip: Mapped[str | None] = mapped_column(INET)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=EMPTY_OBJ)


class MonitorStatus(Base):
    """Single-row heartbeat. A heartbeat_at that is stale means the monitor is not running,
    regardless of the last state written."""

    __tablename__ = "monitor_status"
    __table_args__ = (
        sa.CheckConstraint("id = 1", name="singleton"),
        sa.CheckConstraint(
            "packets_captured >= 0 AND packets_dropped >= 0 AND capture_queue_depth >= 0 "
            "AND write_queue_depth >= 0 AND spill_backlog >= 0",
            name="non_negative",
        ),
        sa.CheckConstraint("jsonb_typeof(degraded_reasons) = 'array'", name="reasons_array"),
    )
    id: Mapped[int] = mapped_column(
        sa.SmallInteger, primary_key=True, autoincrement=False, server_default=sa.text("1")
    )
    state: Mapped[e.MonitorState] = mapped_column(enum_type(e.MonitorState, "state"))
    interface: Mapped[str | None] = mapped_column(sa.Text)
    started_at: Mapped[datetime | None] = mapped_column(tstz())
    heartbeat_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
    packets_captured: Mapped[int] = mapped_column(sa.BigInteger, server_default=sa.text("0"))
    packets_dropped: Mapped[int] = mapped_column(sa.BigInteger, server_default=sa.text("0"))
    packets_per_second: Mapped[float] = mapped_column(sa.Double, server_default=sa.text("0"))
    capture_queue_depth: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("0"))
    write_queue_depth: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("0"))
    spill_backlog: Mapped[int] = mapped_column(sa.Integer, server_default=sa.text("0"))
    degraded_reasons: Mapped[list[str]] = mapped_column(
        JSONB, server_default=sa.text("'[]'::jsonb")
    )
    last_error: Mapped[str | None] = mapped_column(sa.Text)
    version: Mapped[str | None] = mapped_column(sa.Text)


class IngestBatch(Base):
    """Ledger of batches the monitor has applied. A batch id is inserted in the same
    transaction as its data, so replaying a spilled batch (or re-applying after a crash)
    can never double count."""

    __tablename__ = "ingest_batches"
    __table_args__ = (sa.Index("ix_ingest_batches_applied_at", "applied_at"),)
    batch_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(tstz(), server_default=NOW)
