"""Closed vocabularies shared by the API and the monitor. Values are stored as text + CHECK."""

from enum import StrEnum


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    DISMISSED = "dismissed"


class DetectionCategory(StrEnum):
    PORT_SCAN = "port_scan"
    EXCESSIVE_CONNECTIONS = "excessive_connections"
    AUTH_FAILURES = "auth_failures"
    ABNORMAL_TRAFFIC = "abnormal_traffic"
    SUSPICIOUS_DNS = "suspicious_dns"


class Transport(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class Protocol(StrEnum):
    """Classified protocol: transport, or the application protocol when it can be inferred."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    OTHER = "other"


class AppProtocol(StrEnum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"


class DeviceStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class DiscoverySource(StrEnum):
    PASSIVE_ARP = "passive_arp"
    ACTIVE_ARP = "active_arp"
    TRAFFIC = "traffic"


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"


class MonitorState(StrEnum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"


class ActorType(StrEnum):
    USER = "user"
    SYSTEM = "system"
    MONITOR = "monitor"
