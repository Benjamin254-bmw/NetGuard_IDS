from netguard_monitor.ids.base import Rule
from netguard_monitor.ids.rules.abnormal_traffic import AbnormalTraffic
from netguard_monitor.ids.rules.auth_failures import AuthFailures
from netguard_monitor.ids.rules.excessive_connections import ExcessiveConnections
from netguard_monitor.ids.rules.port_scan import PortScan
from netguard_monitor.ids.rules.suspicious_dns import SuspiciousDns

ALL_RULES: tuple[type[Rule], ...] = (
    PortScan,
    ExcessiveConnections,
    AuthFailures,
    AbnormalTraffic,
    SuspiciousDns,
)
__all__ = ["ALL_RULES"]
