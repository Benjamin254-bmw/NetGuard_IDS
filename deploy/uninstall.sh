#!/usr/bin/env bash
# Remove the NetGuard system services (Phase 8).
#   sudo deploy/uninstall.sh           stop and remove services, nginx site and /opt/netguard;
#                                      KEEP /etc/netguard (secrets, certificate), the service users and the database
#   sudo deploy/uninstall.sh --purge   also delete /etc/netguard, /var/lib/netguard-monitor and the two users
# The database is never touched: drop it yourself if you mean to (docs/deployment.md).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
PURGE=0; [[ "${1:-}" == --purge ]] && PURGE=1
systemctl disable -q --now netguard-monitor netguard-api 2>/dev/null || true
rm -f /etc/systemd/system/netguard-monitor.service /etc/systemd/system/netguard-api.service
systemctl daemon-reload
rm -f /etc/nginx/sites-enabled/netguard /etc/nginx/sites-available/netguard
if nginx -t >/dev/null 2>&1; then systemctl reload nginx 2>/dev/null || true; fi
rm -rf /opt/netguard
if [[ $PURGE -eq 1 ]]; then
  rm -rf /etc/netguard /var/lib/netguard-monitor
  for u in netguard-api netguard-monitor; do id -u "$u" >/dev/null 2>&1 && userdel "$u"; done
  echo "removed services, site, code, configuration, state and users (database kept)"
else
  echo "removed services, site and code; kept /etc/netguard, the users and the database (--purge removes more)"
fi
