#!/usr/bin/env bash
# Run a command as the invoking (non-root) user holding ONLY CAP_NET_RAW and CAP_NET_ADMIN.
# Usage: sudo scripts/run-with-caps.sh .venv/bin/python -m netguard_monitor.main check
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run via sudo." >&2; exit 1; }
[[ -n "${SUDO_UID:-}" && "${SUDO_UID}" != "0" ]] || { echo "Invoke with sudo from a normal user account." >&2; exit 1; }
[[ $# -ge 1 ]] || { echo "Usage: sudo $0 <command> [args...]" >&2; exit 2; }
# --reset-env gives the process the target user's own HOME/USER/LOGNAME (sudo leaves USER=root).
exec setpriv --reuid "$SUDO_UID" --regid "${SUDO_GID:?SUDO_GID not set}" --init-groups --reset-env \
  --inh-caps=+net_raw,+net_admin --ambient-caps=+net_raw,+net_admin \
  --bounding-set=-all,+net_raw,+net_admin -- "$@"
