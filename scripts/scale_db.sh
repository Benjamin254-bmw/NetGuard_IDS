#!/usr/bin/env bash
# Create or drop the SCRATCH database used by the Phase 7 API scale test (lab/seed_scale.py).
#   scripts/scale_db.sh up     create 'netguard_scale' (+ migrate it); same roles and passwords as .env
#   scripts/scale_db.sh down   drop 'netguard_scale' and 'netguard_scale_test' (nothing else)
# Needs sudo to the postgres OS user, like scripts/db_init.sh. The development database is never touched.
set -euo pipefail
cd "$(dirname "$0")/.."
SCALE=netguard_scale
case "${1:-}" in
  up)
    TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
    grep -v '^NETGUARD_DB_NAME=' .env > "$TMP"; echo "NETGUARD_DB_NAME=$SCALE" >> "$TMP"
    NETGUARD_ENV_FILE="$TMP" scripts/db_init.sh
    NETGUARD_DB_NAME="$SCALE" .venv/bin/python -m alembic upgrade head
    echo "Scratch database '$SCALE' is ready. Seed it: NETGUARD_DB_NAME=$SCALE .venv/bin/python lab/seed_scale.py"
    ;;
  down)
    for d in "$SCALE" "${SCALE}_test"; do sudo -u postgres dropdb --if-exists "$d"; done
    echo "Dropped $SCALE and ${SCALE}_test."
    ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
