#!/usr/bin/env bash
# Install NetGuard IDS as system services on this machine (Phase 8). Read docs/deployment.md first.
#
#   sudo deploy/install.sh [--api-port N] [--no-monitor]
#
# Run from the repository, with sudo, from your normal account (it builds as you, installs as root):
#   - applies migrations (your .env, migrator role), builds the dashboard and Python wheels AS YOU
#   - creates two system users without a shell or home: netguard-api, netguard-monitor
#   - installs a virtualenv in /opt/netguard/venv and the dashboard in /opt/netguard/www (root-owned, read-only)
#   - writes /etc/netguard/api.env and monitor.env (mode 600, only if absent) and a self-signed certificate
#   - installs the nginx site (HTTPS on 443) and the two systemd units, and starts them
# Re-running upgrades the code and keeps /etc/netguard (secrets, certificate, your monitor settings).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"
PREFIX=/opt/netguard
ETC=/etc/netguard
API_PORT=8100
START_MONITOR=1

die() { echo "install: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-port) API_PORT="${2:?}"; shift 2 ;;
    --no-monitor) START_MONITOR=0; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run with sudo: sudo deploy/install.sh"
U="${SUDO_USER:-}"
[[ -n "$U" && "$U" != root ]] || die "run with sudo from your normal account, not as root directly"
as_user() { sudo -u "$U" -H -- "$@"; }

step "preflight"
for c in nginx openssl python3 systemctl pg_isready ss; do command -v "$c" >/dev/null || die "'$c' not found (sudo apt install nginx)"; done
[[ -f .env ]] || die ".env missing: run 'make init-env' first"
[[ -x .venv/bin/python ]] || die ".venv missing: run 'make setup' first"
[[ -d frontend/node_modules ]] || die "frontend/node_modules missing: run 'make frontend-install' first"
[[ "$API_PORT" =~ ^[0-9]+$ ]] || die "--api-port must be a number"
pg_isready -q -h 127.0.0.1 || die "PostgreSQL is not accepting connections (sudo systemctl start postgresql@18-main)"
if ss -ltnH "sport = :443" | grep -q . && ! ss -ltnpH "sport = :443" 2>/dev/null | grep -q nginx; then
  die "port 443 is already used by something other than nginx"
fi
if ss -ltnH "sport = :$API_PORT" | grep -q . && ! systemctl is-active -q netguard-api; then
  die "port $API_PORT is in use; pick another with --api-port"
fi
# A development monitor (make monitor-run) writing to the same database would double-count everything.
DEV_MONITOR=0
for pid in $(pgrep -f 'netguard_monitor.main run' || true); do
  [[ "$(ps -o user= -p "$pid" | tr -d ' ')" != netguard-monitor ]] && DEV_MONITOR=1
done
echo "ok (installing as root, building as $U, API on 127.0.0.1:$API_PORT behind nginx)"

step "database migrations (as $U, migrator role from .env)"
as_user .venv/bin/python -m alembic upgrade head

step "requirements.lock"
if [[ ! -s requirements.lock ]]; then
  as_user make freeze
fi

step "build the dashboard (as $U)"
as_user bash -c 'cd frontend && npm run build --silent'

step "build Python wheels (as $U)"
WHEELS="$(mktemp -d)"; trap 'rm -rf "$WHEELS"' EXIT
chown "$U" "$WHEELS"
as_user .venv/bin/python -m pip wheel --quiet --disable-pip-version-check -w "$WHEELS" \
  -c requirements.lock ./shared ./backend ./monitor

step "service users"
for u in netguard-api netguard-monitor; do
  if id -u "$u" >/dev/null 2>&1; then echo "$u exists"
  else useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"; echo "created $u"; fi
done

step "stop running services (upgrade)"
systemctl stop netguard-monitor netguard-api 2>/dev/null || true

step "install code into $PREFIX"
install -d -m 755 "$PREFIX"
rm -rf "$PREFIX/venv" "$PREFIX/www" "$PREFIX/docs"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-index \
  --find-links "$WHEELS" netguard-common netguard-backend netguard-monitor
cp -r frontend/dist "$PREFIX/www"
install -d -m 755 "$PREFIX/docs"
cp docs/deployment.md docs/monitor.md docs/api.md docs/dashboard.md "$PREFIX/docs/"
chown -R root:root "$PREFIX"
chmod -R u=rwX,go=rX "$PREFIX"
"$PREFIX/venv/bin/python" -c "import app.main, netguard_monitor.main, netguard_common.config" \
  || die "the installed packages do not import"

step "configuration in $ETC (existing files are kept)"
install -d -m 755 "$ETC"
umask 077
for svc in api monitor; do
  f="$ETC/$svc.env"
  if [[ -e "$f" ]]; then echo "$f kept"
  else
    as_user .venv/bin/python deploy/render_env.py "$svc" --from .env --api-port "$API_PORT" > "$f.tmp"
    mv "$f.tmp" "$f"; echo "$f written"
  fi
  chown root:root "$f"; chmod 600 "$f"
done
umask 022
grep -q "^NETGUARD_API_PORT=\"$API_PORT\"$" "$ETC/api.env" \
  || die "$ETC/api.env has a different NETGUARD_API_PORT than --api-port $API_PORT; edit one of them"
install -d -m 700 "$ETC/tls"
deploy/make_cert.sh "$ETC/tls"

step "nginx site"
sed "s/__API_PORT__/$API_PORT/" deploy/nginx/netguard.conf > /etc/nginx/sites-available/netguard
ln -sf /etc/nginx/sites-available/netguard /etc/nginx/sites-enabled/netguard
if ! nginx -t 2>&1; then
  rm -f /etc/nginx/sites-enabled/netguard
  die "nginx rejected the configuration; the site was disabled again"
fi
systemctl enable -q nginx
systemctl reload-or-restart nginx

step "systemd units"
install -m 644 deploy/systemd/netguard-api.service deploy/systemd/netguard-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q --now netguard-api
if [[ $START_MONITOR -eq 0 ]]; then
  systemctl enable -q netguard-monitor; echo "netguard-monitor enabled, not started (--no-monitor)"
elif [[ $DEV_MONITOR -eq 1 ]]; then
  systemctl enable -q netguard-monitor
  echo "netguard-monitor enabled but NOT started: a development monitor is running."
  echo "  Stop it (Ctrl-C in its terminal), then: sudo systemctl start netguard-monitor"
else
  systemctl enable -q --now netguard-monitor
fi

step "verify"
sleep 3
deploy/verify.sh || true
echo
echo "Dashboard: https://$(hostname -s).local/  or  https://<this machine's address>/"
echo "Monitor settings: sudo nano $ETC/monitor.env, then sudo systemctl restart netguard-monitor"
