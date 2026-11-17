#!/usr/bin/env bash
# Check an installed NetGuard (Phase 8). Read-only, except one deliberately failed sign-in (step 7).
#   sudo deploy/verify.sh        (sudo: reads the root-only env file and the service processes)
set -uo pipefail
cd "$(dirname "$0")/.."
ETC=/etc/netguard
BASE=https://127.0.0.1
FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
API_PORT="$(sed -n 's/^NETGUARD_API_PORT="\([0-9]*\)"$/\1/p' "$ETC/api.env" 2>/dev/null)"
API_PORT="${API_PORT:-8100}"

# 1. services
for s in nginx netguard-api netguard-monitor; do
  if systemctl is-active -q "$s"; then pass "$s is running"; else fail "$s is not running (journalctl -u $s -n 50)"; fi
done

# 2. the API is reachable only from this machine
bound="$(ss -ltnH "sport = :$API_PORT" | awk '{print $4}')"
if [[ -n "$bound" ]] && ! grep -qvE '^(127\.0\.0\.1|\[::1\]):' <<<"$bound"; then
  pass "API listens on loopback only ($(tr '\n' ' ' <<<"$bound"))"
else fail "API port $API_PORT: expected loopback only, got: ${bound:-nothing}"; fi

# 3. through nginx over https
ready="$(curl -sk --max-time 5 "$BASE/api/health/ready")"
[[ "$ready" == '{"status":"ok","database":"ok"}' ]] && pass "API ready through nginx" || fail "readiness through nginx: ${ready:-no answer}"
hdr="$(curl -skI --max-time 5 "$BASE/")"
grep -qi '^content-type: text/html' <<<"$hdr" && pass "dashboard served" || fail "dashboard not served at /"
grep -qi "^content-security-policy: default-src 'self'" <<<"$hdr" && pass "dashboard has a Content-Security-Policy" || fail "no CSP on the dashboard"
grep -qi '^x-frame-options: DENY' <<<"$hdr" && pass "framing denied" || fail "X-Frame-Options missing"
grep -qi '^server: nginx/' <<<"$hdr" && fail "nginx version disclosed" || pass "server version not disclosed"
code="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/events/1")"
[[ "$code" == 200 ]] && pass "client-side routes load the dashboard" || fail "/events/1 gave $code"
code="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/api/no-such-route")"
[[ "$code" == 404 ]] && pass "unknown API routes are 404 from the API, not the dashboard" || fail "/api/no-such-route gave $code"
code="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/api/devices")"
[[ "$code" == 401 ]] && pass "API data needs a session" || fail "/api/devices without a session gave $code"

# 4. TLS
if openssl s_client -connect 127.0.0.1:443 -tls1_1 </dev/null >/dev/null 2>&1; then fail "TLS 1.1 accepted"; else pass "TLS 1.1 refused"; fi

# 5. least privilege of the running processes
caps() { awk '/^CapEff:/{print $2}' "/proc/$1/status"; }
uid() { awk '/^Uid:/{print $3}' "/proc/$1/status"; }
mpid="$(systemctl show -p MainPID --value netguard-monitor)"
if [[ "$mpid" -gt 0 ]]; then
  [[ "$(uid "$mpid")" != 0 && "$(caps "$mpid")" == 0000000000003000 ]] \
    && pass "monitor runs as $(ps -o user= -p "$mpid") with only CAP_NET_RAW + CAP_NET_ADMIN" \
    || fail "monitor uid=$(uid "$mpid") CapEff=$(caps "$mpid") (expected non-root, 0000000000003000)"
fi
apid="$(systemctl show -p MainPID --value netguard-api)"
if [[ "$apid" -gt 0 ]]; then
  [[ "$(uid "$apid")" != 0 && "$(caps "$apid")" == 0000000000000000 ]] \
    && pass "API runs as $(ps -o user= -p "$apid") with no capabilities" \
    || fail "API uid=$(uid "$apid") CapEff=$(caps "$apid")"
fi

# 6. secrets on disk
for f in "$ETC/api.env" "$ETC/monitor.env" "$ETC/tls/netguard.key"; do
  [[ "$(stat -c '%U %a' "$f" 2>/dev/null)" == "root 600" ]] && pass "$f is root-only" || fail "$f: $(stat -c '%U %a' "$f" 2>&1)"
done
if grep -q 'NETGUARD_SECRET_KEY\|MIGRATOR' "$ETC/monitor.env"; then fail "monitor.env holds a secret it does not need"; else pass "monitor.env holds no session secret or migrator password"; fi
if grep -q 'MONITOR_PASSWORD\|MIGRATOR' "$ETC/api.env"; then fail "api.env holds a password it does not need"; else pass "api.env holds only the API database role"; fi

# 7. a client cannot choose the address the API records (X-Forwarded-For is overwritten by nginx)
probe="verify-$(date +%s)-$RANDOM"
curl -sk -o /dev/null --max-time 10 -H 'Content-Type: application/json' -H 'X-Forwarded-For: 203.0.113.66' \
  -d "{\"username\":\"$probe\",\"password\":\"not-a-password\"}" "$BASE/api/auth/login"
recorded="$(/opt/netguard/venv/bin/python - "$probe" "$ETC/api.env" <<'PY'
import sys
from sqlalchemy import text
from netguard_common.config import load_settings
from netguard_common.db import make_engine
with make_engine(load_settings(sys.argv[2]), "api").connect() as c:
    print(c.execute(text("SELECT host(source_ip) FROM audit_logs WHERE details->>'username' = :u "
                         "ORDER BY id DESC LIMIT 1"), {"u": sys.argv[1]}).scalar() or "none")
PY
)"
[[ "$recorded" == 127.0.0.1 ]] && pass "audit log records the real client (127.0.0.1), not a forged X-Forwarded-For" \
  || fail "audit log recorded '$recorded' for a request from 127.0.0.1 claiming 203.0.113.66"

echo
[[ $FAILS -eq 0 ]] && echo "ALL CHECKS PASSED" || echo "$FAILS CHECK(S) FAILED"
exit $(( FAILS > 0 ))
