#!/usr/bin/env bash
# Create (or re-sync) the NetGuard databases and their three least-privilege roles.
# Creates '<name>' (development/production) and '<name>_test' (migration/privilege tests only).
# Idempotent. Reads names/passwords from .env; SQL (with passwords) goes via stdin only, never argv.
# Requires: sudo access to the 'postgres' OS user. Does not touch any other database.
set -euo pipefail
cd "$(dirname "$0")/.."
ENV_FILE="${NETGUARD_ENV_FILE:-.env}"
[[ -f "$ENV_FILE" ]] || { echo "$ENV_FILE not found; run 'make init-env' first." >&2; exit 1; }

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*$//'; }
req() { local v; v="$(get "$1")"; [[ -n "$v" ]] || { echo "$1 is not set in $ENV_FILE" >&2; exit 1; }; printf '%s' "$v"; }

DB="$(req NETGUARD_DB_NAME)"
MIG="$(req NETGUARD_DB_MIGRATOR_USER)"; MON="$(req NETGUARD_DB_MONITOR_USER)"; API="$(req NETGUARD_DB_API_USER)"
MIG_PW="$(req NETGUARD_DB_MIGRATOR_PASSWORD)"; MON_PW="$(req NETGUARD_DB_MONITOR_PASSWORD)"; API_PW="$(req NETGUARD_DB_API_PASSWORD)"

for ident in "$DB" "${DB}_test" "$MIG" "$MON" "$API"; do
  [[ "$ident" =~ ^[a-z_][a-z0-9_]{0,40}$ ]] || { echo "Invalid identifier: $ident" >&2; exit 1; }
done
for pw in "$MIG_PW" "$MON_PW" "$API_PW"; do
  [[ "$pw" =~ ^[A-Za-z0-9_-]{20,}$ ]] || { echo "Passwords must be >=20 chars of [A-Za-z0-9_-] (run 'make init-env')." >&2; exit 1; }
done

run_sql() {  # $1 = database to create/prepare
  sudo -u postgres psql -X -q -v ON_ERROR_STOP=1 -v db="$1" -v mig="$MIG" -d postgres <<SQL
-- Roles: login-only, no superuser/createdb/createrole.
SELECT format('CREATE ROLE %I LOGIN', r) FROM (VALUES ('$MIG'),('$MON'),('$API')) v(r)
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) \gexec
ALTER ROLE "$MIG" NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$MIG_PW' CONNECTION LIMIT 10;
ALTER ROLE "$MON" NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$MON_PW' CONNECTION LIMIT 10;
ALTER ROLE "$API" NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$API_PW' CONNECTION LIMIT 20;
-- Timestamps are handled in UTC regardless of the host timezone.
ALTER ROLE "$MIG" SET timezone TO 'UTC';
ALTER ROLE "$MON" SET timezone TO 'UTC';
ALTER ROLE "$API" SET timezone TO 'UTC';
ALTER ROLE "$API" SET statement_timeout TO '30s';

-- Database: built-in C.UTF-8 provider on PG>=17 (no glibc collation-version drift), libc C.UTF-8 otherwise.
SELECT current_setting('server_version_num')::int >= 170000 AS has_builtin \gset
\if :has_builtin
SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING ''UTF8'' LOCALE_PROVIDER builtin LOCALE ''C.UTF-8''', :'db', :'mig')
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
\else
SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING ''UTF8'' LOCALE ''C.UTF-8''', :'db', :'mig')
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
\endif

REVOKE ALL ON DATABASE "$1" FROM PUBLIC;
GRANT CONNECT ON DATABASE "$1" TO "$MIG", "$MON", "$API";
\connect :db
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO "$MON", "$API";
SQL
}

run_sql "$DB"
run_sql "${DB}_test"
echo "Databases '$DB' and '${DB}_test' and roles ready. Run 'make migrate' to create tables and grants."
