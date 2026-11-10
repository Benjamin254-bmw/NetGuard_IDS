#!/usr/bin/env bash
# Diagnose the most common environment problems. Read-only. Exit status 1 if anything FAILs.
cd "$(dirname "$0")/.." || exit 2
real="$(pwd -P)"
fail=0
ok()   { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fail=1; }
warn() { echo "WARN  $*"; }

echo "INFO  project directory (real path): $real"
case "$real" in
  */Trash/*|*/.Trash*) bad "this directory is in the Trash: open a terminal in the project's real location" ;;
  *) ok "directory is not in the Trash" ;;
esac

if [[ -x .venv/bin/python ]]; then
  ok "$(.venv/bin/python --version 2>&1)"
  if [[ -f .venv/bin/pip ]] && ! head -1 .venv/bin/pip | grep -qF "$real/.venv/bin/python"; then
    bad "the virtualenv was created in another location (project moved or copied): rm -rf .venv && make setup"
  else
    ok "virtualenv belongs to this directory"
  fi
else
  bad ".venv is missing: run 'make setup'"
fi

if [[ -f .env ]]; then
  if [[ -r .env ]]; then ok ".env present (mode $(stat -c %a .env))"; else bad ".env exists but is not readable by you"; fi
else
  bad ".env is missing: run 'make init-env' then 'make db-init'"
fi

exported="$(env | grep -o '^NETGUARD_[A-Z0-9_]*' | tr '\n' ' ')"
if [[ -z "$exported" ]]; then ok "no NETGUARD_* variables exported in this shell"
else warn "exported in this shell (they override .env): $exported"; fi

if [[ -x .venv/bin/python ]]; then
  err="$(mktemp)"
  cur="$(.venv/bin/python -m alembic current 2>"$err" | awk 'NR==1{print $1}')"
  head="$(.venv/bin/python -m alembic heads 2>/dev/null | awk 'NR==1{print $1}')"
  if [[ -z "$cur" ]]; then bad "cannot read the migration state: $(tail -1 "$err" | cut -c1-110); try: make db-init && make migrate"
  elif [[ "$cur" != "$head" ]]; then bad "database is at migration $cur but the code expects $head: make migrate"
  else ok "database migrations are current ($cur)"; fi
fi
rm -f "${err:-}"
exit $fail
