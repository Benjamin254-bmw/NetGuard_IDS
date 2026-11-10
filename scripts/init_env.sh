#!/usr/bin/env bash
# Create .env from .env.example with random secrets. Refuses to overwrite an existing .env.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e .env ]]; then echo ".env already exists; keeping it (never overwritten)."; exit 0; fi
umask 077
python3 - <<'PY'
import secrets
text = open(".env.example").read()
while "=CHANGE_ME" in text:
    text = text.replace("=CHANGE_ME", "=" + secrets.token_urlsafe(32), 1)
open(".env", "w").write(text)
PY
chmod 600 .env
echo "Created .env (mode 600) with generated secrets."
