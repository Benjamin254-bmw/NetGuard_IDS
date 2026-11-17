#!/usr/bin/env bash
# Create a self-signed TLS certificate for the dashboard (Phase 8).
#   deploy/make_cert.sh OUT_DIR [extra-name-or-ip ...]
# Names covered: this host's name, <name>.local, localhost, 127.0.0.1, ::1, every IPv4 address on an up,
# non-loopback interface, plus any extra arguments. Writes OUT_DIR/netguard.crt and OUT_DIR/netguard.key
# (key mode 600). Never overwrites: delete both files first to re-issue.
set -euo pipefail
OUT="${1:?usage: $0 OUT_DIR [extra-name-or-ip ...]}"; shift
CRT="$OUT/netguard.crt"; KEY="$OUT/netguard.key"
if [[ -e "$CRT" || -e "$KEY" ]]; then
  echo "certificate already present in $OUT (delete netguard.crt and netguard.key to re-issue)"; exit 0
fi
mkdir -p "$OUT"
host="$(hostname -s)"
san="DNS:${host},DNS:${host}.local,DNS:localhost,IP:127.0.0.1,IP:::1"
while read -r ip; do san+=",IP:${ip}"; done < <(ip -4 -o addr show up scope global | awk '{split($4,a,"/"); print a[1]}')
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9.]+$ || "$extra" == *:* ]]; then san+=",IP:${extra}"; else san+=",DNS:${extra}"; fi
done
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 825 \
  -subj "/CN=${host} (NetGuard IDS)" -addext "subjectAltName=${san}" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" -keyout "$KEY" -out "$CRT" 2>/dev/null
chmod 600 "$KEY"; chmod 644 "$CRT"
echo "self-signed certificate written to $CRT"
echo "  covers: ${san}"
echo "  SHA-256 fingerprint (compare it with what the browser shows before trusting it):"
openssl x509 -in "$CRT" -noout -fingerprint -sha256 | sed 's/^/    /'
