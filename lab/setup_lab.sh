#!/usr/bin/env bash
# NetGuard isolated lab: bridge br-lab + three network namespaces. No uplink, no NAT, no forwarding.
# Usage: sudo lab/setup_lab.sh {up|down|status|verify}
set -euo pipefail

BR="br-lab"
SUBNET="10.10.10"
declare -A NS_IP=( [ng-victim]="${SUBNET}.10" [ng-normal]="${SUBNET}.20" [ng-attacker]="${SUBNET}.30" )
BR_IP="${SUBNET}.1"

need_root() { [[ $EUID -eq 0 ]] || { echo "Run with sudo (lab setup needs CAP_NET_ADMIN)." >&2; exit 1; }; }

vname() { echo "v${1#ng-}"; }   # host-side veth, e.g. vvictim
pname() { echo "p${1#ng-}"; }   # namespace-side veth

up() {
  need_root
  if ip link show "$BR" >/dev/null 2>&1; then echo "$BR already exists; run 'down' first." >&2; exit 1; fi
  ip link add "$BR" type bridge
  ip addr add "${BR_IP}/24" dev "$BR"
  ip link set "$BR" up
  for ns in "${!NS_IP[@]}"; do
    ip netns add "$ns"
    ip link add "$(vname "$ns")" type veth peer name "$(pname "$ns")"
    ip link set "$(pname "$ns")" netns "$ns"
    ip link set "$(vname "$ns")" master "$BR" up
    ip -n "$ns" addr add "${NS_IP[$ns]}/24" dev "$(pname "$ns")"
    ip -n "$ns" link set "$(pname "$ns")" up
    ip -n "$ns" link set lo up
  done
  echo "Lab is up: bridge $BR ${BR_IP}/24; namespaces: ${!NS_IP[*]}"
}

down() {
  need_root
  for ns in "${!NS_IP[@]}"; do
    ip link del "$(vname "$ns")" 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
  done
  ip link del "$BR" 2>/dev/null || true
  echo "Lab removed."
}

status() {
  ip -br addr show "$BR" 2>/dev/null || echo "$BR: not present"
  ip netns list | grep '^ng-' || echo "no ng-* namespaces"
}

verify() {
  need_root
  for tool in tcpdump ping; do
    command -v "$tool" >/dev/null || { echo "'$tool' is required for verify but was not found in PATH" >&2; exit 1; }
  done
  local pcap; pcap="$(mktemp /tmp/ng-verify.XXXXXX.pcap)"
  trap 'rm -f "$pcap"' RETURN
  local fail=0
  for ns in "${!NS_IP[@]}"; do
    if ip netns exec "$ns" ping -c1 -W1 "${BR_IP}" >/dev/null 2>&1; then echo "PASS  $ns -> bridge"; else echo "FAIL  $ns -> bridge"; fail=1; fi
  done
  # Traffic between namespaces must be visible on the bridge (this is what the monitor relies on).
  tcpdump -ni "$BR" -w "$pcap" icmp >/dev/null 2>&1 &
  local tp=$!; sleep 1
  ip netns exec ng-attacker ping -c3 -W1 "${NS_IP[ng-victim]}" >/dev/null 2>&1 || fail=1
  sleep 1; kill "$tp" 2>/dev/null || true; wait "$tp" 2>/dev/null || true
  local n; n="$(tcpdump -nr "$pcap" 2>/dev/null | grep -c 'ICMP echo' || true)"
  if [[ "$n" -ge 6 ]]; then echo "PASS  sniffer on $BR saw $n ICMP echo packets (expected 6)"; else echo "FAIL  sniffer on $BR saw $n ICMP echo packets (expected 6)"; fail=1; fi
  # Isolation: no default route and no path out of the 10.10.10.0/24 network.
  if ip netns exec ng-attacker ip route | grep -q '^default'; then echo "FAIL  attacker namespace has a default route"; fail=1; else echo "PASS  no default route in attacker namespace (isolated)"; fi
  return $fail
}

case "${1:-}" in
  up) up ;; down) down ;; status) status ;; verify) verify ;;
  *) echo "Usage: sudo $0 {up|down|status|verify}" >&2; exit 2 ;;
esac
