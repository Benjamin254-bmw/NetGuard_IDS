# ADR 0002: Linux network namespaces as the primary lab
Status: accepted. A bridge `br-lab` (10.10.10.0/24) plus namespaces victim/normal/attacker, no
uplink. Rationale: near-zero RAM (8 GB host), fully isolated, repeatable via `lab/setup_lab.sh`,
the monitor sniffs the bridge and sees all lab traffic. Limitation: a real switched LAN would show
less traffic to a host-based sensor; a real-LAN demo is an optional later extension.
