# ADR 0005: Privilege model
Status: accepted. Only the monitor needs CAP_NET_RAW (and CAP_NET_ADMIN for active ARP). It runs
as a non-root user with those ambient capabilities (`scripts/run-with-caps.sh` in development,
systemd `AmbientCapabilities` in deployment). API and frontend never run as root. Three DB roles
(migrator, monitor, api) with separate passwords. Verified in Phase 1 by opening an AF_PACKET
socket as a non-root user with and without the capabilities.
