# ADR 0009: Traffic aggregates and retention
Status: accepted. No raw packets are stored. Two aggregate tables: `traffic_stats_1s` (global
per-protocol counters, intended retention 24 h, a few rows per second) and
`connection_aggregates_1m` (per source/destination/port/transport per minute, intended retention
30 days, the configured default). The monitor caps distinct keys per minute so a scan cannot create
unbounded rows. Retention is a batched DELETE by `bucket_start` run by the monitor (its role holds
DELETE on these two tables only), using the primary-key prefix. Native partitioning would make
pruning cheaper but adds a partition-management job; it is deferred until measurements in
Phase 7 show it is needed. Events, alerts and audit logs are kept indefinitely.
DNS-specific counters are added with the DNS rule in Phase 4.
