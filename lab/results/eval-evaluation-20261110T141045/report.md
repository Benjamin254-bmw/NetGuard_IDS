# NetGuard IDS evaluation: evaluation split

- started: 2026-11-10T14:10:48+00:00
- plan_sha256: fdf34579bc5ff06614bc7f86e976599e1208d371ea4769f32bfeee6622e24d95
- rules_frozen: True
- monitor_privileges: non-root, CAP_NET_RAW+CAP_NET_ADMIN only
- smoke: False

Trials scored: 250 {'positive': 150, 'evasion': 20, 'hard_negative': 50, 'normal': 30}

## Per category (independent confusion matrices)

| category | TP | FN | FP | TN | recall | precision | FPR |
|---|---|---|---|---|---|---|---|
| port_scan | 30 | 0 | 0 | 200 | 100.0% (30/30, 95% CI 89-100%) | 100.0% (30/30, 95% CI 89-100%) | 0.0% (0/200, 95% CI 0-2%) |
| excessive_connections | 30 | 0 | 0 | 220 | 100.0% (30/30, 95% CI 89-100%) | 100.0% (30/30, 95% CI 89-100%) | 0.0% (0/220, 95% CI 0-2%) |
| auth_failures | 30 | 0 | 0 | 220 | 100.0% (30/30, 95% CI 89-100%) | 100.0% (30/30, 95% CI 89-100%) | 0.0% (0/220, 95% CI 0-2%) |
| abnormal_traffic | 30 | 0 | 0 | 220 | 100.0% (30/30, 95% CI 89-100%) | 100.0% (30/30, 95% CI 89-100%) | 0.0% (0/220, 95% CI 0-2%) |
| suspicious_dns | 30 | 0 | 0 | 220 | 100.0% (30/30, 95% CI 89-100%) | 100.0% (30/30, 95% CI 89-100%) | 0.0% (0/220, 95% CI 0-2%) |

## False positives by kind of negative trial

| category | normal traffic | own hard negatives | other attacks |
|---|---|---|---|
| port_scan | 0/30 | 0/10 | 0/160 |
| excessive_connections | 0/30 | 0/10 | 0/180 |
| auth_failures | 0/30 | 0/10 | 0/180 |
| abnormal_traffic | 0/30 | 0/10 | 0/180 |
| suspicious_dns | 0/30 | 0/10 | 0/180 |

## Latency of true positives (seconds)

| category | attack start to event committed (median / p95 / max) | threshold crossing to commit (median / p95 / max) |
|---|---|---|
| port_scan | 0.823 / 3.777 / 3.993 | 0.344 / 0.604 / 0.616 |
| excessive_connections | 1.602 / 3.867 / 7.004 | 0.247 / 0.461 / 0.48 |
| auth_failures | 2.137 / 5.616 / 5.662 | 0.319 / 0.542 / 0.573 |
| abnormal_traffic | 5.063 / 6.521 / 6.64 | 0.002 / 0.003 / 0.003 |
| suspicious_dns | 1.573 / 4.467 / 4.826 | 0.256 / 0.46 / 0.468 |

## Known-evasion techniques (documented limitations; not part of core recall)

| technique | trials | detected |
|---|---|---|
| fin_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| null_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| slow_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| udp_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| xmas_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |

Monitor: captured 3200576, kernel-dropped 0. Resources: {"samples": 2228, "cpu_percent_median": 1.0, "cpu_percent_p95": 15.0, "cpu_percent_max": 31.0, "rss_mb_median": 70.090752, "rss_mb_max": 71.368704}
