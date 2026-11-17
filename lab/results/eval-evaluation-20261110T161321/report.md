# NetGuard IDS evaluation: evaluation split

- started: 2026-11-10T16:13:24+00:00
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
| port_scan | 0.764 / 3.797 / 3.995 | 0.306 / 0.605 / 0.624 |
| excessive_connections | 1.615 / 3.746 / 7.01 | 0.212 / 0.447 / 0.489 |
| auth_failures | 1.81 / 5.415 / 5.521 | 0.319 / 0.56 / 0.563 |
| abnormal_traffic | 4.913 / 6.602 / 6.836 | 0.003 / 0.012 / 0.015 |
| suspicious_dns | 1.542 / 4.31 / 4.825 | 0.35 / 0.602 / 0.603 |

## Known-evasion techniques (documented limitations; not part of core recall)

| technique | trials | detected |
|---|---|---|
| fin_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| null_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| slow_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| udp_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |
| xmas_scan | 4 | 0 (0.0% (0/4, 95% CI 0-49%)) |

Monitor: captured 3209576, kernel-dropped 0. Resources: {"samples": 2216, "cpu_percent_median": 1.0, "cpu_percent_p95": 69.0, "cpu_percent_max": 88.0, "rss_mb_median": 72.347648, "rss_mb_max": 73.412608}
