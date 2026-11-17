# NetGuard IDS evaluation: tuning split

- started: 2026-11-10T14:57:05+00:00
- plan_sha256: fdf34579bc5ff06614bc7f86e976599e1208d371ea4769f32bfeee6622e24d95
- rules_frozen: False
- monitor_privileges: non-root, CAP_NET_RAW+CAP_NET_ADMIN only
- smoke: True

Trials scored: 16 {'positive': 5, 'normal': 1, 'hard_negative': 5, 'evasion': 5}

## Per category (independent confusion matrices)

| category | TP | FN | FP | TN | recall | precision | FPR |
|---|---|---|---|---|---|---|---|
| port_scan | 1 | 0 | 0 | 10 | 100.0% (1/1, 95% CI 21-100%) | 100.0% (1/1, 95% CI 21-100%) | 0.0% (0/10, 95% CI 0-28%) |
| excessive_connections | 1 | 0 | 0 | 15 | 100.0% (1/1, 95% CI 21-100%) | 100.0% (1/1, 95% CI 21-100%) | 0.0% (0/15, 95% CI 0-20%) |
| auth_failures | 1 | 0 | 0 | 15 | 100.0% (1/1, 95% CI 21-100%) | 100.0% (1/1, 95% CI 21-100%) | 0.0% (0/15, 95% CI 0-20%) |
| abnormal_traffic | 1 | 0 | 0 | 15 | 100.0% (1/1, 95% CI 21-100%) | 100.0% (1/1, 95% CI 21-100%) | 0.0% (0/15, 95% CI 0-20%) |
| suspicious_dns | 1 | 0 | 0 | 15 | 100.0% (1/1, 95% CI 21-100%) | 100.0% (1/1, 95% CI 21-100%) | 0.0% (0/15, 95% CI 0-20%) |

## False positives by kind of negative trial

| category | normal traffic | own hard negatives | other attacks |
|---|---|---|---|
| port_scan | 0/1 | 0/1 | 0/8 |
| excessive_connections | 0/1 | 0/1 | 0/13 |
| auth_failures | 0/1 | 0/1 | 0/13 |
| abnormal_traffic | 0/1 | 0/1 | 0/13 |
| suspicious_dns | 0/1 | 0/1 | 0/13 |

## Latency of true positives (seconds)

| category | attack start to event committed (median / p95 / max) | threshold crossing to commit (median / p95 / max) |
|---|---|---|
| port_scan | 0.556 / 0.556 / 0.556 | 0.407 / 0.407 / 0.407 |
| excessive_connections | 0.541 / 0.541 / 0.541 | 0.366 / 0.366 / 0.366 |
| auth_failures | 4.894 / 4.894 / 4.894 | 0.081 / 0.081 / 0.081 |
| abnormal_traffic | 3.316 / 3.316 / 3.316 | 0.002 / 0.002 / 0.002 |
| suspicious_dns | 0.239 / 0.239 / 0.239 | 0.202 / 0.202 / 0.202 |

## Known-evasion techniques (documented limitations; not part of core recall)

| technique | trials | detected |
|---|---|---|
| fin_scan | 1 | 0 (0.0% (0/1, 95% CI 0-79%)) |
| null_scan | 1 | 0 (0.0% (0/1, 95% CI 0-79%)) |
| slow_scan | 1 | 0 (0.0% (0/1, 95% CI 0-79%)) |
| udp_scan | 1 | 0 (0.0% (0/1, 95% CI 0-79%)) |
| xmas_scan | 1 | 0 (0.0% (0/1, 95% CI 0-79%)) |

Monitor: captured 165950, kernel-dropped 0. Resources: {"samples": 233, "cpu_percent_median": 1.0, "cpu_percent_p95": 33.999999999999886, "cpu_percent_max": 86.0, "rss_mb_median": 71.307264, "rss_mb_max": 71.319552}
