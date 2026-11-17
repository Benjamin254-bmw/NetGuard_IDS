# NetGuard IDS evaluation: tuning split

- started: 2026-11-10T13:51:16+00:00
- plan_sha256: fdf34579bc5ff06614bc7f86e976599e1208d371ea4769f32bfeee6622e24d95
- rules_frozen: False
- monitor_privileges: non-root, CAP_NET_RAW+CAP_NET_ADMIN only
- smoke: False

Trials scored: 125 {'positive': 75, 'normal': 15, 'hard_negative': 25, 'evasion': 10}

## Per category (independent confusion matrices)

| category | TP | FN | FP | TN | recall | precision | FPR |
|---|---|---|---|---|---|---|---|
| port_scan | 15 | 0 | 0 | 100 | 100.0% (15/15, 95% CI 80-100%) | 100.0% (15/15, 95% CI 80-100%) | 0.0% (0/100, 95% CI 0-4%) |
| excessive_connections | 15 | 0 | 0 | 110 | 100.0% (15/15, 95% CI 80-100%) | 100.0% (15/15, 95% CI 80-100%) | 0.0% (0/110, 95% CI 0-3%) |
| auth_failures | 15 | 0 | 0 | 110 | 100.0% (15/15, 95% CI 80-100%) | 100.0% (15/15, 95% CI 80-100%) | 0.0% (0/110, 95% CI 0-3%) |
| abnormal_traffic | 15 | 0 | 0 | 110 | 100.0% (15/15, 95% CI 80-100%) | 100.0% (15/15, 95% CI 80-100%) | 0.0% (0/110, 95% CI 0-3%) |
| suspicious_dns | 15 | 0 | 0 | 110 | 100.0% (15/15, 95% CI 80-100%) | 100.0% (15/15, 95% CI 80-100%) | 0.0% (0/110, 95% CI 0-3%) |

## False positives by kind of negative trial

| category | normal traffic | own hard negatives | other attacks |
|---|---|---|---|
| port_scan | 0/15 | 0/5 | 0/80 |
| excessive_connections | 0/15 | 0/5 | 0/90 |
| auth_failures | 0/15 | 0/5 | 0/90 |
| abnormal_traffic | 0/15 | 0/5 | 0/90 |
| suspicious_dns | 0/15 | 0/5 | 0/90 |

## Latency of true positives (seconds)

| category | attack start to event committed (median / p95 / max) | threshold crossing to commit (median / p95 / max) |
|---|---|---|
| port_scan | 0.331 / 2.52 / 2.847 | 0.224 / 0.43 / 0.48 |
| excessive_connections | 1.507 / 5.136 / 6.042 | 0.283 / 0.47 / 0.498 |
| auth_failures | 1.813 / 5.694 / 5.879 | 0.193 / 0.532 / 0.548 |
| abnormal_traffic | 5.622 / 8.239 / 8.425 | 0.002 / 0.003 / 0.004 |
| suspicious_dns | 0.64 / 4.037 / 7.164 | 0.202 / 0.602 / 0.602 |

## Known-evasion techniques (documented limitations; not part of core recall)

| technique | trials | detected |
|---|---|---|
| fin_scan | 2 | 0 (0.0% (0/2, 95% CI 0-66%)) |
| null_scan | 2 | 0 (0.0% (0/2, 95% CI 0-66%)) |
| slow_scan | 2 | 0 (0.0% (0/2, 95% CI 0-66%)) |
| udp_scan | 2 | 0 (0.0% (0/2, 95% CI 0-66%)) |
| xmas_scan | 2 | 0 (0.0% (0/2, 95% CI 0-66%)) |

Monitor: captured 1530396, kernel-dropped 0. Resources: {"samples": 1135, "cpu_percent_median": 1.0, "cpu_percent_p95": 16.0, "cpu_percent_max": 33.9, "rss_mb_median": 69.685248, "rss_mb_max": 70.299648}
