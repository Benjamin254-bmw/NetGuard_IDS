# ADR 0007: Rule versioning is enforced by the database
Status: accepted. `detection_rules` holds the current configuration. A trigger bumps `version`
and writes an immutable snapshot to `detection_rule_versions` on every change to enabled,
severity, threshold, window, cooldown or params, no matter which role or code path made it.
No-op updates and description edits do not bump. `detection_rules.key` is immutable.
Each security event references `(rule_id, rule_version)` by composite foreign key, so the exact
configuration that fired it is preserved and cannot be lost or rewritten (runtime roles have only
SELECT on the history table). We did not copy the config into each event: one immutable source
cannot drift. Rationale: the evaluation chapter must be able to say which thresholds produced
which result, even after tuning. Rule rows are created by the monitor's rule registry (Phase 4),
not by migrations, so defaults live next to the rule code. Tested, including by mutation.
