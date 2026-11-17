# ADR 0015: How detection quality is measured
Status: accepted.

**Goal.** Report recall, precision, false-positive rate and latency per detection category from real
traffic, in a way that cannot flatter the system and can be reproduced.

**Decisions**
- **Ground truth is written first.** `evaluate.py plan` generates every trial from a fixed seed into
  `lab/eval/ground_truth.jsonl` and records its SHA-256 (`plan.sha256`). A run refuses to start if the
  regenerated plan differs from the committed hash, so expectations cannot be edited after seeing results.
- **The monitor is never told what is an attack.** Each trial uses its own source address; events are
  attributed afterwards by (source address, time slot). An address is not reused for 330 s (longer than the
  longest cooldown, 300 s), so two trials never share an event.
- **Trial-level scoring, one confusion matrix per category.** Positive = a real attack of that category.
  Negative = anything else, including attacks of *other* categories (an attack must not trip an unrelated
  rule). False positives are broken down by negative type (normal traffic, the category's own
  near-threshold "hard negatives", other attacks). 95 % Wilson intervals are printed with every ratio.
- **Known-uncovered techniques are reported separately.** UDP, FIN/NULL/Xmas and slow scans are real
  attacks the port-scan rule is documented not to cover. They are neither counted as core recall (which
  would hide the gap by omission) nor as negatives; they have their own table.
- **Tuning and evaluation are disjoint trials.** Thresholds may be changed using the tuning split only.
  `freeze` records the rule configuration (every field and version) and the plan hash; the evaluation
  split refuses to run unless the live rules equal the frozen ones, refuses to run as a smoke subset,
  and every evaluation run is appended to `lab/eval/evaluation_runs.log`.
- **Invalid trials are excluded visibly.** A generator that did not deliver (flood short of its
  connection count, UDP below 90 % of the requested rate, ssh attempts not all rejected, fewer failures
  logged than attempts) makes the trial invalid; invalid trials are listed in the report.
- **Latency is reported two ways**: attack start to event committed in the database, and detection
  threshold crossing to commit. The first includes the time the attack needs to reach the threshold.
- **Metrics come only from `metrics.json` of a run.** `evaluate.py score DIR` recomputes them from the
  stored trials and events and must reproduce them exactly.

**Limits that stay true.** One lab, one victim, one traffic generator: results describe this lab, not
every network. Normal traffic is synthetic. Trial counts (30 per category) give wide intervals; 30/30 is
still only "at least ~89 %" at 95 % confidence.

**Found by building this: promiscuous mode.** With `NETGUARD_PROMISCUOUS=false` the monitor on the lab
bridge captured 5 packets in a run where 165,782 were captured with it on, because frames between other
bridge ports are not addressed to the bridge. The earlier demo scripts passed only because their tcpdump
oracle switched promiscuous mode on as a side effect. All lab scripts now set it explicitly and
`docs/monitor.md` states the requirement.
