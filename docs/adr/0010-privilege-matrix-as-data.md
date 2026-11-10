# ADR 0010: Privilege matrix as data, with column-level grants
Status: accepted. `netguard_common/grants.py` is the single description of what the monitor and
API roles may do, applied by migrations and verified by tests against the live database
(table-level and column-level, including everything *not* granted). Notable rules: the monitor
can create events but only update counters and window state on them; the API can change an
event's triage status but cannot create, alter or delete detections; neither role can modify or
delete audit logs or rule history; neither can change the schema. A migration applies grants only
for the tables that exist at its revision, so history stays reproducible. Adding a table requires
an entry in GRANTS; a test fails otherwise.
