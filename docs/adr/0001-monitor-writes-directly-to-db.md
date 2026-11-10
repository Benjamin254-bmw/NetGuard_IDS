# ADR 0001: The monitor writes directly to PostgreSQL
Status: accepted. The monitor persists observations, events, alerts and heartbeat itself using a
dedicated least-privilege role; the API is a read/control layer. Rationale: the monitor keeps
working if the API is down, and the API needs no privileges. Cost: the DB schema is the contract
between the two (hence `shared/`). NOTIFY/LISTEN is a transient hint only; consumers re-query by
cursor. Spilled JSONL records carry a UUID and are replayed with `ON CONFLICT DO NOTHING`.
