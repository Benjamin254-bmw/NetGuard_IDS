# ADR 0003: Collation and data types
Status: accepted. Observed on the dev machine: databases created before a glibc upgrade report a
collation version mismatch. The `netguard` database uses PostgreSQL's builtin C.UTF-8 provider
(PG >= 17), which has no external version dependency; older servers fall back to libc C.UTF-8.
Schema (Phase 2) will use `inet` for addresses and `timestamptz` for times, so correctness does not
depend on locale-aware text ordering. All roles use timezone UTC (host timezone is not UTC).
