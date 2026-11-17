# ADR 0017: Live updates via NOTIFY and WebSocket
Status: accepted.

- **Database is the record, the socket is a hint.** The monitor already commits the event and alert and
  sends `pg_notify('ids_alerts', alert_id)` in the same transaction (delivered only on commit). The API
  holds one dedicated psycopg async connection with `LISTEN`, reads the alert row (the payload is just an id,
  well under the 8000-byte NOTIFY limit and never trusted as content) and pushes it to connected clients.
- **No guarantee of delivery.** NOTIFY is not stored. If the LISTEN connection drops, the hub reconnects
  with backoff (1 s doubling to 30 s) and sends `resync` to clients; a client that was offline asks the REST
  API for `after_id`. This keeps delivery logic out of the monitor and avoids a queue service (no
  Redis/Kafka, per the project constraints).
- **Back-pressure:** per-client bounded queue (100). On overflow the client is dropped (1013) so one stalled
  browser cannot consume memory or slow the others; the hub never awaits a client.
- **Auth:** same cookie as REST, checked before the handshake completes; foreign `Origin` refused (a
  WebSocket is not covered by CORS, so this check is the protection against cross-site hijacking). Sessions
  are re-validated every 15 s so logout-everywhere or deactivation closes live sockets.
- **Monitor health** is pushed every 5 s while at least one client is connected, using the same
  staleness rule as the REST endpoint.
- **Limits:** one API process; multiple processes would each LISTEN (works, since each reads the DB) but
  would need a shared failure limiter. Clients only send `ping`; anything over 256 bytes closes the socket.
