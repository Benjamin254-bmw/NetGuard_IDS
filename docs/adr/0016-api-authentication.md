# ADR 0016: API authentication and sessions
Status: accepted (decisions confirmed by Benjamin in the project brief).

- **Passwords:** Argon2id (argon2-cffi defaults), rehash on login when parameters change. Policy: 12-128
  characters, at least 5 distinct characters, must not contain the username. Unknown users still cost one
  hash verification (dummy hash) so response time does not reveal which usernames exist.
- **Session token:** HS256 JWT in an HttpOnly, SameSite=Strict cookie (not readable by page scripts, so XSS
  cannot steal it). Algorithm is pinned on decode; `exp`, `iat`, `sub` are required. The token carries only
  user id, session version and a CSRF value. **Authority is never taken from the token:** role, active flag
  and session version are read from PostgreSQL on every request, so demotion, deactivation and password
  changes take effect at once and no revocation list is needed (bumping `users.session_version` revokes all
  of a user's tokens).
- **CSRF:** double submit. `X-CSRF-Token` header must equal the `ng_csrf` cookie and the value signed into
  the session token; an Origin check is applied on unsafe methods as a second layer. SameSite=Strict is the
  first.
- **Brute force:** per-account lockout (5 failures, 15 min; attempts while locked do not extend it) plus a
  per-source-address limiter (20 failures / 5 min, bounded memory). Both are deliberately simple and
  in-process; there is one API process in this deployment. Lockout can be used to deny service to a known
  username; that trade-off is accepted for a small lab network and the admin can unlock (`POST /users/{id}/unlock`).
- **Login failures are indistinguishable** (same status, body and similar timing).
- **No trust in X-Forwarded-For.** The recorded source address is the TCP peer. If a reverse proxy is added
  later this must be revisited together with an explicit trusted-proxy setting.
- **Last administrator:** demoting or deactivating the last active admin is refused, under `SELECT ... FOR
  UPDATE` on the active admins so concurrent requests serialize (tested with a 20-round race).
- **Audit:** every login, failure, lock, logout, password change/reset, user change, status change and rule
  change writes an `audit_logs` row in the same transaction as the change. Passwords, hashes and tokens are
  never written.
- **Least privilege:** the API connects as the `api` role, which can update only specific columns (see
  `shared/netguard_common/grants.py`). It cannot touch traffic tables or insert events.
- **Explicit transactions:** handlers open `tx(request)` themselves. A yield-dependency was rejected
  because FastAPI >= 0.118 runs its exit code after the response is sent, which would let a commit failure
  go unnoticed by the client.
- **Not done:** multi-factor authentication, password-reset by email (email deferred), rate limiting shared
  across processes, secret-key rotation without logging everyone out. Listed as limitations.
