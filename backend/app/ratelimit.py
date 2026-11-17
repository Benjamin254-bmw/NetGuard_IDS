"""Per-address failure limiter for the login endpoint (in-process, bounded memory).

Per-account lockout (security.py) stops guessing against one user; this stops one address from
trying many usernames. It is process-local: run a single API worker (documented), or move it to the
reverse proxy. The clock is injected so tests need no sleeping.
"""

from __future__ import annotations

from collections import OrderedDict, deque


class FailureLimiter:
    def __init__(
        self, max_failures: int = 20, window_seconds: float = 300.0, max_keys: int = 10_000
    ) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self.max_keys = max_keys
        self._seen: OrderedDict[str, deque[float]] = OrderedDict()

    def _trim(self, key: str, now: float) -> deque[float]:
        q = self._seen.get(key)
        if q is None:
            return deque()
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            del self._seen[key]
            return deque()
        return q

    def blocked(self, key: str, now: float) -> float:
        """Seconds until `key` may try again (0 = allowed now)."""
        q = self._trim(key, now)
        if len(q) < self.max_failures:
            return 0.0
        return max(0.0, q[0] + self.window - now)

    def record_failure(self, key: str, now: float) -> None:
        q = self._trim(key, now)
        if not q:
            while len(self._seen) >= self.max_keys:  # evict the least recently active address
                self._seen.popitem(last=False)
            self._seen[key] = q
        q.append(now)
        self._seen.move_to_end(key)

    def reset(self, key: str) -> None:
        self._seen.pop(key, None)
