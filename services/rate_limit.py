"""Tiny in-memory sliding-window rate limiter.

Fine for healthy Flask deployments (especially a single worker like
PythonAnywhere's default) and zero-dependency. Keys are typically
"action:ip" or "login:ip:identifier".

State lives only as long as the process; a restart simply resets the
budget, which is acceptable for brute-force throttling.
"""

import time


class RateLimiter:
    def __init__(self):
        self._hits = {}

    def _prune(self, key, window):
        now = time.time()
        kept = [t for t in self._hits.get(key, []) if t > now - window]
        if kept:
            self._hits[key] = kept
        elif key in self._hits:
            del self._hits[key]
        return now, kept

    def allow(self, key, limit, window):
        """Record a hit and answer: is this request within budget?"""
        now, kept = self._prune(key, window)
        if len(kept) >= limit:
            return False
        self._hits.setdefault(key, []).append(now)
        return True

    def retry_after(self, key, window):
        """Seconds until the oldest hit falls outside the window."""
        now, kept = self._prune(key, window)
        if not kept:
            return 0
        return max(1, int(window - (now - min(kept))))

    def clear(self, key):
        self._hits.pop(key, None)