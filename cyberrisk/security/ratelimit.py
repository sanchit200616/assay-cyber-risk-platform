"""Token-bucket rate limiter with an injectable clock (route-aware keys supplied by the caller)."""
from __future__ import annotations

import threading
import time
from typing import Callable


class RateLimiter:
    def __init__(self, per_minute: int, burst: int | None = None, clock: Callable[[], float] = time.monotonic):
        self.rate = per_minute / 60.0
        self.capacity = float(burst or per_minute)
        self.clock = clock
        self._buckets: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, (1 - tokens) / self.rate if self.rate else 60.0
