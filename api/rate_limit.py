"""In-memory token bucket per API key, sized by the key's role (Role.rate_limit_rpm).

Each bucket holds up to ``rpm`` tokens and refills at ``rpm / 60`` tokens per second,
so a key can burst its whole minute's allowance and then sustain ``rpm``.

Per process: with N uvicorn workers a key gets N times its limit. The API is run
with one worker (paused runs and review decisions are designed around that).
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

SECONDS_PER_MINUTE = 60.0
# Per-IP buckets (failed auth) are attacker-chosen: cap how many are tracked.
MAX_TRACKED_BUCKETS = 10_000


@dataclass(frozen=True)
class _Bucket:
    tokens: float
    updated_at: float
    # True once a denial has been reported since the bucket last allowed a request.
    denial_reported: bool = False


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_seconds: int = 0
    # Audit only the first denial of each exhaustion, so a flood cannot grow the log.
    should_audit: bool = False


def bucket_id(api_key: str) -> str:
    """Buckets are keyed by a digest so raw keys are not held twice in memory."""
    return hashlib.sha256(api_key.encode()).hexdigest()[:32]


class TokenBucketLimiter:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        max_buckets: int = MAX_TRACKED_BUCKETS,
    ) -> None:
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str, rpm: int) -> RateDecision:
        """Spend one token for ``key`` if available."""
        if rpm <= 0:
            raise ValueError(f"rpm must be positive, got {rpm}")
        rate = rpm / SECONDS_PER_MINUTE
        with self._lock:
            now = self._clock()
            prev = self._buckets.get(key, _Bucket(tokens=float(rpm), updated_at=now))
            tokens = min(float(rpm), prev.tokens + (now - prev.updated_at) * rate)
            allowed = tokens >= 1.0
            remaining = tokens - 1.0 if allowed else tokens
            first_denial = not allowed and not prev.denial_reported
            self._buckets = {**self._bounded(key), key: _Bucket(
                tokens=remaining, updated_at=now, denial_reported=not allowed)}
        if allowed:
            return RateDecision(allowed=True)
        retry = max(1, math.ceil((1.0 - tokens) / rate))
        return RateDecision(allowed=False, retry_after_seconds=retry, should_audit=first_denial)

    def _bounded(self, key: str) -> dict[str, _Bucket]:
        """Buckets minus the least recently used one when a new key would exceed the cap."""
        if key in self._buckets or len(self._buckets) < self._max_buckets:
            return self._buckets
        stalest = min(self._buckets, key=lambda k: self._buckets[k].updated_at)
        return {k: v for k, v in self._buckets.items() if k != stalest}

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets)
