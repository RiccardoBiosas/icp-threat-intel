"""Per-host token-bucket rate limiting (SPEC guardrail 4)."""

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

Clock = Callable[[], float]
Sleep = Callable[[float], None]


@dataclass
class _Bucket:
    rate: float
    capacity: float
    tokens: float
    updated: float = field(default=0.0)


class HostRateLimiter:
    """Blocks until the host's bucket has a token.

    Each host gets its own bucket of ``burst`` tokens refilled at ``rate_per_second``;
    ``overrides`` maps a host to its own ``(rate_per_second, burst)``.
    """

    def __init__(
        self,
        rate_per_second: float = 2.0,
        burst: int = 4,
        *,
        overrides: Mapping[str, tuple[float, int]] | None = None,
        clock: Clock = time.monotonic,
        sleep: Sleep = time.sleep,
    ) -> None:
        if rate_per_second <= 0 or burst < 1:
            raise ValueError("rate_per_second must be > 0 and burst >= 1")
        self._default = (rate_per_second, burst)
        self._overrides = dict(overrides or {})
        self._clock = clock
        self._sleep = sleep
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, host: str) -> _Bucket:
        bucket = self._buckets.get(host)
        if bucket is None:
            rate, burst = self._overrides.get(host, self._default)
            bucket = _Bucket(rate=rate, capacity=float(burst), tokens=float(burst))
            bucket.updated = self._clock()
            self._buckets[host] = bucket
        return bucket

    def _refill(self, bucket: _Bucket) -> None:
        now = self._clock()
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.rate)
        bucket.updated = now

    def acquire(self, host: str) -> None:
        """Take one token for ``host``, sleeping first if the bucket is empty."""
        bucket = self._bucket(host.lower())
        self._refill(bucket)
        if bucket.tokens < 1.0:
            self._sleep((1.0 - bucket.tokens) / bucket.rate)
            self._refill(bucket)
            bucket.tokens = max(bucket.tokens, 1.0)
        bucket.tokens -= 1.0
