"""
Rate Limiter & Retry Utilities

Provides:
  - ``TokenBucketRateLimiter``  – thread-/coroutine-safe token-bucket rate limiter
  - ``RetryConfig``             – exponential-backoff configuration dataclass
  - ``with_retry``              – decorator / context-manager for async functions
  - Per-tool default configs    – ``TOOL_RATE_LIMITS``
"""
from __future__ import annotations

import asyncio
import functools
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Tuple, Type

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token-Bucket Rate Limiter
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """
    Asyncio-compatible token-bucket rate limiter.

    Allows up to *capacity* tokens with a refill rate of *rate* tokens per
    second.  Callers ``await`` :meth:`acquire` to consume a token; the coroutine
    suspends until enough tokens are available.

    Example::

        limiter = TokenBucketRateLimiter(rate=10, capacity=20)  # 10 req/s
        async with limiter:
            ...  # guarded code
    """

    def __init__(self, rate: float, capacity: float) -> None:
        """
        Args:
            rate: Token refill rate (tokens per second).
            capacity: Maximum number of tokens in the bucket.
        """
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if capacity <= 0:
            raise ValueError("capacity must be > 0")

        self.rate = rate
        self.capacity = capacity
        self._tokens: float = capacity
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill (not thread-safe)."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    async def acquire(self, tokens: float = 1.0) -> None:
        """
        Wait until *tokens* tokens are available, then consume them.

        Args:
            tokens: Number of tokens to consume (default: 1).
        """
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # Calculate how long to wait for enough tokens
                deficit = tokens - self._tokens
                wait_time = deficit / self.rate

            await asyncio.sleep(wait_time)

    async def __aenter__(self) -> "TokenBucketRateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------

@dataclass
class RetryConfig:
    """
    Configuration for exponential-backoff retries.

    Attributes:
        max_attempts: Maximum number of total attempts (including the first).
        base_delay: Initial delay in seconds before the first retry.
        max_delay: Upper bound on the delay between retries.
        backoff_factor: Multiplier applied to the delay after each failure.
        jitter: If True, add ±25 % random jitter to each delay.
        retryable_exceptions: Tuple of exception types to catch and retry on.
            Defaults to ``(Exception,)``.
    """

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_factor: float = 2.0
    jitter: bool = True
    retryable_exceptions: Tuple[Type[BaseException], ...] = field(
        default_factory=lambda: (Exception,)
    )

    def delay_for(self, attempt: int) -> float:
        """
        Return the delay (seconds) to wait before *attempt* (1-indexed).

        ``attempt=1`` is the first retry (after the initial failure).
        """
        import random

        delay = min(self.base_delay * (self.backoff_factor ** (attempt - 1)), self.max_delay)
        if self.jitter:
            delay *= 0.75 + random.random() * 0.5  # ±25 %
        return delay


# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------

def with_retry(
    config: Optional[RetryConfig] = None,
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Tuple[Type[BaseException], ...] = (Exception,),
) -> Callable:
    """
    Decorator that retries an **async** function with exponential backoff.

    Can be used with a ``RetryConfig`` instance or by passing keyword args
    directly.

    Usage::

        @with_retry(max_attempts=5, base_delay=2.0)
        async def call_external_api(url: str) -> dict:
            ...

        # or with an explicit config object:
        cfg = RetryConfig(max_attempts=3, retryable_exceptions=(IOError,))

        @with_retry(cfg)
        async def my_func():
            ...
    """
    if config is None:
        config = RetryConfig(
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            backoff_factor=backoff_factor,
            jitter=jitter,
            retryable_exceptions=retryable_exceptions,
        )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Optional[BaseException] = None
            for attempt in range(1, config.max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except config.retryable_exceptions as exc:
                    last_exc = exc
                    if attempt == config.max_attempts:
                        logger.error(
                            "%s failed after %d attempts: %s",
                            func.__qualname__,
                            config.max_attempts,
                            exc,
                        )
                        raise
                    delay = config.delay_for(attempt)
                    logger.warning(
                        "%s attempt %d/%d failed (%s), retrying in %.2fs",
                        func.__qualname__,
                        attempt,
                        config.max_attempts,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
            raise last_exc  # should be unreachable

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Per-tool default rate-limit configurations
# ---------------------------------------------------------------------------

TOOL_RATE_LIMITS: dict[str, TokenBucketRateLimiter] = {
    # Naabu – port scanner: allow up to 1000 syn/s, burst of 2000
    "naabu": TokenBucketRateLimiter(rate=1000.0, capacity=2000.0),

    # Nuclei – vuln scanner: conservative defaults to avoid detection
    "nuclei": TokenBucketRateLimiter(rate=50.0, capacity=100.0),

    # httpx – HTTP probing: aggressive but reasonable
    "httpx": TokenBucketRateLimiter(rate=200.0, capacity=400.0),

    # Katana – web crawler: respect crawl-delay
    "katana": TokenBucketRateLimiter(rate=30.0, capacity=60.0),

    # Subfinder – passive recon: rate-limited by upstream APIs
    "subfinder": TokenBucketRateLimiter(rate=5.0, capacity=10.0),

    # GAU – external URL lookups via Wayback / Common Crawl / OTX / URLScan
    "gau": TokenBucketRateLimiter(rate=5.0, capacity=10.0),

    # Kiterunner – API brute-force: keep polite
    "kiterunner": TokenBucketRateLimiter(rate=50.0, capacity=100.0),
}


def get_rate_limiter(tool_name: str) -> TokenBucketRateLimiter:
    """
    Return the rate limiter for *tool_name*.

    Falls back to a conservative 10 req/s limiter if no config is registered.
    """
    return TOOL_RATE_LIMITS.get(tool_name, TokenBucketRateLimiter(rate=10.0, capacity=20.0))
