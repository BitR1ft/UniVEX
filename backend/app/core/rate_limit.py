"""
Per-user and per-project rate limiting using an in-process sliding window.

Also provides RedisRateLimiter for distributed rate limiting backed by Redis.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Optional

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """
    Thread-safe sliding window rate limiter backed by an in-process deque.

    Args:
        max_calls: Maximum number of calls allowed in the window.
        window_seconds: Length of the sliding window in seconds.
        name: Human-readable name for logging.
    """

    def __init__(self, max_calls: int, window_seconds: int, name: str = "default") -> None:
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.name = name
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _check_with_remaining(self, key: str) -> tuple[bool, int]:
        """
        Internal helper: check whether ``key`` is within the rate limit.

        Returns:
            (allowed, remaining): allowed is True if the call should proceed;
            remaining is the number of calls left in this window.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets[key]
            # Evict timestamps outside the window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_calls:
                return False, 0

            bucket.append(now)
            return True, self.max_calls - len(bucket)

    def is_allowed(self, key: str) -> bool:
        """
        Check whether ``key`` is within the rate limit.

        Returns:
            True if the call should proceed, False if the rate limit is exceeded.
        """
        allowed, _ = self._check_with_remaining(key)
        return allowed

    def check(self, key: str, *, correlation_id: Optional[str] = None) -> None:
        """
        Like :meth:`is_allowed` but raises HTTP 429 on limit exceeded.

        Args:
            key: Unique identifier (e.g. user_id or project_id).
            correlation_id: Request ID for audit logging.
        """
        allowed, remaining = self._check_with_remaining(key)
        if not allowed:
            logger.warning(
                "Rate limit exceeded for key=%s limiter=%s correlation_id=%s",
                key,
                self.name,
                correlation_id,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({self.max_calls} req/{self.window_seconds}s).",
                headers={"Retry-After": str(self.window_seconds)},
            )


class RedisRateLimiter:
    """
    Distributed sliding window rate limiter backed by Redis sorted sets.

    Uses ZADD/ZREMRANGEBYSCORE to implement a per-key sliding window.
    Gracefully falls back to :class:`SlidingWindowRateLimiter` when Redis
    is unavailable.

    Args:
        max_calls: Maximum number of calls allowed in the window.
        window_seconds: Length of the sliding window in seconds.
        name: Human-readable name for logging.
        redis_url: Redis connection URL (default: redis://localhost:6379).
    """

    def __init__(
        self,
        max_calls: int,
        window_seconds: int,
        name: str = "default",
        redis_url: str = "redis://localhost:6379",
    ) -> None:
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.name = name
        self._redis_url = redis_url
        self._redis: Optional[Any] = None
        self._fallback = SlidingWindowRateLimiter(max_calls, window_seconds, name)
        self._redis_available = False

    async def _get_redis(self) -> Optional[Any]:
        """Lazily connect to Redis; returns None on failure."""
        if self._redis is not None and self._redis_available:
            return self._redis
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
            client = await aioredis.from_url(self._redis_url, decode_responses=True)
            await client.ping()
            self._redis = client
            self._redis_available = True
            return client
        except Exception as exc:
            logger.debug("Redis unavailable for rate limiter '%s': %s", self.name, exc)
            self._redis_available = False
            return None

    async def _redis_check(self, key: str) -> tuple[bool, int]:
        """
        Atomic sliding-window check using a Redis Lua script.

        The Lua script runs atomically on the Redis server, eliminating the
        race condition that would arise from a pipeline-based check-then-add
        approach when multiple workers share the same rate-limit key.
        """
        client = await self._get_redis()
        if client is None:
            allowed, remaining = self._fallback._check_with_remaining(key)
            return allowed, remaining

        redis_key = f"ratelimit:{self.name}:{key}"
        now = time.time()
        window_start = now - self.window_seconds

        # Lua script: atomically prune old entries, check count, and conditionally add.
        # Returns: [allowed (0/1), remaining_slots]
        _LUA_SCRIPT = """
local key        = KEYS[1]
local now        = tonumber(ARGV[1])
local window_st  = tonumber(ARGV[2])
local max_calls  = tonumber(ARGV[3])
local ttl        = tonumber(ARGV[4])
local unique_id  = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_st)
local count = redis.call('ZCARD', key)

if count >= max_calls then
    return {0, 0}
end

redis.call('ZADD', key, now, unique_id)
redis.call('EXPIRE', key, ttl)
return {1, max_calls - count - 1}
"""
        import uuid as _uuid
        unique_id = f"{now}:{_uuid.uuid4()}"
        results = await client.eval(
            _LUA_SCRIPT,
            1,
            redis_key,
            now,
            window_start,
            self.max_calls,
            self.window_seconds + 1,
            unique_id,
        )
        allowed = bool(results[0])
        remaining = int(results[1])
        return allowed, remaining

    def _sync_check(self, key: str) -> tuple[bool, int]:
        """Synchronous check — delegates to in-memory fallback."""
        return self._fallback._check_with_remaining(key)

    def is_allowed(self, key: str) -> bool:
        """
        Synchronous interface (fallback only).

        For full Redis-backed checking use :meth:`is_allowed_async`.
        """
        allowed, _ = self._sync_check(key)
        return allowed

    async def is_allowed_async(self, key: str) -> bool:
        """Async Redis-backed check."""
        allowed, _ = await self._redis_check(key)
        return allowed

    def check(self, key: str, *, correlation_id: Optional[str] = None) -> None:
        """
        Synchronous check that raises HTTP 429 on limit exceeded.

        For async contexts prefer :meth:`check_async`.
        """
        allowed, _ = self._sync_check(key)
        if not allowed:
            logger.warning(
                "Rate limit exceeded for key=%s limiter=%s correlation_id=%s",
                key,
                self.name,
                correlation_id,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({self.max_calls} req/{self.window_seconds}s).",
                headers={"Retry-After": str(self.window_seconds)},
            )

    async def check_async(self, key: str, *, correlation_id: Optional[str] = None) -> None:
        """Async check that raises HTTP 429 on limit exceeded."""
        allowed, _ = await self._redis_check(key)
        if not allowed:
            logger.warning(
                "Rate limit exceeded for key=%s limiter=%s correlation_id=%s",
                key,
                self.name,
                correlation_id,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({self.max_calls} req/{self.window_seconds}s).",
                headers={"Retry-After": str(self.window_seconds)},
            )


# ---------------------------------------------------------------------------
# Pre-built limiters
# ---------------------------------------------------------------------------

# 60 API calls per user per minute
user_api_limiter = RedisRateLimiter(
    max_calls=60,
    window_seconds=60,
    name="user_api",
)

# 10 project start operations per user per hour
project_start_limiter = RedisRateLimiter(
    max_calls=10,
    window_seconds=3600,
    name="project_start",
)

# 5 login attempts per IP per 15 minutes  (brute-force protection)
login_limiter = RedisRateLimiter(
    max_calls=5,
    window_seconds=900,
    name="login",
)

# 20 agent chat messages per user per minute — prevents LLM cost runaway
agent_limiter = SlidingWindowRateLimiter(
    max_calls=20,
    window_seconds=60,
    name="agent_chat",
)

# 10 AutoChain starts per user per hour — expensive pipeline operations
autochain_limiter = SlidingWindowRateLimiter(
    max_calls=10,
    window_seconds=3600,
    name="autochain_start",
)
