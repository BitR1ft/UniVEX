"""
Redis Client — Connection pooling, auto-reconnection, health checks, pub/sub.

"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator, Optional

import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import ConnectionError, RedisError, TimeoutError

logger = logging.getLogger(__name__)

_BACKOFF_BASE = 0.5   # seconds
_BACKOFF_MAX = 30.0   # seconds


def get_connection_pool(
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None,
    max_connections: int = 20,
) -> ConnectionPool:
    """Factory for a shared async Redis connection pool."""
    return aioredis.ConnectionPool(
        host=host,
        port=port,
        db=db,
        password=password,
        max_connections=max_connections,
        decode_responses=True,
    )


class RedisClient:
    """
    Async Redis wrapper with connection pooling, automatic reconnection,
    health checks, and pub/sub support.

    Usage::

        async with RedisClient(url="redis://localhost:6379") as client:
            await client.set("key", "value")
            val = await client.get("key")
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379",
        pool: Optional[ConnectionPool] = None,
        max_retries: int = 5,
        decode_responses: bool = True,
    ) -> None:
        self._url = url
        self._pool = pool
        self._max_retries = max_retries
        self._decode_responses = decode_responses
        self._client: Optional[aioredis.Redis] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open connection (or reuse pool)."""
        if self._pool is not None:
            self._client = aioredis.Redis(connection_pool=self._pool)
        else:
            self._client = await aioredis.from_url(
                self._url,
                decode_responses=self._decode_responses,
            )

    async def disconnect(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # Context-manager support
    async def __aenter__(self) -> "RedisClient":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _redis(self) -> aioredis.Redis:
        if self._client is None:
            raise RuntimeError("RedisClient is not connected. Call connect() first.")
        return self._client

    async def _with_retry(self, coro_fn, *args, **kwargs):
        """Execute *coro_fn* with exponential-backoff retry on connection errors."""
        backoff = _BACKOFF_BASE
        for attempt in range(1, self._max_retries + 1):
            try:
                return await coro_fn(*args, **kwargs)
            except (ConnectionError, TimeoutError) as exc:
                if attempt == self._max_retries:
                    logger.error("Redis connection failed after %d retries: %s", attempt, exc)
                    raise
                logger.warning(
                    "Redis connection error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt,
                    self._max_retries,
                    exc,
                    backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _BACKOFF_MAX)
                # Reconnect
                try:
                    await self.connect()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Core operations (with retry)
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Optional[str]:
        return await self._with_retry(self._redis.get, key)

    async def set(
        self,
        key: str,
        value: str,
        ex: Optional[int] = None,
        px: Optional[int] = None,
        nx: bool = False,
    ) -> Optional[bool]:
        return await self._with_retry(self._redis.set, key, value, ex=ex, px=px, nx=nx)

    async def delete(self, *keys: str) -> int:
        return await self._with_retry(self._redis.delete, *keys)

    async def exists(self, *keys: str) -> int:
        return await self._with_retry(self._redis.exists, *keys)

    async def expire(self, key: str, seconds: int) -> bool:
        return await self._with_retry(self._redis.expire, key, seconds)

    async def ttl(self, key: str) -> int:
        return await self._with_retry(self._redis.ttl, key)

    async def keys(self, pattern: str = "*") -> list[str]:
        return await self._with_retry(self._redis.keys, pattern)

    async def incr(self, key: str) -> int:
        return await self._with_retry(self._redis.incr, key)

    async def zadd(self, name: str, mapping: dict) -> int:
        return await self._with_retry(self._redis.zadd, name, mapping)

    async def zrange(self, name: str, start: int, end: int, withscores: bool = False):
        return await self._with_retry(self._redis.zrange, name, start, end, withscores=withscores)

    async def zrangebyscore(self, name: str, min: float, max: float):
        return await self._with_retry(self._redis.zrangebyscore, name, min, max)

    async def zremrangebyscore(self, name: str, min: float, max: float) -> int:
        return await self._with_retry(self._redis.zremrangebyscore, name, min, max)

    async def zcard(self, name: str) -> int:
        return await self._with_retry(self._redis.zcard, name)

    async def zpopmax(self, name: str, count: int = 1):
        """Atomically pop the member(s) with the highest score(s)."""
        return await self._with_retry(self._redis.zpopmax, name, count)

    async def zrem(self, name: str, *values) -> int:
        return await self._with_retry(self._redis.zrem, name, *values)

    async def lpush(self, name: str, *values) -> int:
        return await self._with_retry(self._redis.lpush, name, *values)

    async def rpush(self, name: str, *values) -> int:
        return await self._with_retry(self._redis.rpush, name, *values)

    async def lpop(self, name: str) -> Optional[str]:
        return await self._with_retry(self._redis.lpop, name)

    async def rpop(self, name: str) -> Optional[str]:
        return await self._with_retry(self._redis.rpop, name)

    async def llen(self, name: str) -> int:
        return await self._with_retry(self._redis.llen, name)

    async def hset(self, name: str, mapping: dict) -> int:
        return await self._with_retry(self._redis.hset, name, mapping=mapping)

    async def hget(self, name: str, key: str) -> Optional[str]:
        return await self._with_retry(self._redis.hget, name, key)

    async def hgetall(self, name: str) -> dict:
        return await self._with_retry(self._redis.hgetall, name)

    async def hdel(self, name: str, *keys: str) -> int:
        return await self._with_retry(self._redis.hdel, name, *keys)

    async def scan_iter(self, match: str = "*") -> AsyncIterator[str]:
        """Async iteration over matching keys (no retry wrapper — generator)."""
        async for key in self._redis.scan_iter(match=match):
            yield key

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> bool:
        """Return True if Redis responds to PING."""
        try:
            result = await self._redis.ping()
            return bool(result)
        except (RedisError, RuntimeError):
            return False

    # ------------------------------------------------------------------
    # Pub/Sub
    # ------------------------------------------------------------------

    async def publish(self, channel: str, message: Any) -> int:
        """Publish *message* (JSON-serialised if not str) to *channel*."""
        if not isinstance(message, str):
            message = json.dumps(message)
        return await self._with_retry(self._redis.publish, channel, message)

    async def subscribe(self, channel: str) -> aioredis.client.PubSub:
        """Return a PubSub object subscribed to *channel*."""
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(channel)
        return pubsub

    async def listen(self, pubsub: aioredis.client.PubSub) -> AsyncIterator[Any]:
        """Async-iterate over messages from *pubsub*."""
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                try:
                    yield json.loads(data)
                except (json.JSONDecodeError, TypeError):
                    yield data
