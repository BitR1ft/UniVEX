"""
CacheManager — TTL-based caching with Redis backend and in-memory fallback.

"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.redis_client import RedisClient

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Metadata wrapper around a cached value."""
    value: Any
    ttl: int                       # seconds; -1 = no expiry
    created_at: float = field(default_factory=time.time)
    hits: int = 0

    def is_expired(self) -> bool:
        if self.ttl < 0:
            return False
        return (time.time() - self.created_at) > self.ttl


class CacheManager:
    """
    TTL-aware cache backed by Redis with transparent in-memory fallback.

    All keys are namespaced as ``{namespace}:{key}`` to avoid collisions across
    multiple instances or services.

    Args:
        redis_client: Connected :class:`RedisClient` instance (optional).
        namespace: Key prefix for all entries stored by this manager.
        default_ttl: Default time-to-live in seconds (default 300).
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        namespace: str = "cache",
        default_ttl: int = 300,
    ) -> None:
        self._redis = redis_client
        self._namespace = namespace
        self._default_ttl = default_ttl
        # In-memory fallback store
        self._memory: dict[str, CacheEntry] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _full_key(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    def _serialize(self, value: Any) -> str:
        return json.dumps(value, default=str)

    def _deserialize(self, raw: str) -> Any:
        return json.loads(raw)

    def _cleanup_memory(self) -> None:
        expired = [k for k, v in self._memory.items() if v.is_expired()]
        for k in expired:
            del self._memory[k]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a value by *key*.

        Returns:
            Deserialized value or None if missing / expired.
        """
        full_key = self._full_key(key)

        if self._redis is not None:
            try:
                raw = await self._redis.get(full_key)
                if raw is None:
                    return None
                return self._deserialize(raw)
            except Exception as exc:
                logger.warning("Redis get failed, using in-memory fallback: %s", exc)

        # In-memory fallback
        entry = self._memory.get(full_key)
        if entry is None:
            return None
        if entry.is_expired():
            del self._memory[full_key]
            return None
        entry.hits += 1
        return entry.value

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Store *value* under *key* with an optional TTL (seconds).

        Falls back to in-memory when Redis is unavailable.
        """
        full_key = self._full_key(key)
        effective_ttl = ttl if ttl is not None else self._default_ttl
        serialized = self._serialize(value)

        if self._redis is not None:
            try:
                await self._redis.set(full_key, serialized, ex=effective_ttl if effective_ttl >= 0 else None)
                return
            except Exception as exc:
                logger.warning("Redis set failed, using in-memory fallback: %s", exc)

        # In-memory fallback
        self._cleanup_memory()
        self._memory[full_key] = CacheEntry(value=value, ttl=effective_ttl)

    async def delete(self, key: str) -> None:
        """Remove a single entry."""
        full_key = self._full_key(key)

        if self._redis is not None:
            try:
                await self._redis.delete(full_key)
            except Exception as exc:
                logger.warning("Redis delete failed: %s", exc)

        self._memory.pop(full_key, None)

    async def invalidate_prefix(self, prefix: str) -> int:
        """
        Delete all keys whose *key* (without namespace) starts with *prefix*.

        Returns:
            Number of deleted keys.
        """
        full_prefix = self._full_key(prefix)
        deleted = 0

        if self._redis is not None:
            try:
                # NOTE: KEYS blocks Redis while scanning. For large key spaces,
                # replace with SCAN (redis_client.scan_iter) to avoid latency spikes.
                keys = await self._redis.keys(f"{full_prefix}*")
                if keys:
                    deleted = await self._redis.delete(*keys)
                # Also clear memory for those keys
                for k in list(self._memory.keys()):
                    if k.startswith(full_prefix):
                        del self._memory[k]
                return deleted
            except Exception as exc:
                logger.warning("Redis invalidate_prefix failed, falling back: %s", exc)

        # In-memory fallback
        to_delete = [k for k in self._memory if k.startswith(full_prefix)]
        for k in to_delete:
            del self._memory[k]
        return len(to_delete)

    async def flush_namespace(self, namespace: Optional[str] = None) -> int:
        """
        Delete ALL keys in *namespace* (defaults to this manager's namespace).

        Returns:
            Number of deleted keys.
        """
        return await self.invalidate_prefix("")  # Uses self._namespace prefix already

    async def get_entry(self, key: str) -> Optional[CacheEntry]:
        """Return a :class:`CacheEntry` with metadata (in-memory only)."""
        full_key = self._full_key(key)
        entry = self._memory.get(full_key)
        if entry and entry.is_expired():
            del self._memory[full_key]
            return None
        return entry
