"""
Proxy Request Store

In-memory + optional Redis-backed storage for captured HTTP/HTTPS
request/response pairs with TTL-based expiration and rich search support.

Features:
  - Stores CapturedRequest + CapturedResponse pairs keyed by UUID
  - TTL-based expiration (default 1 hour)
  - Search/filter by URL substring, method, status code, content type,
    and arbitrary body regex
  - Optional Redis backing: on store the entry is also written to Redis
    (JSON) with the same TTL; on miss the in-memory layer falls back to
    Redis for distributed lookup
  - Thread-safe via asyncio.Lock

OWASP: A10:2021-Server-Side Request Forgery / A04:2021-Insecure Design
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CapturedResponse:
    """Serialisable snapshot of an HTTP response."""

    status_code: int
    reason: str
    headers: Dict[str, str]
    body: str  # UTF-8 decoded; binary bodies are base64-encoded strings
    content_type: str
    elapsed_ms: float  # round-trip time in milliseconds


@dataclass
class CapturedRequest:
    """Serialisable snapshot of an HTTP request + its paired response."""

    id: str
    timestamp: float  # Unix epoch seconds
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    response: Optional[CapturedResponse] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapturedRequest":
        resp_data = d.pop("response", None)
        req = cls(**d)
        if resp_data:
            req.response = CapturedResponse(**resp_data)
        return req

    def to_har_entry(self) -> Dict[str, Any]:
        """Convert to HAR (HTTP Archive) entry format."""
        entry: Dict[str, Any] = {
            "startedDateTime": _epoch_to_iso(self.timestamp),
            "time": self.response.elapsed_ms if self.response else 0,
            "request": {
                "method": self.method,
                "url": self.url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in self.headers.items()],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(self.body.encode("utf-8")),
                "postData": {"mimeType": "application/octet-stream", "text": self.body}
                if self.body
                else None,
            },
            "response": {},
            "cache": {},
            "timings": {"send": 0, "wait": self.response.elapsed_ms if self.response else 0, "receive": 0},
        }
        if self.response:
            entry["response"] = {
                "status": self.response.status_code,
                "statusText": self.response.reason,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in self.response.headers.items()],
                "cookies": [],
                "content": {
                    "size": len(self.response.body.encode("utf-8")),
                    "mimeType": self.response.content_type,
                    "text": self.response.body,
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(self.response.body.encode("utf-8")),
            }
        return entry


def _epoch_to_iso(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# RequestStore
# ---------------------------------------------------------------------------


class RequestStore:
    """
    Central store for captured HTTP request/response pairs.

    ``store()`` persists a ``CapturedRequest`` in memory (and optionally to
    Redis).  Callers can later ``get()``, ``search()``, ``export_har()``,
    or ``export_csv()`` captured traffic.

    Args:
        ttl_seconds:      Lifetime for stored entries (default: 3600 s / 1 h).
        max_entries:      Maximum entries to hold in memory.  Oldest entries are
                          evicted when the limit is reached (default: 10 000).
        redis_client:     Optional async Redis client (e.g. ``redis.asyncio.Redis``).
                          When provided, entries are written through to Redis and
                          looked up from Redis on cache miss.
    """

    def __init__(
        self,
        ttl_seconds: int = 3600,
        max_entries: int = 10_000,
        redis_client: Optional[Any] = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._redis = redis_client
        self._store: Dict[str, CapturedRequest] = {}
        self._expiry: Dict[str, float] = {}  # id → expiry epoch
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def store(self, request: CapturedRequest) -> str:
        """
        Persist *request*.  If the request has no ``id`` a UUID is assigned.

        Returns the assigned ``id``.
        """
        if not request.id:
            request.id = str(uuid.uuid4())

        async with self._lock:
            await self._evict_expired()

            # Evict oldest if at capacity
            while len(self._store) >= self._max:
                oldest_id = next(iter(self._store))
                del self._store[oldest_id]
                self._expiry.pop(oldest_id, None)

            self._store[request.id] = request
            self._expiry[request.id] = time.monotonic() + self._ttl

        if self._redis:
            await self._redis_set(request)

        return request.id

    async def update(self, request_id: str, **kwargs: Any) -> bool:
        """
        Update fields on an existing ``CapturedRequest``.

        Returns True if the entry was found and updated.
        """
        async with self._lock:
            req = self._store.get(request_id)
            if req is None:
                return False
            for key, value in kwargs.items():
                if hasattr(req, key):
                    setattr(req, key, value)
        return True

    async def delete(self, request_id: str) -> bool:
        """Remove a specific entry.  Returns True if it existed."""
        async with self._lock:
            if request_id in self._store:
                del self._store[request_id]
                self._expiry.pop(request_id, None)
                return True
        return False

    async def clear(self) -> int:
        """Remove all entries.  Returns the count that were removed."""
        async with self._lock:
            count = len(self._store)
            self._store.clear()
            self._expiry.clear()
        if self._redis:
            # Best-effort clear of redis keys managed by this store instance
            try:
                await self._redis.flushdb()
            except Exception:
                pass
        return count

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, request_id: str) -> Optional[CapturedRequest]:
        """Retrieve a specific entry, falling back to Redis on miss."""
        async with self._lock:
            req = self._store.get(request_id)
            if req and not self._is_expired(request_id):
                return req

        if self._redis:
            return await self._redis_get(request_id)
        return None

    async def list_all(
        self, page: int = 1, page_size: int = 100
    ) -> List[CapturedRequest]:
        """Return all non-expired entries, newest first, paginated."""
        async with self._lock:
            await self._evict_expired()
            entries = list(reversed(list(self._store.values())))
        offset = (page - 1) * page_size
        return entries[offset : offset + page_size]

    async def count(self) -> int:
        async with self._lock:
            await self._evict_expired()
            return len(self._store)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    async def search(
        self,
        url_contains: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        content_type_contains: Optional[str] = None,
        body_regex: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[CapturedRequest]:
        """
        Return captured requests matching ALL specified filters.

        All filters are optional; omitting a filter means "match any".

        Args:
            url_contains:           Substring that must appear in the URL.
            method:                 HTTP method (GET/POST/etc.), case-insensitive.
            status_code:            Exact response status code to match.
            content_type_contains:  Substring in response Content-Type.
            body_regex:             Regular expression matched against request OR
                                    response body.
            tag:                    Tag that must be present in ``request.tags``.
        """
        compiled_regex: Optional[re.Pattern] = None
        if body_regex:
            try:
                compiled_regex = re.compile(body_regex, re.IGNORECASE | re.DOTALL)
            except re.error as exc:
                raise ValueError(f"Invalid body_regex: {exc}") from exc

        async with self._lock:
            await self._evict_expired()
            candidates = list(self._store.values())

        results: List[CapturedRequest] = []
        for req in candidates:
            if url_contains and url_contains.lower() not in req.url.lower():
                continue
            if method and req.method.upper() != method.upper():
                continue
            if status_code is not None:
                if req.response is None or req.response.status_code != status_code:
                    continue
            if content_type_contains:
                if req.response is None or content_type_contains.lower() not in req.response.content_type.lower():
                    continue
            if tag and tag not in req.tags:
                continue
            if compiled_regex:
                req_body_match = compiled_regex.search(req.body or "")
                resp_body_match = (
                    compiled_regex.search(req.response.body or "")
                    if req.response
                    else False
                )
                if not req_body_match and not resp_body_match:
                    continue
            results.append(req)

        return list(reversed(results))

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_har(self, entries: List[CapturedRequest]) -> str:
        """Export a list of captured requests as an HTTP Archive (HAR) JSON string."""
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "UniVex Proxy", "version": "1.0.0"},
                "entries": [e.to_har_entry() for e in entries],
            }
        }
        return json.dumps(har, indent=2)

    def export_json(self, entries: List[CapturedRequest]) -> str:
        """Export entries as a JSON array."""
        return json.dumps([e.to_dict() for e in entries], indent=2)

    def export_csv(self, entries: List[CapturedRequest]) -> str:
        """Export entries as a minimal CSV string."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["id", "timestamp", "method", "url", "status_code", "content_type", "elapsed_ms"]
        )
        for e in entries:
            writer.writerow(
                [
                    e.id,
                    e.timestamp,
                    e.method,
                    e.url,
                    e.response.status_code if e.response else "",
                    e.response.content_type if e.response else "",
                    e.response.elapsed_ms if e.response else "",
                ]
            )
        return output.getvalue()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _is_expired(self, request_id: str) -> bool:
        expiry = self._expiry.get(request_id)
        return expiry is None or time.monotonic() > expiry

    async def _evict_expired(self) -> None:
        """Remove all expired entries.  Must be called with the lock held."""
        now = time.monotonic()
        expired = [k for k, exp in self._expiry.items() if now > exp]
        for k in expired:
            self._store.pop(k, None)
            self._expiry.pop(k, None)

    # ------------------------------------------------------------------
    # Redis helpers
    # ------------------------------------------------------------------

    def _redis_key(self, request_id: str) -> str:
        return f"univex:proxy:req:{request_id}"

    async def _redis_set(self, request: CapturedRequest) -> None:
        try:
            payload = json.dumps(request.to_dict())
            await self._redis.setex(self._redis_key(request.id), self._ttl, payload)
        except Exception as exc:
            logger.warning("Redis write failed: %s", exc)

    async def _redis_get(self, request_id: str) -> Optional[CapturedRequest]:
        try:
            raw = await self._redis.get(self._redis_key(request_id))
            if raw:
                d = json.loads(raw)
                return CapturedRequest.from_dict(d)
        except Exception as exc:
            logger.warning("Redis read failed: %s", exc)
        return None
