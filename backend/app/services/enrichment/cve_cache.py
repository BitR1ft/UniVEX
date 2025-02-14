"""
CVE Caching System

Provides a SQLite-backed persistent cache for :class:`EnrichedCVE` objects.

Design
------
- Uses Python's built-in ``sqlite3`` (no extra dependencies).
- Records are serialised to JSON and compressed with zlib for storage.
- Expiry is enforced at read time: stale records are treated as cache misses
  and automatically deleted.
- ``warm()`` accepts a list of CVE IDs and pre-populates the cache by
  forwarding fetches to a provided callable.

Schema
------
    cve_cache(
        cve_id   TEXT PRIMARY KEY,
        data     TEXT   -- JSON-encoded EnrichedCVE (field-level dataclass serialisation)
        stored_at REAL  -- Unix timestamp
    )
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
import zlib
from pathlib import Path
from typing import Any, Callable, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = str(Path.home() / ".univex" / "cve_cache.db")


# ---------------------------------------------------------------------------
# CVECache
# ---------------------------------------------------------------------------

class CVECache:
    """
    SQLite-backed cache for :class:`~app.services.enrichment.enrichment_service.EnrichedCVE`
    objects.

    Args:
        ttl_days:  How many days before a cached entry is considered stale.
        db_path:   Path to the SQLite database file.  Defaults to
                   ``~/.univex/cve_cache.db``.
    """

    def __init__(
        self,
        ttl_days: int = 30,
        db_path: Optional[str] = None,
    ) -> None:
        self._ttl_seconds = ttl_days * 86_400
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._lock = asyncio.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema setup
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Create the cache database and table if they do not exist."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id    TEXT PRIMARY KEY,
                    data      BLOB NOT NULL,
                    stored_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_stored ON cve_cache(stored_at)")
            conn.commit()

    # ------------------------------------------------------------------
    # Get / Set
    # ------------------------------------------------------------------

    async def get(self, cve_id: str) -> Optional[Any]:
        """
        Return a cached :class:`EnrichedCVE` or ``None`` on miss / expiry.
        """
        async with self._lock:
            return await asyncio.get_event_loop().run_in_executor(
                None, self._sync_get, cve_id
            )

    def _sync_get(self, cve_id: str) -> Optional[Any]:
        try:
            with sqlite3.connect(self._db_path) as conn:
                row = conn.execute(
                    "SELECT data, stored_at FROM cve_cache WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()
            if not row:
                return None
            data_blob, stored_at = row
            age = time.time() - stored_at
            if age > self._ttl_seconds:
                # Stale – delete and return miss
                self._sync_delete(cve_id)
                return None
            return _deserialise(data_blob)
        except Exception as exc:
            logger.warning("Cache get failed for %s: %s", cve_id, exc)
            return None

    async def set(self, cve_id: str, enriched: Any) -> None:
        """Store *enriched* in the cache keyed by *cve_id*."""
        async with self._lock:
            await asyncio.get_event_loop().run_in_executor(
                None, self._sync_set, cve_id, enriched
            )

    def _sync_set(self, cve_id: str, enriched: Any) -> None:
        try:
            blob = _serialise(enriched)
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_cache (cve_id, data, stored_at)
                    VALUES (?, ?, ?)
                    """,
                    (cve_id, blob, time.time()),
                )
                conn.commit()
        except Exception as exc:
            logger.warning("Cache set failed for %s: %s", cve_id, exc)

    # ------------------------------------------------------------------
    # Delete / Purge
    # ------------------------------------------------------------------

    def _sync_delete(self, cve_id: str) -> None:
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("DELETE FROM cve_cache WHERE cve_id = ?", (cve_id,))
                conn.commit()
        except Exception as exc:
            logger.warning("Cache delete failed for %s: %s", cve_id, exc)

    async def purge_expired(self) -> int:
        """Delete all entries older than TTL.  Returns number of rows deleted."""
        cutoff = time.time() - self._ttl_seconds
        async with self._lock:
            def _do() -> int:
                with sqlite3.connect(self._db_path) as conn:
                    cur = conn.execute(
                        "DELETE FROM cve_cache WHERE stored_at < ?", (cutoff,)
                    )
                    conn.commit()
                    return cur.rowcount
            return await asyncio.get_event_loop().run_in_executor(None, _do)

    async def count(self) -> int:
        """Return the number of entries currently in the cache."""
        def _do() -> int:
            with sqlite3.connect(self._db_path) as conn:
                return conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        return await asyncio.get_event_loop().run_in_executor(None, _do)

    # ------------------------------------------------------------------
    # Cache warming
    # ------------------------------------------------------------------

    async def warm(
        self,
        cve_ids: List[str],
        fetcher: Callable[[str], Any],
        concurrency: int = 5,
    ) -> int:
        """
        Pre-populate the cache for *cve_ids* using *fetcher*.

        Skips IDs that are already cached and fresh.

        Args:
            cve_ids:    List of CVE IDs to pre-fetch.
            fetcher:    Async callable ``(cve_id) -> EnrichedCVE | None``.
            concurrency: Maximum number of simultaneous fetches.

        Returns:
            Number of new entries written to the cache.
        """
        sem = asyncio.Semaphore(concurrency)
        written = 0

        async def _fetch_one(cve_id: str) -> None:
            nonlocal written
            existing = await self.get(cve_id)
            if existing:
                return  # Already warm
            async with sem:
                try:
                    result = await fetcher(cve_id)
                    if result:
                        await self.set(cve_id, result)
                        written += 1
                except Exception as exc:
                    logger.warning("Warm-up failed for %s: %s", cve_id, exc)

        await asyncio.gather(*[_fetch_one(c) for c in cve_ids])
        logger.info("Cache warm-up complete: %d/%d entries written", written, len(cve_ids))
        return written


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _serialise(enriched: Any) -> bytes:
    """Serialise an EnrichedCVE to compressed JSON bytes."""
    import dataclasses
    from datetime import datetime

    def _default(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")

    raw_json = json.dumps(
        __dataclass_to_dict(enriched), default=_default
    ).encode()
    return zlib.compress(raw_json)


def _deserialise(blob: bytes) -> Any:
    """Deserialise compressed JSON bytes back to an EnrichedCVE."""
    from app.services.enrichment.enrichment_service import (
        CVSSVector,
        EnrichedCVE,
        ExploitInfo,
    )
    from datetime import datetime, timezone

    raw_json = zlib.decompress(blob)
    data = json.loads(raw_json)

    # Reconstruct nested dataclasses
    cvss_v3 = None
    if data.get("cvss_v3"):
        cvss_v3 = CVSSVector(**data["cvss_v3"])

    exploit_info = ExploitInfo(**data.get("exploit_info", {}))

    def _dt(val: Optional[str]) -> Optional[datetime]:
        if not val:
            return None
        return datetime.fromisoformat(val)

    return EnrichedCVE(
        cve_id=data["cve_id"],
        description=data.get("description"),
        published=_dt(data.get("published")),
        last_modified=_dt(data.get("last_modified")),
        cvss_v3=cvss_v3,
        cvss_v2_score=data.get("cvss_v2_score"),
        cwe_ids=data.get("cwe_ids", []),
        capec_ids=data.get("capec_ids", []),
        exploit_info=exploit_info,
        cpe_matches=data.get("cpe_matches", []),
        affected_versions=data.get("affected_versions", []),
        sources=data.get("sources", []),
        fetched_at=_dt(data.get("fetched_at")) or datetime.now(timezone.utc),
        raw=data.get("raw", {}),
    )


def __dataclass_to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses to plain dicts."""
    import dataclasses
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: __dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [__dataclass_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {k: __dataclass_to_dict(v) for k, v in obj.items()}
    return obj
