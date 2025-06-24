"""

Async Python client for ClickHouse using the clickhouse-driver package.
Provides:
  - Connection pool management (thread-local connections in async context)
  - Parameterised query execution
  - Bulk INSERT helpers for high-throughput event recording
  - Health-check and schema introspection helpers

Environment variables
---------------------
CLICKHOUSE_HOST     : ClickHouse host (default: localhost)
CLICKHOUSE_PORT     : Native TCP port (default: 9000)
CLICKHOUSE_DATABASE : Default database (default: univex)
CLICKHOUSE_USER     : Username (default: default)
CLICKHOUSE_PASSWORD : Password (default: "")
CLICKHOUSE_POOL_SIZE: Connection pool size (default: 5)
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
from queue import Empty, Queue
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import of clickhouse_driver (optional dep — graceful degradation)
# ---------------------------------------------------------------------------

try:
    from clickhouse_driver import Client as _CHClient  # type: ignore
    _CLICKHOUSE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CHClient = None  # type: ignore
    _CLICKHOUSE_AVAILABLE = False
    logger.warning(
        "clickhouse-driver not installed; ClickHouseClient will operate in stub mode. "
        "Install with: pip install clickhouse-driver>=0.2.10"
    )


class ClickHouseSettings:
    """Reads ClickHouse connection settings from environment variables."""

    def __init__(self) -> None:
        self.host: str = os.getenv("CLICKHOUSE_HOST", "localhost")
        self.port: int = int(os.getenv("CLICKHOUSE_PORT", "9000"))
        self.database: str = os.getenv("CLICKHOUSE_DATABASE", "univex")
        self.user: str = os.getenv("CLICKHOUSE_USER", "default")
        self.password: str = os.getenv("CLICKHOUSE_PASSWORD", "")
        self.pool_size: int = int(os.getenv("CLICKHOUSE_POOL_SIZE", "5"))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "user": self.user,
            "password": self.password,
            "connect_timeout": 10,
            "send_receive_timeout": 30,
            "sync_request_timeout": 5,
            "compress_block_size": 1048576,
            "compression": False,
            "client_name": "univex-analytics",
            "settings": {
                "use_numpy": False,
            },
        }


class _StubClient:
    """No-op client used when clickhouse-driver is not installed."""

    def execute(self, query: str, params: Any = None, **kwargs: Any) -> List:
        logger.debug("ClickHouse STUB execute: %s", query[:80])
        return []

    def disconnect(self) -> None:
        pass

    def connection(self) -> None:  # type: ignore[return]
        return None


class ClickHousePool:
    """
    Thread-safe connection pool for clickhouse-driver (synchronous driver).

    clickhouse-driver uses synchronous sockets.  We wrap pool acquisition in
    ``asyncio.to_thread`` so that pool operations never block the event loop.
    """

    def __init__(self, settings: ClickHouseSettings) -> None:
        self._settings = settings
        self._pool: Queue = Queue(maxsize=settings.pool_size)
        self._lock = threading.Lock()
        self._available = True

        for _ in range(settings.pool_size):
            self._pool.put(self._make_client())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_client(self) -> Any:
        if not _CLICKHOUSE_AVAILABLE:
            return _StubClient()
        try:
            return _CHClient(**self._settings.as_dict())
        except Exception as exc:
            logger.warning("ClickHouse connection failed, using stub: %s", exc)
            return _StubClient()

    def _acquire(self, timeout: float = 5.0) -> Any:
        try:
            return self._pool.get(timeout=timeout)
        except Empty:
            logger.warning("ClickHouse pool exhausted — creating transient connection")
            return self._make_client()

    def _release(self, client: Any) -> None:
        try:
            self._pool.put_nowait(client)
        except Exception:
            # Pool is full (transient connection); just discard
            client.disconnect()

    # ------------------------------------------------------------------
    # Public async interface
    # ------------------------------------------------------------------

    async def execute(
        self,
        query: str,
        params: Optional[Any] = None,
        with_column_types: bool = False,
    ) -> Any:
        """Execute a query, acquiring and releasing a pool connection."""
        return await asyncio.to_thread(
            self._sync_execute, query, params, with_column_types
        )

    def _sync_execute(
        self,
        query: str,
        params: Any,
        with_column_types: bool,
    ) -> Any:
        client = self._acquire()
        try:
            kwargs: Dict[str, Any] = {}
            if with_column_types:
                kwargs["with_column_types"] = True
            result = client.execute(query, params or [], **kwargs)
            return result
        except Exception as exc:
            logger.error("ClickHouse query failed: %s | query=%.120s", exc, query)
            raise
        finally:
            self._release(client)

    async def close(self) -> None:
        """Drain and close all connections in the pool."""
        while not self._pool.empty():
            try:
                client = self._pool.get_nowait()
                client.disconnect()
            except Exception:
                pass
        self._available = False


class ClickHouseClient:
    """
    High-level async client for UniVex analytics.

    Usage::

        client = ClickHouseClient()
        await client.execute("INSERT INTO agent_runs (...) VALUES", rows)

    The client is a thin async wrapper around ``ClickHousePool``.  Callers
    should obtain a module-level singleton via ``get_clickhouse_client()``.
    """

    def __init__(self, settings: Optional[ClickHouseSettings] = None) -> None:
        self._settings = settings or ClickHouseSettings()
        self._pool = ClickHousePool(self._settings)

    # ------------------------------------------------------------------
    # Core query API
    # ------------------------------------------------------------------

    async def execute(
        self,
        query: str,
        params: Optional[Any] = None,
        with_column_types: bool = False,
    ) -> Any:
        """
        Execute an arbitrary ClickHouse query.

        Args:
            query: SQL string.  Use %s placeholders for parameters.
            params: List of parameter values or a dict (clickhouse-driver format).
            with_column_types: If True, returns (rows, column_types) tuple.

        Returns:
            List of result rows (tuples), or (rows, types) if with_column_types.
        """
        logger.debug("ClickHouse execute: %.120s", query)
        return await self._pool.execute(query, params, with_column_types)

    async def insert(self, table: str, rows: Sequence[Dict[str, Any]]) -> None:
        """
        Bulk insert rows into *table*.

        Args:
            table: Fully-qualified table name (e.g. ``univex.agent_runs``).
            rows: List of dicts mapping column name → value.
        """
        if not rows:
            return

        columns = list(rows[0].keys())
        col_str = ", ".join(columns)
        query = f"INSERT INTO {table} ({col_str}) VALUES"
        values = [[row[col] for col in columns] for row in rows]
        await self._pool.execute(query, values)
        logger.debug("Inserted %d rows into %s", len(rows), table)

    async def fetch_one(
        self, query: str, params: Optional[Any] = None
    ) -> Optional[Tuple]:
        """Return the first row of a SELECT, or None."""
        rows = await self.execute(query, params)
        return rows[0] if rows else None

    async def fetch_all(
        self, query: str, params: Optional[Any] = None
    ) -> List[Tuple]:
        """Return all rows of a SELECT."""
        result = await self.execute(query, params)
        return result if result else []

    # ------------------------------------------------------------------
    # Health & schema helpers
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """Return True if ClickHouse is reachable."""
        try:
            result = await self.fetch_one("SELECT 1")
            return result is not None and result[0] == 1
        except Exception as exc:
            logger.warning("ClickHouse ping failed: %s", exc)
            return False

    async def table_exists(self, table: str, database: Optional[str] = None) -> bool:
        """Return True if *table* exists in *database* (default: configured db)."""
        db = database or self._settings.database
        rows = await self.fetch_all(
            "SELECT name FROM system.tables WHERE database = %(db)s AND name = %(tbl)s",
            {"db": db, "tbl": table},
        )
        return len(rows) > 0

    async def get_table_columns(
        self, table: str, database: Optional[str] = None
    ) -> List[Tuple[str, str]]:
        """Return list of (column_name, type) tuples for *table*."""
        db = database or self._settings.database
        rows = await self.fetch_all(
            "SELECT name, type FROM system.columns "
            "WHERE database = %(db)s AND table = %(tbl)s ORDER BY position",
            {"db": db, "tbl": table},
        )
        return [(r[0], r[1]) for r in rows]

    # Allowlist of valid table names to prevent SQL injection via get_row_count
    _VALID_TABLES: frozenset = frozenset({
        "univex.agent_runs",
        "univex.tool_executions",
        "univex.findings",
        "univex.scan_sessions",
        "univex.llm_calls",
        "mv_daily_agent_stats",
        "mv_daily_llm_cost",
        "mv_daily_findings",
        "mv_tool_performance",
    })

    async def get_row_count(self, table: str) -> int:
        """
        Return approximate row count for *table*.

        Args:
            table: Fully-qualified table name (must be in the allowed list).

        Raises:
            ValueError: If *table* is not in the allowlist.
        """
        if table not in self._VALID_TABLES:
            raise ValueError(
                f"Table '{table}' is not in the list of allowed tables. "
                f"Allowed: {sorted(self._VALID_TABLES)}"
            )
        result = await self.fetch_one(
            f"SELECT count() FROM {table}"  # noqa: S608
        )
        return int(result[0]) if result else 0

    async def close(self) -> None:
        """Close all pool connections."""
        await self._pool.close()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_client: Optional[ClickHouseClient] = None
_client_lock = asyncio.Lock()


async def get_clickhouse_client() -> ClickHouseClient:
    """Return the module-level ClickHouseClient singleton (lazy init)."""
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = ClickHouseClient()
    return _client


def set_clickhouse_client(client: ClickHouseClient) -> None:
    """Override the singleton — used in tests to inject a mock client."""
    global _client
    _client = client
