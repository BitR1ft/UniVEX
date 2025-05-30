"""
pgvector-backed vector store — async PostgreSQL implementation.

Provides a :class:`PGVectorStore` that uses the ``pgvector`` extension for
cosine-similarity search.  Designed as a production-grade alternative to
ChromaDB that lives entirely within the existing PostgreSQL database.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_CREATE_EXTENSION = "CREATE EXTENSION IF NOT EXISTS vector;"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS embeddings (
    id          TEXT PRIMARY KEY,
    collection  TEXT NOT NULL DEFAULT 'default',
    doc_text    TEXT NOT NULL,
    embedding   vector({dims}),
    metadata    JSONB NOT NULL DEFAULT '{{}}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_embeddings_collection
ON embeddings (collection);
"""


@dataclass
class SearchResult:
    """A single result returned from a vector similarity search."""

    doc_id: str
    text: str
    score: float  # cosine similarity ∈ [0, 1]
    metadata: Dict[str, Any] = field(default_factory=dict)
    collection: str = "default"


class PGVectorStore:
    """
    Async pgvector-backed vector store.

    Parameters
    ----------
    database_url:
        PostgreSQL DSN.  Falls back to the ``DATABASE_URL`` environment
        variable when ``None``.
    dimensions:
        Embedding dimension; all vectors stored in this instance must have
        exactly this many components.
    pool_min_size / pool_max_size:
        Connection pool bounds (passed to ``asyncpg.create_pool``).
    """

    def __init__(
        self,
        database_url: Optional[str] = None,
        dimensions: int = 1536,
        pool_min_size: int = 2,
        pool_max_size: int = 10,
    ) -> None:
        import os  # noqa: PLC0415

        self._database_url = database_url or os.environ.get("DATABASE_URL", "")
        self._dimensions = dimensions
        self._pool_min = pool_min_size
        self._pool_max = pool_max_size
        self._pool = None  # created in initialize()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Create the asyncpg connection pool, enable the vector extension,
        and ensure the ``embeddings`` table exists.
        """
        try:
            import asyncpg  # lazy import  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "asyncpg is required for PGVectorStore. "
                "Install it with: pip install asyncpg"
            ) from exc

        if not self._database_url:
            raise ValueError(
                "DATABASE_URL is not set. "
                "Pass database_url or set the DATABASE_URL environment variable."
            )

        self._pool = await asyncpg.create_pool(
            self._database_url,
            min_size=self._pool_min,
            max_size=self._pool_max,
        )

        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_EXTENSION)
            await conn.execute(
                _CREATE_TABLE.format(dims=self._dimensions)
            )
            await conn.execute(_CREATE_INDEX)

        logger.info(
            "PGVectorStore initialised (dims=%d, pool=%d–%d)",
            self._dimensions,
            self._pool_min,
            self._pool_max,
        )

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("PGVectorStore pool closed.")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def add_document(
        self,
        doc_id: Optional[str],
        text: str,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None,
        collection: str = "default",
    ) -> str:
        """
        Insert or replace a document with its embedding.

        Parameters
        ----------
        doc_id:
            Unique identifier.  A UUID is generated when ``None``.
        text:
            Original document text.
        embedding:
            Dense vector (must have ``self._dimensions`` components).
        metadata:
            Arbitrary JSON-serialisable metadata dict.
        collection:
            Logical namespace (default: ``"default"``).

        Returns
        -------
        str
            The ``doc_id`` that was stored.
        """
        self._ensure_pool()
        if len(embedding) != self._dimensions:
            raise ValueError(
                f"Embedding has {len(embedding)} dims; expected {self._dimensions}."
            )
        if doc_id is None:
            doc_id = str(uuid.uuid4())

        vec_str = "[" + ",".join(str(v) for v in embedding) + "]"
        meta_json = json.dumps(metadata or {})

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO embeddings (id, collection, doc_text, embedding, metadata)
                VALUES ($1, $2, $3, $4::vector, $5::jsonb)
                ON CONFLICT (id) DO UPDATE
                    SET collection = EXCLUDED.collection,
                        doc_text   = EXCLUDED.doc_text,
                        embedding  = EXCLUDED.embedding,
                        metadata   = EXCLUDED.metadata,
                        created_at = NOW()
                """,
                doc_id,
                collection,
                text,
                vec_str,
                meta_json,
            )
        logger.debug("PGVectorStore: upserted doc_id=%s collection=%s", doc_id, collection)
        return doc_id

    async def search(
        self,
        query_embedding: List[float],
        k: int = 10,
        collection: str = "default",
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        """
        Return the *k* most similar documents using cosine distance (``<=>``).

        Parameters
        ----------
        query_embedding:
            Query vector.
        k:
            Number of results to return.
        collection:
            Logical namespace to search within.
        metadata_filter:
            Optional metadata filter dict.  Simple equality checks on
            top-level metadata keys are supported (e.g. ``{"severity": "high"}``).
            Filter keys are validated to contain only alphanumeric characters and
            underscores to prevent SQL injection.
        """
        self._ensure_pool()

        if metadata_filter:
            for key in metadata_filter:
                if not re.match(r"^[a-zA-Z0-9_]+$", key):
                    raise ValueError(
                        f"Invalid metadata filter key {key!r}. "
                        "Keys must contain only alphanumeric characters and underscores."
                    )

        vec_str = "[" + ",".join(str(v) for v in query_embedding) + "]"

        # Build WHERE clause for optional metadata filters
        where_clauses = ["collection = $1"]
        params: list = [collection]
        idx = 2
        if metadata_filter:
            for key, val in metadata_filter.items():
                where_clauses.append(f"metadata->>${idx} = ${idx + 1}")
                params.append(key)
                params.append(str(val))
                idx += 2

        where_sql = " AND ".join(where_clauses)
        query_sql = f"""
            SELECT
                id,
                doc_text,
                metadata,
                collection,
                1 - (embedding <=> ${idx}::vector) AS score
            FROM embeddings
            WHERE {where_sql}
            ORDER BY embedding <=> ${idx}::vector
            LIMIT ${idx + 1}
        """
        params.extend([vec_str, k])

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query_sql, *params)

        results = []
        for row in rows:
            meta = json.loads(row["metadata"]) if isinstance(row["metadata"], str) else dict(row["metadata"])
            results.append(
                SearchResult(
                    doc_id=row["id"],
                    text=row["doc_text"],
                    score=float(row["score"]),
                    metadata=meta,
                    collection=row["collection"],
                )
            )
        return results

    async def delete_document(self, doc_id: str) -> bool:
        """
        Delete a document by ID.

        Returns
        -------
        bool
            ``True`` if a row was deleted, ``False`` if not found.
        """
        self._ensure_pool()
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM embeddings WHERE id = $1", doc_id
            )
        deleted = result.endswith("1")
        logger.debug("PGVectorStore: delete doc_id=%s deleted=%s", doc_id, deleted)
        return deleted

    # ------------------------------------------------------------------
    # Collection management
    # ------------------------------------------------------------------

    async def get_collection_stats(self, collection: str) -> Dict[str, Any]:
        """
        Return statistics for *collection*.

        Returns
        -------
        dict with keys: ``count``, ``dimensions``, ``storage_bytes``
        """
        self._ensure_pool()
        async with self._pool.acquire() as conn:
            count_row = await conn.fetchrow(
                "SELECT COUNT(*) AS cnt FROM embeddings WHERE collection = $1",
                collection,
            )
            size_row = await conn.fetchrow(
                """
                SELECT pg_total_relation_size('embeddings') AS bytes
                """,
            )
        return {
            "count": int(count_row["cnt"]),
            "dimensions": self._dimensions,
            "storage_bytes": int(size_row["bytes"]) if size_row else 0,
        }

    async def list_collections(self) -> List[str]:
        """Return a sorted list of distinct collection names."""
        self._ensure_pool()
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT DISTINCT collection FROM embeddings ORDER BY collection"
            )
        return [row["collection"] for row in rows]

    async def flush_collection(self, collection: str) -> int:
        """
        Delete all documents in *collection*.

        Returns
        -------
        int
            Number of rows deleted.
        """
        self._ensure_pool()
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM embeddings WHERE collection = $1", collection
            )
        # asyncpg returns e.g. "DELETE 42"
        try:
            count = int(result.split()[-1])
        except (IndexError, ValueError):
            count = 0
        logger.info(
            "PGVectorStore: flushed collection=%s rows=%d", collection, count
        )
        return count

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_pool(self) -> None:
        if self._pool is None:
            raise RuntimeError(
                "PGVectorStore is not initialised. "
                "Call `await store.initialize()` before using the store."
            )


__all__ = ["PGVectorStore", "SearchResult"]
