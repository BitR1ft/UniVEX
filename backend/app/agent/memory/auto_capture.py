"""
AutoCaptureMiddleware — Automatic Agent Output Ingestion into Vector Store

Middleware that automatically ingests agent tool outputs and agent responses
into the configured vector store. Activated by AUTO_CAPTURE=true env var.
Tags each entry by flow_id, agent_role, and memory_type.

Usage:
    middleware = AutoCaptureMiddleware(registry=embedding_registry)
    await middleware.capture_response(
        flow_id="flow-123",
        agent_role="recon",
        memory_type=MemoryType.ANSWER,
        content="Found open ports: 80, 443",
        session_id="session-456",
        tags=["port_scan", "nmap"],
    )
"""

from __future__ import annotations

import logging
import os
import time
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.agent.memory.episodic_memory import MemoryType

logger = logging.getLogger(__name__)


@dataclass
class CaptureEntry:
    """A single auto-captured agent output record stored in the vector store."""

    entry_id: str
    flow_id: str
    session_id: str
    agent_role: str
    memory_type: MemoryType
    content: str
    tags: List[str]
    metadata: Dict[str, Any]
    timestamp: float
    collection: str


class AutoCaptureMiddleware:
    """
    Middleware that automatically ingests agent responses and tool outputs
    into the configured vector store.

    Parameters
    ----------
    registry:
        :class:`~app.embeddings.embedding_registry.EmbeddingRegistry` instance.
        When ``None``, the global singleton is used lazily.
    enabled:
        Explicit override for the ``AUTO_CAPTURE`` env var.  Defaults to
        ``os.environ.get("AUTO_CAPTURE", "false").lower() == "true"``.
    collection_prefix:
        Prefix for vector store collection names (default: ``"univex"``).
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        enabled: Optional[bool] = None,
        collection_prefix: str = "univex",
    ) -> None:
        if enabled is None:
            enabled = os.environ.get("AUTO_CAPTURE", "false").lower() == "true"
        self._enabled: bool = enabled
        self._registry = registry  # resolved lazily
        self._collection_prefix = collection_prefix

        # Thread-safe counters
        self._lock = threading.Lock()
        self._total_captures: int = 0
        self._captures_by_agent: Dict[str, int] = {}
        self._captures_by_type: Dict[str, int] = {}

        # In-memory index of stored entries for search support
        self._entries: List[CaptureEntry] = []

    # ------------------------------------------------------------------
    # Enable / disable
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """Enable automatic capture."""
        self._enabled = True
        logger.debug("AutoCaptureMiddleware enabled.")

    def disable(self) -> None:
        """Disable automatic capture (becomes a no-op)."""
        self._enabled = False
        logger.debug("AutoCaptureMiddleware disabled.")

    # ------------------------------------------------------------------
    # Core capture helpers
    # ------------------------------------------------------------------

    async def capture_response(
        self,
        flow_id: str,
        agent_role: str,
        memory_type: MemoryType,
        content: str,
        session_id: str = "default",
        tags: Optional[List[str]] = None,
        **metadata: Any,
    ) -> Optional[CaptureEntry]:
        """
        Embed *content* and store it in the vector store.

        Returns the :class:`CaptureEntry` on success, ``None`` when disabled
        or if an error occurs (errors are logged, never raised).
        """
        if not self._enabled:
            return None

        tags = tags or []

        try:
            registry = self._get_registry()
            collection = self._collection_name(memory_type)

            embeddings = registry.embed_with_fallback([content])
            embedding = embeddings[0] if embeddings else []

            entry_id = str(uuid.uuid4())
            entry_meta: Dict[str, Any] = {
                "flow_id": flow_id,
                "session_id": session_id,
                "agent_role": agent_role,
                "memory_type": memory_type.value,
                "tags": tags,
                **metadata,
            }

            # Attempt to persist to vector store
            await self._store_embedding(
                entry_id=entry_id,
                content=content,
                embedding=embedding,
                metadata=entry_meta,
                collection=collection,
            )

            entry = CaptureEntry(
                entry_id=entry_id,
                flow_id=flow_id,
                session_id=session_id,
                agent_role=agent_role,
                memory_type=memory_type,
                content=content,
                tags=tags,
                metadata=metadata,
                timestamp=time.time(),
                collection=collection,
            )

            with self._lock:
                self._total_captures += 1
                self._captures_by_agent[agent_role] = (
                    self._captures_by_agent.get(agent_role, 0) + 1
                )
                self._captures_by_type[memory_type.value] = (
                    self._captures_by_type.get(memory_type.value, 0) + 1
                )
                self._entries.append(entry)

            logger.debug(
                "AutoCapture: stored entry_id=%s agent=%s type=%s",
                entry_id,
                agent_role,
                memory_type.value,
            )
            return entry

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "AutoCaptureMiddleware.capture_response failed (agent=%s): %s",
                agent_role,
                exc,
            )
            return None

    async def capture_tool_output(
        self,
        flow_id: str,
        agent_role: str,
        tool_name: str,
        output: str,
        session_id: str = "default",
    ) -> Optional[CaptureEntry]:
        """
        Capture the output of a specific tool invocation.

        Wraps :meth:`capture_response` with ``memory_type=MemoryType.ANSWER``
        and adds ``tool_name`` to the tags.
        """
        return await self.capture_response(
            flow_id=flow_id,
            agent_role=agent_role,
            memory_type=MemoryType.ANSWER,
            content=output,
            session_id=session_id,
            tags=[tool_name],
            tool_name=tool_name,
        )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    async def search_captures(
        self,
        query: str,
        flow_id: Optional[str] = None,
        agent_role: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        k: int = 10,
    ) -> List[CaptureEntry]:
        """
        Semantic search through captured entries.

        Attempts a vector-store search first; falls back to a simple
        in-memory content scan when the vector store is unavailable.
        """
        if not self._enabled:
            return []

        try:
            registry = self._get_registry()
            embeddings = registry.embed_with_fallback([query])
            query_embedding = embeddings[0] if embeddings else []

            collection = (
                self._collection_name(memory_type)
                if memory_type is not None
                else f"{self._collection_prefix}_default"
            )

            metadata_filter: Dict[str, str] = {}
            if flow_id is not None:
                metadata_filter["flow_id"] = flow_id
            if agent_role is not None:
                metadata_filter["agent_role"] = agent_role

            store = self._get_vector_store()
            if store is not None and query_embedding:
                results = await store.search(
                    query_embedding=query_embedding,
                    k=k,
                    collection=collection,
                    metadata_filter=metadata_filter or None,
                )
                matched: List[CaptureEntry] = []
                for r in results:
                    matched.append(
                        CaptureEntry(
                            entry_id=r.doc_id,
                            flow_id=r.metadata.get("flow_id", ""),
                            session_id=r.metadata.get("session_id", "default"),
                            agent_role=r.metadata.get("agent_role", ""),
                            memory_type=MemoryType(
                                r.metadata.get("memory_type", MemoryType.ANSWER.value)
                            ),
                            content=r.text,
                            tags=r.metadata.get("tags", []),
                            metadata={
                                k: v
                                for k, v in r.metadata.items()
                                if k
                                not in {
                                    "flow_id",
                                    "session_id",
                                    "agent_role",
                                    "memory_type",
                                    "tags",
                                }
                            },
                            timestamp=0.0,
                            collection=r.collection,
                        )
                    )
                return matched

        except Exception as exc:  # noqa: BLE001
            logger.warning("AutoCaptureMiddleware.search_captures vector search failed: %s", exc)

        # Fallback: in-memory linear scan
        candidates = list(self._entries)
        if flow_id is not None:
            candidates = [e for e in candidates if e.flow_id == flow_id]
        if agent_role is not None:
            candidates = [e for e in candidates if e.agent_role == agent_role]
        if memory_type is not None:
            candidates = [e for e in candidates if e.memory_type == memory_type]
        query_lower = query.lower()
        scored = [(e, query_lower in e.content.lower()) for e in candidates]
        matched_entries = [e for e, hit in scored if hit]
        return matched_entries[:k]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """
        Return capture statistics.

        Returns
        -------
        dict with keys: ``total_captures``, ``captures_by_agent``,
        ``captures_by_type``, ``enabled``
        """
        with self._lock:
            return {
                "total_captures": self._total_captures,
                "captures_by_agent": dict(self._captures_by_agent),
                "captures_by_type": dict(self._captures_by_type),
                "enabled": self._enabled,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_registry(self) -> Any:
        if self._registry is not None:
            return self._registry
        from app.embeddings.embedding_registry import get_registry  # noqa: PLC0415
        return get_registry()

    def _get_vector_store(self) -> Optional[Any]:
        """Return a PGVectorStore if DATABASE_URL is configured, else None."""
        db_url = os.environ.get("DATABASE_URL", "")
        if not db_url:
            return None
        try:
            from app.embeddings.pgvector_store import PGVectorStore  # noqa: PLC0415
            registry = self._get_registry()
            info = registry.get_provider_info()
            dims = info.get("dimensions", 1536) or 1536
            return PGVectorStore(database_url=db_url, dimensions=dims)
        except Exception as exc:  # noqa: BLE001
            logger.debug("PGVectorStore unavailable: %s", exc)
            return None

    async def _store_embedding(
        self,
        entry_id: str,
        content: str,
        embedding: List[float],
        metadata: Dict[str, Any],
        collection: str,
    ) -> None:
        """Persist to vector store; silently skip when unavailable."""
        store = self._get_vector_store()
        if store is None or not embedding:
            logger.debug(
                "AutoCapture: vector store unavailable, skipping persistent storage."
            )
            return
        try:
            await store.initialize()
            await store.add_document(
                doc_id=entry_id,
                text=content,
                embedding=embedding,
                metadata=metadata,
                collection=collection,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("AutoCapture: failed to persist to vector store: %s", exc)
        finally:
            await store.close()

    def _collection_name(self, memory_type: Optional[MemoryType]) -> str:
        if memory_type is None:
            return f"{self._collection_prefix}_default"
        return f"{self._collection_prefix}_{memory_type.value}"


__all__ = ["AutoCaptureMiddleware", "CaptureEntry"]
