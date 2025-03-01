"""
FlowMemoryNamespace — Per-Flow Memory Isolation

Provides a namespaced memory context that binds together:
  - ``EpisodicMemoryStore`` (local, fast retrieval)
  - ``GraphitiClient`` (semantic knowledge graph)

Each pentest flow gets its own ``FlowMemoryNamespace``.  All memory
operations within a flow are automatically scoped to that flow's ID,
preventing context pollution between concurrent pentests.

Usage::

    ns = FlowMemoryNamespace(
        flow_id="flow-abc123",
        store=global_memory_store,
        graphiti=graphiti_client,
    )

    # Capture a finding
    entry = await ns.capture(
        session_id="session-001",
        agent_role="recon",
        memory_type=MemoryType.ANSWER,
        content="Target runs Apache 2.4.51 — vulnerable to CVE-2021-41773",
        cve="CVE-2021-41773",
        target_type="web",
    )

    # Search past knowledge
    results = await ns.search("path traversal Apache", memory_type=MemoryType.GUIDE)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.agent.memory.episodic_memory import (
    EpisodicMemoryStore,
    MemoryEntry,
    MemoryType,
    _FlowView,
)
from app.agent.memory.graphiti_client import (
    GraphitiClient,
    GraphitiSearchResult,
)

logger = logging.getLogger(__name__)


class FlowMemoryNamespace:
    """
    A fully isolated memory namespace for a single pentest flow.

    Bridges episodic (local) memory and the Graphiti semantic knowledge graph.
    All writes go to both stores; reads query both and merge results.
    """

    def __init__(
        self,
        flow_id: str,
        store: EpisodicMemoryStore,
        graphiti: Optional[GraphitiClient] = None,
        auto_sync_graphiti: bool = True,
    ) -> None:
        """
        Initialise the namespace.

        Args:
            flow_id             – Unique identifier for this pentest flow.
            store               – Shared EpisodicMemoryStore instance.
            graphiti            – Optional GraphitiClient for knowledge graph.
            auto_sync_graphiti  – If True, every ``capture()`` call also
                                  pushes the entry to Graphiti asynchronously.
        """
        self.flow_id = flow_id
        self._store = store
        self._graphiti = graphiti
        self._auto_sync = auto_sync_graphiti
        self._view: _FlowView = store.for_flow(flow_id)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def capture(
        self,
        session_id: str,
        agent_role: str,
        memory_type: MemoryType,
        content: str,
        target_type: str = "web",
        cve: Optional[str] = None,
        technique: Optional[str] = None,
        tool_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        score: float = 1.0,
    ) -> MemoryEntry:
        """
        Persist a memory entry in the local store and (optionally) Graphiti.

        Returns the stored ``MemoryEntry``.
        """
        entry = MemoryEntry(
            flow_id=self.flow_id,
            session_id=session_id,
            agent_role=agent_role,
            memory_type=memory_type,
            content=content,
            target_type=target_type,
            cve=cve,
            technique=technique,
            tool_name=tool_name,
            tags=tags or [],
            score=score,
        )
        self._store.capture(entry)

        if self._auto_sync and self._graphiti is not None:
            try:
                await self._graphiti.ingest_agent_output(
                    content=content,
                    agent_role=agent_role,
                    memory_type=memory_type,
                    flow_id=self.flow_id,
                    session_id=session_id,
                    cve=cve,
                    technique=technique,
                    tool_name=tool_name,
                    tags=tags,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Graphiti sync failed (non-fatal): %s", exc)

        return entry

    # ------------------------------------------------------------------
    # Read — local
    # ------------------------------------------------------------------

    def query_local(
        self,
        *,
        target_type: Optional[str] = None,
        cve: Optional[str] = None,
        technique: Optional[str] = None,
        tool_name: Optional[str] = None,
        memory_type: Optional[MemoryType] = None,
        agent_role: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_score: float = 0.0,
        limit: int = 50,
    ) -> List[MemoryEntry]:
        """Query the local episodic store for this flow."""
        return self._store.query(
            self.flow_id,
            target_type=target_type,
            cve=cve,
            technique=technique,
            tool_name=tool_name,
            memory_type=memory_type,
            agent_role=agent_role,
            tags=tags,
            min_score=min_score,
            limit=limit,
        )

    def recent(
        self,
        n: int = 10,
        memory_type: Optional[MemoryType] = None,
    ) -> List[MemoryEntry]:
        """Return the *n* most recent local entries for this flow."""
        return self._store.recent(self.flow_id, n=n, memory_type=memory_type)

    # ------------------------------------------------------------------
    # Read — Graphiti semantic search
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        limit: int = 10,
    ) -> List[GraphitiSearchResult]:
        """
        Perform a semantic search over the Graphiti knowledge graph.

        Falls back to an empty list when Graphiti is not configured.
        """
        if self._graphiti is None:
            logger.debug("Graphiti not configured — skipping semantic search")
            return []

        return await self._graphiti.search(
            query=query,
            memory_type=memory_type,
            limit=limit,
            flow_id=self.flow_id,
        )

    # ------------------------------------------------------------------
    # Hybrid search — merge local + Graphiti
    # ------------------------------------------------------------------

    async def hybrid_search(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        local_limit: int = 20,
        graphiti_limit: int = 10,
    ) -> Dict[str, Any]:
        """
        Return a combined result set from both local episodic memory and Graphiti.

        Useful for agents that need maximum context before planning.
        """
        local_results = self.query_local(memory_type=memory_type, limit=local_limit)
        graphiti_results = await self.search(
            query=query,
            memory_type=memory_type,
            limit=graphiti_limit,
        )
        return {
            "local": [e.to_dict() for e in local_results],
            "graphiti": [
                {
                    "node_id": r.node_id,
                    "name": r.name,
                    "score": r.score,
                    "memory_type": r.memory_type,
                }
                for r in graphiti_results
            ],
        }

    # ------------------------------------------------------------------
    # Stats & lifecycle
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return memory statistics for this flow."""
        return self._view.stats()

    def clear(self) -> int:
        """Remove all local entries for this flow. Returns count removed."""
        count = self._store.clear_flow(self.flow_id)
        logger.info("Cleared %d memory entries for flow %s", count, self.flow_id)
        return count
