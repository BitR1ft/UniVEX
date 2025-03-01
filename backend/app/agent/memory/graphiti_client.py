"""
GraphitiClient — Semantic Knowledge Graph Integration

Connects to the Graphiti REST API service (port 8010) that wraps Neo4j with
semantic relationship extraction.  Agent outputs are automatically ingested
into the knowledge graph, enabling:
  - Semantic search over past pentest knowledge
  - Relationship extraction between entities (CVEs, techniques, targets)
  - Memory type filtering (answer | memory | guide | code)
  - Cross-session knowledge retrieval

Graphiti API reference:
  POST /nodes          — Create a node
  POST /relations      — Create a relation between nodes
  POST /search         — Semantic search
  GET  /nodes/{id}     — Retrieve a node
  DELETE /nodes/{id}   — Delete a node
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from app.agent.memory.episodic_memory import MemoryType

logger = logging.getLogger(__name__)

# Default Graphiti service base URL (overridable via env var)
_DEFAULT_BASE_URL = "http://graphiti:8010"

# Request timeout (seconds)
_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class GraphitiNode:
    """
    A node in the Graphiti knowledge graph.

    Attributes:
        node_id    – Unique identifier (returned by the API).
        label      – Node type label, e.g. "CVE", "Technique", "Target".
        name       – Human-readable name.
        properties – Arbitrary key/value metadata.
    """
    label: str
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    node_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "name": self.name,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphitiNode":
        return cls(
            label=data.get("label", "Unknown"),
            name=data.get("name", ""),
            properties=data.get("properties", {}),
            node_id=data.get("node_id") or data.get("id"),
        )


@dataclass
class GraphitiRelation:
    """
    A directed relation between two nodes in the knowledge graph.

    Attributes:
        from_node_id  – Source node identifier.
        to_node_id    – Target node identifier.
        relation_type – Relation label, e.g. "EXPLOITS", "USES", "RELATES_TO".
        properties    – Arbitrary key/value metadata.
        relation_id   – Unique identifier (returned by the API).
    """
    from_node_id: str
    to_node_id: str
    relation_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    relation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "relation_type": self.relation_type,
            "properties": self.properties,
        }


@dataclass
class GraphitiSearchResult:
    """A single search result from the Graphiti API."""
    node_id: str
    label: str
    name: str
    score: float
    properties: Dict[str, Any] = field(default_factory=dict)
    memory_type: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphitiSearchResult":
        return cls(
            node_id=data.get("node_id") or data.get("id", ""),
            label=data.get("label", ""),
            name=data.get("name", ""),
            score=float(data.get("score", 0.0)),
            properties=data.get("properties", {}),
            memory_type=data.get("memory_type"),
        )


# ---------------------------------------------------------------------------
# GraphitiClient
# ---------------------------------------------------------------------------


class GraphitiClient:
    """
    REST client for the Graphiti knowledge graph service.

    Usage::

        client = GraphitiClient(base_url="http://graphiti:8010")
        node = await client.create_node(GraphitiNode(label="CVE", name="CVE-2024-1234"))
        results = await client.search("RCE via Log4Shell", memory_type=MemoryType.GUIDE)

    When the Graphiti service is unavailable, all methods degrade gracefully —
    they log a warning and return empty / ``None`` results.  This ensures agent
    pipelines continue even when the knowledge graph is offline.
    """

    def __init__(
        self,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _TIMEOUT,
        api_key: Optional[str] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        # Lazily initialised async client (re-entrant safe)
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=self._headers,
                timeout=self._timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _post(self, path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            client = self._get_client()
            resp = await client.post(path, json=payload)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("Graphiti API error %s: %s", exc.response.status_code, path)
            return None
        except httpx.RequestError as exc:
            logger.warning("Graphiti unavailable (%s) — degrading gracefully", exc)
            return None

    async def _get(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            client = self._get_client()
            resp = await client.get(path)
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("Graphiti GET failed: %s", exc)
            return None

    async def _delete(self, path: str) -> bool:
        try:
            client = self._get_client()
            resp = await client.delete(path)
            return resp.is_success
        except (httpx.HTTPStatusError, httpx.RequestError) as exc:
            logger.warning("Graphiti DELETE failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    async def create_node(self, node: GraphitiNode) -> Optional[GraphitiNode]:
        """Create a node in the knowledge graph. Returns the node with its ID."""
        result = await self._post("/nodes", node.to_dict())
        if result:
            node.node_id = result.get("node_id") or result.get("id")
            logger.debug("Graphiti node created: %s/%s", node.label, node.name)
        return node if result else None

    async def get_node(self, node_id: str) -> Optional[GraphitiNode]:
        """Retrieve a node by its ID."""
        result = await self._get(f"/nodes/{node_id}")
        return GraphitiNode.from_dict(result) if result else None

    async def delete_node(self, node_id: str) -> bool:
        """Delete a node and all its relations."""
        return await self._delete(f"/nodes/{node_id}")

    # ------------------------------------------------------------------
    # Relations
    # ------------------------------------------------------------------

    async def create_relation(self, relation: GraphitiRelation) -> Optional[GraphitiRelation]:
        """Create a directed relation between two existing nodes."""
        result = await self._post("/relations", relation.to_dict())
        if result:
            relation.relation_id = result.get("relation_id") or result.get("id")
        return relation if result else None

    # ------------------------------------------------------------------
    # Semantic search
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        limit: int = 10,
        flow_id: Optional[str] = None,
    ) -> List[GraphitiSearchResult]:
        """
        Perform a semantic similarity search over the knowledge graph.

        Args:
            query       – Natural language search query.
            memory_type – Optional filter: answer | memory | guide | code.
            limit       – Maximum number of results to return.
            flow_id     – Optional filter to restrict search to a specific flow.

        Returns:
            List of ``GraphitiSearchResult`` objects sorted by relevance.
        """
        payload: Dict[str, Any] = {
            "query": query,
            "limit": limit,
        }
        if memory_type is not None:
            payload["memory_type"] = memory_type.value
        if flow_id is not None:
            payload["flow_id"] = flow_id

        result = await self._post("/search", payload)
        if not result:
            return []

        raw_results = result.get("results") or result.get("nodes") or []
        return [GraphitiSearchResult.from_dict(r) for r in raw_results]

    # ------------------------------------------------------------------
    # High-level ingestion helper
    # ------------------------------------------------------------------

    async def ingest_agent_output(
        self,
        content: str,
        agent_role: str,
        memory_type: MemoryType,
        flow_id: str,
        session_id: str,
        cve: Optional[str] = None,
        technique: Optional[str] = None,
        tool_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Optional[GraphitiNode]:
        """
        Convenience method: create a ``Finding`` node from an agent output.

        Automatically sets all required metadata and returns the created node.
        """
        properties: Dict[str, Any] = {
            "agent_role": agent_role,
            "memory_type": memory_type.value,
            "flow_id": flow_id,
            "session_id": session_id,
            "content": content[:4096],  # Truncate to stay within API limits
        }
        if cve:
            properties["cve"] = cve
        if technique:
            properties["technique"] = technique
        if tool_name:
            properties["tool_name"] = tool_name
        if tags:
            properties["tags"] = tags

        node = GraphitiNode(
            label="Finding",
            name=f"{agent_role}:{memory_type.value}:{session_id}",
            properties=properties,
        )
        return await self.create_node(node)

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "GraphitiClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
