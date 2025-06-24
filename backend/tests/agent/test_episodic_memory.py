"""
Tests for Day 1 — Episodic Memory & Graphiti Knowledge Graph.

Coverage:
  - EpisodicMemoryStore: capture, query, deduplication, eviction, export/import
  - MemoryType enum values
  - _FlowView proxy scoping
  - GraphitiClient: node CRUD, semantic search, graceful degradation
  - GraphitiSearchResult parsing
  - FlowMemoryNamespace: capture, local query, hybrid search, stats, clear
  - BaseAgent: auto_capture, memory_ns integration, query_past_knowledge
  - MemoryEntry: to_dict/from_dict, deterministic entry_id
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

# ---------------------------------------------------------------------------
# Episodic Memory
# ---------------------------------------------------------------------------
from app.agent.memory.episodic_memory import (
    EpisodicMemoryStore,
    MemoryEntry,
    MemoryType,
    _FlowView,
)


# ===========================================================================
# MemoryType
# ===========================================================================

class TestMemoryType:
    """Tests for MemoryType enum."""

    def test_all_types_exist(self):
        assert MemoryType.ANSWER == "answer"
        assert MemoryType.MEMORY == "memory"
        assert MemoryType.GUIDE == "guide"
        assert MemoryType.CODE == "code"

    def test_all_four_values(self):
        values = {mt.value for mt in MemoryType}
        assert values == {"answer", "memory", "guide", "code"}

    def test_from_string(self):
        assert MemoryType("answer") is MemoryType.ANSWER
        assert MemoryType("code") is MemoryType.CODE


# ===========================================================================
# MemoryEntry
# ===========================================================================

class TestMemoryEntry:
    """Tests for the MemoryEntry dataclass."""

    def _make_entry(self, content: str = "test content", **kwargs) -> MemoryEntry:
        return MemoryEntry(
            flow_id="flow-001",
            session_id="session-001",
            agent_role="recon",
            memory_type=MemoryType.ANSWER,
            content=content,
            **kwargs,
        )

    def test_deterministic_entry_id(self):
        e1 = self._make_entry("same content")
        e2 = self._make_entry("same content")
        assert e1.entry_id == e2.entry_id

    def test_different_content_different_id(self):
        e1 = self._make_entry("content A")
        e2 = self._make_entry("content B")
        assert e1.entry_id != e2.entry_id

    def test_entry_id_length(self):
        entry = self._make_entry()
        assert len(entry.entry_id) == 16

    def test_to_dict_round_trip(self):
        entry = self._make_entry(
            cve="CVE-2024-1234",
            technique="T1190",
            tool_name="nmap",
            tags=["critical"],
            score=0.95,
        )
        d = entry.to_dict()
        assert d["flow_id"] == "flow-001"
        assert d["cve"] == "CVE-2024-1234"
        assert d["memory_type"] == "answer"
        assert d["tags"] == ["critical"]
        assert d["score"] == 0.95

    def test_from_dict_round_trip(self):
        entry = self._make_entry(cve="CVE-2024-5678", score=0.7)
        d = entry.to_dict()
        restored = MemoryEntry.from_dict(d)
        assert restored.flow_id == entry.flow_id
        assert restored.content == entry.content
        assert restored.cve == "CVE-2024-5678"
        assert restored.memory_type is MemoryType.ANSWER
        assert restored.score == pytest.approx(0.7)

    def test_default_fields(self):
        entry = self._make_entry()
        assert entry.target_type == "web"
        assert entry.cve is None
        assert entry.technique is None
        assert entry.tool_name is None
        assert entry.tags == []
        assert entry.score == 1.0

    def test_created_at_is_recent(self):
        before = time.time()
        entry = self._make_entry()
        after = time.time()
        assert before <= entry.created_at <= after


# ===========================================================================
# EpisodicMemoryStore
# ===========================================================================

class TestEpisodicMemoryStore:
    """Comprehensive tests for EpisodicMemoryStore."""

    def _make_store(self, max_entries: int = 100) -> EpisodicMemoryStore:
        return EpisodicMemoryStore(max_entries_per_flow=max_entries)

    def _make_entry(
        self,
        flow_id: str = "flow-001",
        session_id: str = "session-001",
        content: str = "test",
        memory_type: MemoryType = MemoryType.ANSWER,
        **kwargs,
    ) -> MemoryEntry:
        return MemoryEntry(
            flow_id=flow_id,
            session_id=session_id,
            agent_role="recon",
            memory_type=memory_type,
            content=content,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Basic capture
    # ------------------------------------------------------------------

    def test_capture_returns_entry(self):
        store = self._make_store()
        entry = self._make_entry()
        result = store.capture(entry)
        assert result.entry_id == entry.entry_id

    def test_captured_entry_retrievable(self):
        store = self._make_store()
        entry = self._make_entry(content="retrievable content")
        store.capture(entry)
        results = store.query("flow-001")
        assert any(e.content == "retrievable content" for e in results)

    def test_capture_deduplication(self):
        store = self._make_store()
        entry = self._make_entry(content="unique content")
        store.capture(entry)
        store.capture(entry)  # duplicate
        results = store.query("flow-001")
        assert len(results) == 1

    def test_capture_many(self):
        store = self._make_store()
        entries = [self._make_entry(content=f"entry {i}") for i in range(5)]
        results = store.capture_many(entries)
        assert len(results) == 5
        assert len(store.query("flow-001")) == 5

    # ------------------------------------------------------------------
    # Eviction
    # ------------------------------------------------------------------

    def test_eviction_when_full(self):
        store = self._make_store(max_entries=3)
        for i in range(5):
            entry = self._make_entry(content=f"content {i}")
            time.sleep(0.001)  # Ensure different timestamps
            store.capture(entry)
        results = store.query("flow-001")
        assert len(results) == 3

    def test_eviction_removes_oldest(self):
        store = self._make_store(max_entries=2)
        e1 = self._make_entry(content="oldest")
        time.sleep(0.001)
        e2 = self._make_entry(content="middle")
        time.sleep(0.001)
        e3 = self._make_entry(content="newest")
        store.capture(e1)
        store.capture(e2)
        store.capture(e3)
        results = store.query("flow-001")
        contents = {e.content for e in results}
        assert "oldest" not in contents

    # ------------------------------------------------------------------
    # Query filtering
    # ------------------------------------------------------------------

    def test_query_by_memory_type(self):
        store = self._make_store()
        store.capture(self._make_entry(content="answer entry", memory_type=MemoryType.ANSWER))
        store.capture(self._make_entry(content="guide entry", memory_type=MemoryType.GUIDE))
        results = store.query("flow-001", memory_type=MemoryType.ANSWER)
        assert all(e.memory_type is MemoryType.ANSWER for e in results)
        assert len(results) == 1

    def test_query_by_cve(self):
        store = self._make_store()
        store.capture(self._make_entry(content="CVE entry", cve="CVE-2024-1234"))
        store.capture(self._make_entry(content="no CVE"))
        results = store.query("flow-001", cve="CVE-2024-1234")
        assert len(results) == 1
        assert results[0].cve == "CVE-2024-1234"

    def test_query_by_technique(self):
        store = self._make_store()
        store.capture(self._make_entry(content="technique entry", technique="T1190"))
        store.capture(self._make_entry(content="no technique"))
        results = store.query("flow-001", technique="T1190")
        assert len(results) == 1

    def test_query_by_tool_name(self):
        store = self._make_store()
        store.capture(self._make_entry(content="nmap entry", tool_name="nmap"))
        store.capture(self._make_entry(content="other tool", tool_name="nikto"))
        results = store.query("flow-001", tool_name="nmap")
        assert len(results) == 1

    def test_query_by_target_type(self):
        store = self._make_store()
        store.capture(self._make_entry(content="web", target_type="web"))
        store.capture(self._make_entry(content="api", target_type="api"))
        results = store.query("flow-001", target_type="web")
        assert len(results) == 1
        assert results[0].content == "web"

    def test_query_by_agent_role(self):
        store = self._make_store()
        e1 = MemoryEntry(flow_id="flow-001", session_id="s1", agent_role="recon",
                         memory_type=MemoryType.ANSWER, content="recon result")
        e2 = MemoryEntry(flow_id="flow-001", session_id="s1", agent_role="exploit",
                         memory_type=MemoryType.ANSWER, content="exploit result")
        store.capture(e1)
        store.capture(e2)
        results = store.query("flow-001", agent_role="recon")
        assert len(results) == 1
        assert results[0].agent_role == "recon"

    def test_query_by_tags(self):
        store = self._make_store()
        store.capture(self._make_entry(content="tagged", tags=["critical", "web"]))
        store.capture(self._make_entry(content="untagged"))
        results = store.query("flow-001", tags=["critical"])
        assert len(results) == 1

    def test_query_by_min_score(self):
        store = self._make_store()
        store.capture(self._make_entry(content="high score", score=0.9))
        store.capture(self._make_entry(content="low score", score=0.3))
        results = store.query("flow-001", min_score=0.5)
        assert len(results) == 1
        assert results[0].score == pytest.approx(0.9)

    def test_query_limit(self):
        store = self._make_store()
        for i in range(10):
            store.capture(self._make_entry(content=f"entry {i}"))
        results = store.query("flow-001", limit=5)
        assert len(results) == 5

    def test_query_sorted_by_score_desc(self):
        store = self._make_store()
        for score in [0.3, 0.9, 0.6]:
            store.capture(self._make_entry(content=f"score {score}", score=score))
        results = store.query("flow-001")
        scores = [e.score for e in results]
        assert scores == sorted(scores, reverse=True)

    def test_query_cross_flow_when_no_flow_id(self):
        store = self._make_store()
        store.capture(self._make_entry(flow_id="flow-A", content="from flow A"))
        store.capture(self._make_entry(flow_id="flow-B", content="from flow B"))
        results = store.query(flow_id=None)
        assert len(results) == 2

    # ------------------------------------------------------------------
    # Namespace isolation
    # ------------------------------------------------------------------

    def test_flow_namespace_isolation(self):
        store = self._make_store()
        store.capture(self._make_entry(flow_id="flow-A", content="A data"))
        store.capture(self._make_entry(flow_id="flow-B", content="B data"))
        results_a = store.query("flow-A")
        results_b = store.query("flow-B")
        assert len(results_a) == 1
        assert results_a[0].content == "A data"
        assert len(results_b) == 1
        assert results_b[0].content == "B data"

    # ------------------------------------------------------------------
    # Recent
    # ------------------------------------------------------------------

    def test_recent_returns_n_newest(self):
        store = self._make_store()
        for i in range(5):
            store.capture(self._make_entry(content=f"entry {i}"))
            time.sleep(0.001)
        recent = store.recent("flow-001", n=3)
        assert len(recent) == 3

    def test_recent_filtered_by_type(self):
        store = self._make_store()
        store.capture(self._make_entry(content="answer", memory_type=MemoryType.ANSWER))
        store.capture(self._make_entry(content="guide", memory_type=MemoryType.GUIDE))
        recent = store.recent("flow-001", memory_type=MemoryType.ANSWER)
        assert all(e.memory_type is MemoryType.ANSWER for e in recent)

    # ------------------------------------------------------------------
    # Get by ID
    # ------------------------------------------------------------------

    def test_get_existing_entry(self):
        store = self._make_store()
        entry = self._make_entry(content="findable")
        store.capture(entry)
        found = store.get(entry.entry_id, "flow-001")
        assert found is not None
        assert found.content == "findable"

    def test_get_nonexistent_returns_none(self):
        store = self._make_store()
        assert store.get("nonexistent-id", "flow-001") is None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def test_stats_empty_store(self):
        store = self._make_store()
        stats = store.stats()
        assert stats["total_entries"] == 0
        assert stats["flow_count"] == 0

    def test_stats_with_entries(self):
        store = self._make_store()
        store.capture(self._make_entry(content="a", memory_type=MemoryType.ANSWER))
        store.capture(self._make_entry(content="b", memory_type=MemoryType.GUIDE))
        stats = store.stats()
        assert stats["total_entries"] == 2
        assert stats["by_type"]["answer"] == 1
        assert stats["by_type"]["guide"] == 1

    # ------------------------------------------------------------------
    # Export / Import
    # ------------------------------------------------------------------

    def test_export_produces_dicts(self):
        store = self._make_store()
        entry = self._make_entry(content="exportable")
        store.capture(entry)
        exported = store.export("flow-001")
        assert len(exported) == 1
        assert isinstance(exported[0], dict)
        assert exported[0]["content"] == "exportable"

    def test_import_round_trip(self):
        store = self._make_store()
        entry = self._make_entry(content="round trip")
        store.capture(entry)
        exported = store.export("flow-001")

        store2 = self._make_store()
        count = store2.import_entries(exported)
        assert count == 1
        results = store2.query("flow-001")
        assert results[0].content == "round trip"

    def test_export_all_flows(self):
        store = self._make_store()
        store.capture(self._make_entry(flow_id="flow-A", content="A"))
        store.capture(self._make_entry(flow_id="flow-B", content="B"))
        exported = store.export()
        assert len(exported) == 2

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def test_clear_flow(self):
        store = self._make_store()
        store.capture(self._make_entry(content="to be cleared"))
        removed = store.clear_flow("flow-001")
        assert removed == 1
        assert store.query("flow-001") == []

    def test_clear_all(self):
        store = self._make_store()
        store.capture(self._make_entry(flow_id="A", content="a"))
        store.capture(self._make_entry(flow_id="B", content="b"))
        store.clear_all()
        assert store.stats()["total_entries"] == 0


# ===========================================================================
# _FlowView
# ===========================================================================

class TestFlowView:
    """Tests for _FlowView proxy."""

    def test_capture_scoped_to_flow(self):
        store = EpisodicMemoryStore()
        view = store.for_flow("flow-xyz")
        view.capture(
            session_id="s1",
            agent_role="recon",
            memory_type=MemoryType.ANSWER,
            content="flow-scoped content",
        )
        results = view.query()
        assert len(results) == 1
        assert results[0].flow_id == "flow-xyz"

    def test_query_does_not_return_other_flows(self):
        store = EpisodicMemoryStore()
        view_a = store.for_flow("flow-A")
        view_b = store.for_flow("flow-B")
        view_a.capture(session_id="s", agent_role="r", memory_type=MemoryType.ANSWER, content="A")
        view_b.capture(session_id="s", agent_role="r", memory_type=MemoryType.ANSWER, content="B")
        results_a = view_a.query()
        assert all(e.flow_id == "flow-A" for e in results_a)

    def test_stats_scoped_to_flow(self):
        store = EpisodicMemoryStore()
        view = store.for_flow("flow-stats")
        view.capture(session_id="s", agent_role="r", memory_type=MemoryType.ANSWER, content="c1")
        view.capture(session_id="s", agent_role="r", memory_type=MemoryType.GUIDE, content="c2")
        stats = view.stats()
        assert stats["total_entries"] == 2
        assert stats["flow_id"] == "flow-stats"

    def test_clear_scoped_to_flow(self):
        store = EpisodicMemoryStore()
        view_a = store.for_flow("flow-A")
        view_b = store.for_flow("flow-B")
        view_a.capture(session_id="s", agent_role="r", memory_type=MemoryType.ANSWER, content="A")
        view_b.capture(session_id="s", agent_role="r", memory_type=MemoryType.ANSWER, content="B")
        view_a.clear()
        # flow-A cleared, flow-B intact
        assert view_a.query() == []
        assert len(view_b.query()) == 1

    def test_recent_through_view(self):
        store = EpisodicMemoryStore()
        view = store.for_flow("flow-recent")
        for i in range(5):
            view.capture(session_id="s", agent_role="r",
                         memory_type=MemoryType.MEMORY, content=f"entry {i}")
        recent = view.recent(n=3)
        assert len(recent) == 3


# ===========================================================================
# GraphitiClient
# ===========================================================================

from app.agent.memory.graphiti_client import (
    GraphitiClient,
    GraphitiNode,
    GraphitiRelation,
    GraphitiSearchResult,
)


class TestGraphitiNode:
    def test_to_dict(self):
        node = GraphitiNode(label="CVE", name="CVE-2024-1234", node_id="abc")
        d = node.to_dict()
        assert d["label"] == "CVE"
        assert d["name"] == "CVE-2024-1234"
        assert d["node_id"] == "abc"

    def test_from_dict(self):
        data = {"label": "Technique", "name": "T1190", "properties": {"platform": "web"}}
        node = GraphitiNode.from_dict(data)
        assert node.label == "Technique"
        assert node.name == "T1190"
        assert node.properties == {"platform": "web"}
        assert node.node_id is None

    def test_from_dict_with_id(self):
        data = {"label": "CVE", "name": "CVE-2024-5678", "id": "node-123"}
        node = GraphitiNode.from_dict(data)
        assert node.node_id == "node-123"


class TestGraphitiSearchResult:
    def test_from_dict(self):
        data = {"node_id": "n1", "label": "Finding", "name": "SQLi", "score": 0.95}
        result = GraphitiSearchResult.from_dict(data)
        assert result.node_id == "n1"
        assert result.score == pytest.approx(0.95)

    def test_from_dict_defaults(self):
        data = {}
        result = GraphitiSearchResult.from_dict(data)
        assert result.score == pytest.approx(0.0)
        assert result.label == ""


class TestGraphitiClient:
    """Tests for GraphitiClient — uses mock HTTP responses."""

    def _make_client(self, base_url: str = "http://graphiti:8010") -> GraphitiClient:
        return GraphitiClient(base_url=base_url, timeout=1.0)

    @pytest.mark.asyncio
    async def test_create_node_success(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"node_id": "created-123"}

        with patch.object(client, "_post", new=AsyncMock(return_value={"node_id": "created-123"})):
            node = GraphitiNode(label="CVE", name="CVE-2024-1234")
            result = await client.create_node(node)
            assert result is not None
            assert result.node_id == "created-123"

    @pytest.mark.asyncio
    async def test_create_node_degrades_gracefully_on_error(self):
        import httpx
        client = self._make_client()
        with patch.object(client, "_post", new=AsyncMock(return_value=None)):
            node = GraphitiNode(label="CVE", name="CVE-2024-1234")
            result = await client.create_node(node)
            assert result is None

    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        client = self._make_client()
        mock_results = {
            "results": [
                {"node_id": "n1", "label": "Finding", "name": "SQLi", "score": 0.9},
                {"node_id": "n2", "label": "Finding", "name": "XSS", "score": 0.7},
            ]
        }
        with patch.object(client, "_post", new=AsyncMock(return_value=mock_results)):
            results = await client.search("SQL injection")
            assert len(results) == 2
            assert results[0].name == "SQLi"

    @pytest.mark.asyncio
    async def test_search_with_memory_type_filter(self):
        client = self._make_client()
        mock_results = {"results": [
            {"node_id": "n1", "label": "Finding", "name": "Apache", "score": 0.8}
        ]}
        with patch.object(client, "_post", new=AsyncMock(return_value=mock_results)) as mock_post:
            await client.search("Apache exploit", memory_type=MemoryType.GUIDE)
            call_payload = mock_post.call_args[0][1]
            assert call_payload["memory_type"] == "guide"

    @pytest.mark.asyncio
    async def test_search_returns_empty_on_failure(self):
        client = self._make_client()
        with patch.object(client, "_post", new=AsyncMock(return_value=None)):
            results = await client.search("any query")
            assert results == []

    @pytest.mark.asyncio
    async def test_search_with_flow_id_filter(self):
        client = self._make_client()
        mock_results = {"results": []}
        with patch.object(client, "_post", new=AsyncMock(return_value=mock_results)) as mock_post:
            await client.search("query", flow_id="flow-abc")
            call_payload = mock_post.call_args[0][1]
            assert call_payload["flow_id"] == "flow-abc"

    @pytest.mark.asyncio
    async def test_ingest_agent_output(self):
        client = self._make_client()
        mock_result = {"node_id": "finding-001"}
        with patch.object(client, "_post", new=AsyncMock(return_value=mock_result)):
            node = await client.ingest_agent_output(
                content="Found SQLi on /search endpoint",
                agent_role="exploit",
                memory_type=MemoryType.ANSWER,
                flow_id="flow-001",
                session_id="session-001",
                cve="CVE-2024-9999",
            )
            assert node is not None

    @pytest.mark.asyncio
    async def test_delete_node_success(self):
        client = self._make_client()
        with patch.object(client, "_delete", new=AsyncMock(return_value=True)):
            result = await client.delete_node("node-123")
            assert result is True

    @pytest.mark.asyncio
    async def test_delete_node_returns_false_on_failure(self):
        client = self._make_client()
        with patch.object(client, "_delete", new=AsyncMock(return_value=False)):
            result = await client.delete_node("bad-id")
            assert result is False

    @pytest.mark.asyncio
    async def test_create_relation(self):
        client = self._make_client()
        mock_result = {"relation_id": "rel-001"}
        with patch.object(client, "_post", new=AsyncMock(return_value=mock_result)):
            relation = GraphitiRelation(
                from_node_id="node-A",
                to_node_id="node-B",
                relation_type="EXPLOITS",
            )
            result = await client.create_relation(relation)
            assert result is not None
            assert result.relation_id == "rel-001"

    @pytest.mark.asyncio
    async def test_context_manager(self):
        client = self._make_client()
        async with client as c:
            assert c is client

    @pytest.mark.asyncio
    async def test_http_error_degrades_gracefully(self):
        import httpx
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        exc = httpx.HTTPStatusError("Service unavailable", request=MagicMock(), response=mock_resp)
        http_client = AsyncMock()
        http_client.post.side_effect = exc
        client._client = http_client
        result = await client._post("/nodes", {})
        assert result is None

    @pytest.mark.asyncio
    async def test_connection_error_degrades_gracefully(self):
        import httpx
        client = self._make_client()
        http_client = AsyncMock()
        http_client.post.side_effect = httpx.ConnectError("Connection refused")
        client._client = http_client
        result = await client._post("/nodes", {})
        assert result is None


# ===========================================================================
# FlowMemoryNamespace
# ===========================================================================

from app.agent.memory.flow_memory import FlowMemoryNamespace


class TestFlowMemoryNamespace:
    """Tests for FlowMemoryNamespace."""

    def _make_ns(
        self,
        flow_id: str = "flow-ns-001",
        graphiti: Any = None,
    ) -> FlowMemoryNamespace:
        store = EpisodicMemoryStore()
        return FlowMemoryNamespace(
            flow_id=flow_id,
            store=store,
            graphiti=graphiti,
            auto_sync_graphiti=graphiti is not None,
        )

    @pytest.mark.asyncio
    async def test_capture_stores_locally(self):
        ns = self._make_ns()
        entry = await ns.capture(
            session_id="session-001",
            agent_role="recon",
            memory_type=MemoryType.ANSWER,
            content="test finding",
        )
        assert entry.flow_id == "flow-ns-001"
        assert entry.content == "test finding"
        local = ns.query_local()
        assert len(local) == 1

    @pytest.mark.asyncio
    async def test_capture_with_all_optional_fields(self):
        ns = self._make_ns()
        entry = await ns.capture(
            session_id="s1",
            agent_role="exploit",
            memory_type=MemoryType.CODE,
            content="reverse shell payload",
            cve="CVE-2024-1234",
            technique="T1059",
            tool_name="metasploit",
            tags=["critical", "rce"],
            score=1.0,
        )
        assert entry.cve == "CVE-2024-1234"
        assert entry.technique == "T1059"
        assert entry.tool_name == "metasploit"
        assert "critical" in entry.tags

    @pytest.mark.asyncio
    async def test_capture_syncs_to_graphiti(self):
        mock_graphiti = AsyncMock(spec=GraphitiClient)
        mock_graphiti.ingest_agent_output.return_value = GraphitiNode(label="F", name="f")
        ns = FlowMemoryNamespace(
            flow_id="flow-001",
            store=EpisodicMemoryStore(),
            graphiti=mock_graphiti,
            auto_sync_graphiti=True,
        )
        await ns.capture(
            session_id="s1",
            agent_role="recon",
            memory_type=MemoryType.ANSWER,
            content="synced finding",
        )
        mock_graphiti.ingest_agent_output.assert_called_once()

    @pytest.mark.asyncio
    async def test_capture_graphiti_failure_non_fatal(self):
        mock_graphiti = AsyncMock(spec=GraphitiClient)
        mock_graphiti.ingest_agent_output.side_effect = RuntimeError("Graphiti down")
        ns = FlowMemoryNamespace(
            flow_id="flow-001",
            store=EpisodicMemoryStore(),
            graphiti=mock_graphiti,
            auto_sync_graphiti=True,
        )
        # Should not raise even though Graphiti is down
        entry = await ns.capture(
            session_id="s1",
            agent_role="recon",
            memory_type=MemoryType.ANSWER,
            content="test",
        )
        assert entry is not None

    @pytest.mark.asyncio
    async def test_query_local_filtered(self):
        ns = self._make_ns()
        await ns.capture(session_id="s", agent_role="r", memory_type=MemoryType.ANSWER, content="a")
        await ns.capture(session_id="s", agent_role="r", memory_type=MemoryType.GUIDE, content="g")
        results = ns.query_local(memory_type=MemoryType.GUIDE)
        assert len(results) == 1
        assert results[0].memory_type is MemoryType.GUIDE

    @pytest.mark.asyncio
    async def test_recent(self):
        ns = self._make_ns()
        for i in range(5):
            await ns.capture(session_id="s", agent_role="r",
                             memory_type=MemoryType.MEMORY, content=f"entry {i}")
        recent = ns.recent(n=3)
        assert len(recent) == 3

    @pytest.mark.asyncio
    async def test_search_returns_empty_without_graphiti(self):
        ns = self._make_ns(graphiti=None)
        results = await ns.search("query")
        assert results == []

    @pytest.mark.asyncio
    async def test_search_delegates_to_graphiti(self):
        mock_graphiti = AsyncMock(spec=GraphitiClient)
        mock_graphiti.search.return_value = [
            GraphitiSearchResult(node_id="n1", label="F", name="SQLi", score=0.9)
        ]
        ns = FlowMemoryNamespace(
            flow_id="flow-001",
            store=EpisodicMemoryStore(),
            graphiti=mock_graphiti,
        )
        results = await ns.search("SQL injection")
        assert len(results) == 1
        assert results[0].name == "SQLi"
        mock_graphiti.search.assert_called_once_with(
            query="SQL injection", memory_type=None, limit=10, flow_id="flow-001"
        )

    @pytest.mark.asyncio
    async def test_hybrid_search(self):
        mock_graphiti = AsyncMock(spec=GraphitiClient)
        mock_graphiti.search.return_value = [
            GraphitiSearchResult(node_id="n1", label="F", name="XSS", score=0.8)
        ]
        ns = FlowMemoryNamespace(
            flow_id="flow-001",
            store=EpisodicMemoryStore(),
            graphiti=mock_graphiti,
        )
        await ns.capture(session_id="s", agent_role="r",
                         memory_type=MemoryType.ANSWER, content="local finding")
        result = await ns.hybrid_search("XSS vulnerability")
        assert "local" in result
        assert "graphiti" in result
        assert len(result["local"]) == 1
        assert len(result["graphiti"]) == 1

    @pytest.mark.asyncio
    async def test_stats(self):
        ns = self._make_ns()
        await ns.capture(session_id="s", agent_role="r",
                         memory_type=MemoryType.ANSWER, content="entry")
        stats = ns.stats()
        assert stats["total_entries"] == 1
        assert stats["flow_id"] == "flow-ns-001"

    @pytest.mark.asyncio
    async def test_clear(self):
        ns = self._make_ns()
        await ns.capture(session_id="s", agent_role="r",
                         memory_type=MemoryType.ANSWER, content="to clear")
        count = ns.clear()
        assert count == 1
        assert ns.query_local() == []


# ===========================================================================
# BaseAgent memory integration
# ===========================================================================

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry


class _ConcreteAgent(BaseAgent):
    """Minimal concrete agent for testing BaseAgent memory features."""
    AGENT_NAME = "test_agent"
    PREFERRED_TOOLS = []

    def get_phase(self) -> Phase:
        return Phase.INFORMATIONAL

    async def run(self, state: MultiAgentState, task: str):
        return {"agent": self.AGENT_NAME, "task": task}


class TestBaseAgentMemoryIntegration:
    """Tests for BaseAgent memory capture and query capabilities."""

    def _make_agent(self, memory_ns=None, auto_capture=True):
        registry = ToolRegistry()
        return _ConcreteAgent(
            registry=registry,
            memory_ns=memory_ns,
            auto_capture=auto_capture,
        )

    @pytest.mark.asyncio
    async def test_capture_memory_no_namespace_noop(self):
        agent = self._make_agent(memory_ns=None)
        from app.agent.memory.episodic_memory import MemoryType
        # Should not raise
        await agent.capture_memory("content", MemoryType.ANSWER)

    @pytest.mark.asyncio
    async def test_capture_memory_auto_capture_false_noop(self):
        store = EpisodicMemoryStore()
        graphiti = AsyncMock(spec=GraphitiClient)
        ns = FlowMemoryNamespace("flow-001", store, graphiti)
        agent = self._make_agent(memory_ns=ns, auto_capture=False)

        from app.agent.memory.episodic_memory import MemoryType
        await agent.capture_memory("should not be stored", MemoryType.ANSWER)
        assert store.stats()["total_entries"] == 0

    @pytest.mark.asyncio
    async def test_capture_memory_stores_entry(self):
        store = EpisodicMemoryStore()
        ns = FlowMemoryNamespace("flow-001", store, None)
        agent = self._make_agent(memory_ns=ns, auto_capture=True)

        from app.agent.memory.episodic_memory import MemoryType
        await agent.capture_memory(
            "important finding",
            MemoryType.ANSWER,
            session_id="session-001",
        )
        entries = store.query("flow-001")
        assert len(entries) == 1
        assert entries[0].content == "important finding"
        assert entries[0].agent_role == "test_agent"

    @pytest.mark.asyncio
    async def test_query_past_knowledge_no_namespace(self):
        agent = self._make_agent(memory_ns=None)
        results = await agent.query_past_knowledge("anything")
        assert results == []

    @pytest.mark.asyncio
    async def test_query_past_knowledge_with_namespace(self):
        mock_graphiti = AsyncMock(spec=GraphitiClient)
        mock_graphiti.search.return_value = [
            GraphitiSearchResult(node_id="n1", label="F", name="SQLi", score=0.9)
        ]
        store = EpisodicMemoryStore()
        ns = FlowMemoryNamespace("flow-001", store, mock_graphiti)
        agent = self._make_agent(memory_ns=ns)

        results = await agent.query_past_knowledge("SQL injection technique")
        assert len(results) == 1
        assert results[0]["name"] == "SQLi"

    def test_set_memory_namespace(self):
        agent = self._make_agent()
        store = EpisodicMemoryStore()
        ns = FlowMemoryNamespace("flow-001", store, None)
        agent.set_memory_namespace(ns)
        assert agent._memory_ns is ns

    def test_get_summarizer_no_llm(self):
        agent = self._make_agent()
        assert agent.get_summarizer() is None

    def test_get_summarizer_with_llm(self):
        agent = self._make_agent()
        agent.llm = MagicMock()
        summarizer = agent.get_summarizer()
        assert summarizer is not None

    @pytest.mark.asyncio
    async def test_compress_messages_no_llm_returns_original(self):
        agent = self._make_agent()
        messages = [{"type": "human", "content": "test"}]
        result = await agent.compress_messages(messages)
        assert result == messages

    @pytest.mark.asyncio
    async def test_compress_messages_with_summarizer(self):
        agent = self._make_agent()
        mock_llm = AsyncMock()
        mock_llm.ainvoke.return_value = MagicMock(content="Summarised history")
        agent.llm = mock_llm

        from langchain_core.messages import HumanMessage, AIMessage
        # Create a large list of messages that will trigger summarisation
        messages = [HumanMessage(content=f"msg {i} " * 100) for i in range(20)]
        result = await agent.compress_messages(messages, model_name="gpt-4")
        # Should be fewer messages after compression
        assert len(result) <= len(messages)
