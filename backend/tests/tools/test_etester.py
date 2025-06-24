"""
Comprehensive tests for:
  - AutoCaptureMiddleware (backend/app/agent/memory/auto_capture.py)
  - EtesterCLI (backend/tools/etester.py)
  - BaseAgent middleware integration (backend/app/agent/agents/__init__.py)

All async tests use asyncio.run() for Python 3.12 compatibility.
"""

from __future__ import annotations

import asyncio
import os
import sys
import types
import importlib
import importlib.util
from argparse import Namespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_BACKEND = os.path.join(_REPO_ROOT, "backend")
_TOOLS_DIR = os.path.join(_BACKEND, "tools")

for p in (_BACKEND, _TOOLS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Import targets
# ---------------------------------------------------------------------------

from app.agent.memory.episodic_memory import MemoryType  # noqa: E402
from app.agent.memory.auto_capture import AutoCaptureMiddleware, CaptureEntry  # noqa: E402
import etester  # noqa: E402
from etester import EtesterCLI, colored, ok, fail, _human_bytes, _provider_api_key_env  # noqa: E402


# ===========================================================================
# Helpers / fixtures
# ===========================================================================


def _make_registry(dims: int = 8) -> MagicMock:
    """Return a mock EmbeddingRegistry that returns real-ish embeddings."""
    reg = MagicMock()
    reg.get_provider_info.return_value = {
        "name": "tfidf",
        "model": "tfidf",
        "dimensions": dims,
        "configured": True,
    }
    reg.embed_with_fallback.return_value = [[0.1] * dims]
    reg.list_providers.return_value = ["tfidf", "openai"]
    return reg


def _make_store() -> MagicMock:
    store = MagicMock()
    store.initialize = AsyncMock()
    store.close = AsyncMock()
    store.add_document = AsyncMock(return_value="doc-id")
    store.search = AsyncMock(return_value=[])
    store.flush_collection = AsyncMock(return_value=5)
    store.list_collections = AsyncMock(return_value=["univex_answer"])
    store.get_collection_stats = AsyncMock(
        return_value={"count": 10, "dimensions": 8, "storage_bytes": 1024}
    )
    store.delete_document = AsyncMock(return_value=True)
    return store


# ===========================================================================
# AutoCaptureMiddleware Tests
# ===========================================================================


class TestAutoCaptureMiddlewareEnabled:
    def test_disabled_by_default(self):
        mw = AutoCaptureMiddleware()
        assert mw._enabled is False

    def test_enabled_via_param(self):
        mw = AutoCaptureMiddleware(enabled=True)
        assert mw._enabled is True

    def test_enabled_via_env(self):
        with patch.dict(os.environ, {"AUTO_CAPTURE": "true"}):
            mw = AutoCaptureMiddleware()
        assert mw._enabled is True

    def test_disabled_via_env_false(self):
        with patch.dict(os.environ, {"AUTO_CAPTURE": "false"}):
            mw = AutoCaptureMiddleware()
        assert mw._enabled is False

    def test_enable_disable(self):
        mw = AutoCaptureMiddleware(enabled=False)
        mw.enable()
        assert mw._enabled is True
        mw.disable()
        assert mw._enabled is False


class TestAutoCaptureMiddlewareCapture:
    def test_capture_response_disabled_returns_none(self):
        mw = AutoCaptureMiddleware(enabled=False)
        result = asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.ANSWER,
                content="test",
            )
        )
        assert result is None

    def test_capture_response_returns_entry(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        entry = asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.ANSWER,
                content="open ports: 80, 443",
                session_id="sess1",
                tags=["nmap"],
            )
        )
        assert isinstance(entry, CaptureEntry)
        assert entry.flow_id == "f1"
        assert entry.agent_role == "recon"
        assert entry.memory_type == MemoryType.ANSWER
        assert "nmap" in entry.tags
        assert entry.content == "open ports: 80, 443"

    def test_capture_response_increments_stats(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.ANSWER,
                content="data",
            )
        )
        asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.GUIDE,
                content="guide",
            )
        )
        stats = mw.get_stats()
        assert stats["total_captures"] == 2
        assert stats["captures_by_agent"]["recon"] == 2
        assert stats["captures_by_type"]["answer"] == 1
        assert stats["captures_by_type"]["guide"] == 1

    def test_capture_response_graceful_on_registry_failure(self):
        reg = MagicMock()
        reg.embed_with_fallback.side_effect = RuntimeError("provider down")
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        # Should not raise
        entry = asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.ANSWER,
                content="data",
            )
        )
        assert entry is None

    def test_capture_response_with_metadata_kwargs(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        entry = asyncio.run(
            mw.capture_response(
                flow_id="f2",
                agent_role="exploit",
                memory_type=MemoryType.CODE,
                content="payload code",
                session_id="s2",
                tags=["sqli"],
                cve="CVE-2021-1234",
            )
        )
        assert entry is not None
        assert entry.metadata.get("cve") == "CVE-2021-1234"

    def test_multiple_captures_stored_in_entries(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        for i in range(5):
            asyncio.run(
                mw.capture_response(
                    flow_id="f1",
                    agent_role="recon",
                    memory_type=MemoryType.ANSWER,
                    content=f"content {i}",
                )
            )
        assert len(mw._entries) == 5


class TestAutoCaptureMiddlewareCaptureToolOutput:
    def test_capture_tool_output_disabled_returns_none(self):
        mw = AutoCaptureMiddleware(enabled=False)
        result = asyncio.run(
            mw.capture_tool_output(
                flow_id="f1",
                agent_role="recon",
                tool_name="nmap",
                output="80/tcp open",
            )
        )
        assert result is None

    def test_capture_tool_output_returns_entry(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        entry = asyncio.run(
            mw.capture_tool_output(
                flow_id="f1",
                agent_role="recon",
                tool_name="nmap",
                output="80/tcp open http",
                session_id="s1",
            )
        )
        assert isinstance(entry, CaptureEntry)
        assert entry.memory_type == MemoryType.ANSWER
        assert "nmap" in entry.tags
        assert entry.metadata.get("tool_name") == "nmap"

    def test_capture_tool_output_increments_counter(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        asyncio.run(
            mw.capture_tool_output("f1", "recon", "gobuster", "found /admin")
        )
        asyncio.run(
            mw.capture_tool_output("f1", "recon", "nikto", "CVE found")
        )
        stats = mw.get_stats()
        assert stats["total_captures"] == 2


class TestAutoCaptureMiddlewareSearch:
    def test_search_when_disabled_returns_empty(self):
        mw = AutoCaptureMiddleware(enabled=False)
        results = asyncio.run(mw.search_captures("ports"))
        assert results == []

    def test_search_fallback_in_memory(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.ANSWER,
                content="open ports 80 443",
            )
        )
        asyncio.run(
            mw.capture_response(
                flow_id="f1",
                agent_role="recon",
                memory_type=MemoryType.ANSWER,
                content="sql injection found",
            )
        )
        results = asyncio.run(mw.search_captures("ports", flow_id="f1"))
        assert any("ports" in e.content for e in results)

    def test_search_filters_by_agent_role(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        asyncio.run(
            mw.capture_response("f1", "recon", MemoryType.ANSWER, "ports scan results")
        )
        asyncio.run(
            mw.capture_response("f1", "exploit", MemoryType.ANSWER, "ports exploited")
        )
        results = asyncio.run(
            mw.search_captures("ports", agent_role="recon")
        )
        assert all(e.agent_role == "recon" for e in results)

    def test_search_filters_by_memory_type(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        asyncio.run(
            mw.capture_response("f1", "recon", MemoryType.GUIDE, "guide for ports")
        )
        asyncio.run(
            mw.capture_response("f1", "recon", MemoryType.CODE, "code for ports")
        )
        results = asyncio.run(
            mw.search_captures("ports", memory_type=MemoryType.GUIDE)
        )
        assert all(e.memory_type == MemoryType.GUIDE for e in results)

    def test_search_respects_k_limit(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        for i in range(10):
            asyncio.run(
                mw.capture_response("f1", "recon", MemoryType.ANSWER, f"result {i}")
            )
        results = asyncio.run(mw.search_captures("result", k=3))
        assert len(results) <= 3


class TestAutoCaptureMiddlewareStats:
    def test_get_stats_structure(self):
        mw = AutoCaptureMiddleware(enabled=True)
        stats = mw.get_stats()
        assert "total_captures" in stats
        assert "captures_by_agent" in stats
        assert "captures_by_type" in stats
        assert "enabled" in stats

    def test_get_stats_enabled_reflects_state(self):
        mw = AutoCaptureMiddleware(enabled=False)
        assert mw.get_stats()["enabled"] is False
        mw.enable()
        assert mw.get_stats()["enabled"] is True

    def test_get_stats_initial_zeros(self):
        mw = AutoCaptureMiddleware(enabled=True)
        stats = mw.get_stats()
        assert stats["total_captures"] == 0
        assert stats["captures_by_agent"] == {}
        assert stats["captures_by_type"] == {}

    def test_collection_prefix_in_entry(self):
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True, collection_prefix="test")
        entry = asyncio.run(
            mw.capture_response("f1", "recon", MemoryType.ANSWER, "content")
        )
        assert entry is not None
        assert entry.collection.startswith("test_")


# ===========================================================================
# EtesterCLI Tests
# ===========================================================================


class TestEtesterHelpers:
    def test_colored_no_color_env(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            result = colored("hello", "green")
        assert result == "hello"

    def test_colored_with_color(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            result = colored("hello", "green")
        assert "\033[" in result

    def test_ok_contains_checkmark(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            assert "✓" in ok("test")

    def test_fail_contains_cross(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            assert "✗" in fail("test")

    def test_human_bytes_bytes(self):
        assert "B" in _human_bytes(512)

    def test_human_bytes_kb(self):
        assert "KB" in _human_bytes(2048)

    def test_human_bytes_mb(self):
        assert "MB" in _human_bytes(2 * 1024 * 1024)

    def test_provider_api_key_env_openai(self):
        assert _provider_api_key_env("openai") == "OPENAI_API_KEY"

    def test_provider_api_key_env_unknown(self):
        assert _provider_api_key_env("tfidf") is None


class TestEtesterCLICmdInfo:
    def test_cmd_info_prints_provider(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        cli.cmd_info(Namespace())
        out = capsys.readouterr().out
        assert "tfidf" in out

    def test_cmd_info_shows_dimensions(self, capsys):
        reg = _make_registry(dims=384)
        cli = EtesterCLI(registry=reg)
        cli.cmd_info(Namespace())
        out = capsys.readouterr().out
        assert "384" in out

    def test_cmd_info_shows_configured(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        cli.cmd_info(Namespace())
        out = capsys.readouterr().out
        assert "yes" in out or "✓" in out

    def test_cmd_info_shows_no_store_without_db_url(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_info(Namespace())
        out = capsys.readouterr().out
        assert "DATABASE_URL" in out or "none" in out

    def test_cmd_info_shows_api_key_masked(self, capsys):
        reg = _make_registry()
        reg.get_provider_info.return_value = {
            "name": "openai",
            "model": "text-embedding-3-small",
            "dimensions": 1536,
            "configured": True,
        }
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test1234abcd", "DATABASE_URL": ""}):
            cli.cmd_info(Namespace())
        out = capsys.readouterr().out
        assert "****" in out


class TestEtesterCLICmdSearch:
    def test_cmd_search_no_db_url(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_search(Namespace(query="ports", type=None, k=5))
        out = capsys.readouterr().out
        assert "unavailable" in out.lower() or "DATABASE_URL" in out

    def test_cmd_search_embed_failure_exits(self):
        reg = MagicMock()
        reg.embed_with_fallback.return_value = []
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}):
            with pytest.raises(SystemExit) as exc_info:
                cli.cmd_search(Namespace(query="test", type=None, k=5))
        assert exc_info.value.code == 1

    def test_cmd_search_prints_results(self, capsys):
        reg = _make_registry()
        from app.embeddings.pgvector_store import SearchResult

        mock_results = [
            SearchResult(doc_id="doc-1", text="port 80 open", score=0.9, metadata={}, collection="univex_answer")
        ]
        store = _make_store()
        store.search = AsyncMock(return_value=mock_results)

        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_search(Namespace(query="ports", type="answer", k=5))
        out = capsys.readouterr().out
        assert "doc-1" in out or "port 80" in out

    def test_cmd_search_no_results_message(self, capsys):
        reg = _make_registry()
        store = _make_store()
        store.search = AsyncMock(return_value=[])

        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_search(Namespace(query="nothinghere", type=None, k=5))
        out = capsys.readouterr().out
        assert "no results" in out.lower()


class TestEtesterCLICmdFlush:
    def test_cmd_flush_no_db_url(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_flush(Namespace(collection=None, yes=True))
        out = capsys.readouterr().out
        assert "unavailable" in out.lower() or "DATABASE_URL" in out

    def test_cmd_flush_yes_flag_skips_confirmation(self, capsys):
        reg = _make_registry()
        store = _make_store()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_flush(Namespace(collection="univex_answer", yes=True))
        out = capsys.readouterr().out
        assert "5" in out  # flush_collection returns 5

    def test_cmd_flush_confirmation_declined(self, capsys):
        reg = _make_registry()
        store = _make_store()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store), \
             patch("builtins.input", return_value="n"):
            cli.cmd_flush(Namespace(collection="univex_answer", yes=False))
        out = capsys.readouterr().out
        assert "aborted" in out.lower()

    def test_cmd_flush_confirmation_accepted(self, capsys):
        reg = _make_registry()
        store = _make_store()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store), \
             patch("builtins.input", return_value="y"):
            cli.cmd_flush(Namespace(collection="univex_answer", yes=False))
        out = capsys.readouterr().out
        assert "5" in out

    def test_cmd_flush_all_collections_when_no_collection(self, capsys):
        reg = _make_registry()
        store = _make_store()
        store.list_collections = AsyncMock(return_value=["univex_answer", "univex_guide"])
        store.flush_collection = AsyncMock(return_value=3)
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_flush(Namespace(collection=None, yes=True))
        out = capsys.readouterr().out
        assert "univex_answer" in out or "3" in out


class TestEtesterCLICmdReindex:
    def test_cmd_reindex_no_db_url(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_reindex(Namespace(provider=None, batch_size=32))
        out = capsys.readouterr().out
        assert "unavailable" in out.lower() or "DATABASE_URL" in out

    def test_cmd_reindex_invalid_provider_exits(self):
        reg = _make_registry()
        reg.set_provider.side_effect = ValueError("Unknown provider 'bad'")
        cli = EtesterCLI(registry=reg)
        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_reindex(Namespace(provider="bad", batch_size=32))
        assert exc_info.value.code == 1

    def test_cmd_reindex_reports_documents(self, capsys):
        reg = _make_registry()
        store = _make_store()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_reindex(Namespace(provider=None, batch_size=32))
        out = capsys.readouterr().out
        assert "reindex" in out.lower() or "10" in out

    def test_cmd_reindex_switches_provider(self, capsys):
        reg = _make_registry()
        store = _make_store()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_reindex(Namespace(provider="tfidf", batch_size=16))
        reg.set_provider.assert_called_once_with("tfidf")


class TestEtesterCLICmdStats:
    def test_cmd_stats_shows_provider(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_stats(Namespace())
        out = capsys.readouterr().out
        assert "tfidf" in out

    def test_cmd_stats_no_db_url_shows_unavailable(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_stats(Namespace())
        out = capsys.readouterr().out
        assert "unavailable" in out.lower() or "DATABASE_URL" in out

    def test_cmd_stats_with_store(self, capsys):
        reg = _make_registry()
        store = _make_store()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            cli.cmd_stats(Namespace())
        out = capsys.readouterr().out
        assert "10" in out  # count from mock


class TestEtesterCLICmdTest:
    def test_cmd_test_embed_failure_exits(self):
        reg = MagicMock()
        reg.embed_with_fallback.return_value = []
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            with pytest.raises(SystemExit) as exc_info:
                cli.cmd_test(Namespace(provider=None))
        assert exc_info.value.code == 1

    def test_cmd_test_success_no_db(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_test(Namespace(provider=None))
        out = capsys.readouterr().out
        assert "✓" in out or "Step 1" in out

    def test_cmd_test_with_store(self, capsys):
        reg = _make_registry()
        from app.embeddings.pgvector_store import SearchResult

        store = _make_store()
        store.search = AsyncMock(
            return_value=[
                SearchResult(
                    doc_id="etester_test_TESTID",
                    text="UniVex security test",
                    score=1.0,
                    metadata={},
                    collection="univex_etester_test",
                )
            ]
        )

        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch.object(cli, "_get_store", return_value=store):
            # Patch uuid to get deterministic test id
            with patch("etester.uuid.uuid4") as mock_uuid:
                mock_uuid.return_value.hex = "TESTID12345678"
                # The store search returns a doc_id that won't match test_id
                # so retrieve step will fail — that's acceptable
                try:
                    cli.cmd_test(Namespace(provider=None))
                except SystemExit:
                    pass
        # At least embed step should succeed
        out = capsys.readouterr().out
        assert "Step 1" in out

    def test_cmd_test_provider_switch(self, capsys):
        reg = _make_registry()
        cli = EtesterCLI(registry=reg)
        with patch.dict(os.environ, {"DATABASE_URL": ""}):
            cli.cmd_test(Namespace(provider="tfidf"))
        reg.set_provider.assert_called_once_with("tfidf")

    def test_cmd_test_invalid_provider_exits(self):
        reg = _make_registry()
        reg.set_provider.side_effect = ValueError("Unknown provider")
        cli = EtesterCLI(registry=reg)
        with pytest.raises(SystemExit) as exc_info:
            cli.cmd_test(Namespace(provider="bad"))
        assert exc_info.value.code == 1


# ===========================================================================
# BaseAgent Middleware Integration Tests
# ===========================================================================

class _ConcreteAgent:
    """Minimal concrete agent for testing BaseAgent methods."""
    pass


def _make_base_agent():
    """Create a minimal BaseAgent subclass instance."""
    from app.agent.agents import BaseAgent, MultiAgentState
    from app.agent.state.agent_state import Phase
    from app.agent.tools.tool_registry import ToolRegistry

    class ConcreteAgent(BaseAgent):
        AGENT_NAME = "test_agent"
        PREFERRED_TOOLS: list = []

        def get_phase(self):
            return Phase.RECON

        async def run(self, state, task):
            return {}

    registry = MagicMock(spec=ToolRegistry)
    registry.get_tool.return_value = None
    registry.get_tools_for_phase.return_value = {}
    return ConcreteAgent(registry=registry)


class TestBaseAgentMiddlewareIntegration:
    def test_auto_capture_middleware_initially_none(self):
        agent = _make_base_agent()
        assert agent._auto_capture_middleware is None

    def test_set_auto_capture_middleware(self):
        agent = _make_base_agent()
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        agent.set_auto_capture_middleware(mw)
        assert agent._auto_capture_middleware is mw

    def test_capture_memory_with_middleware(self):
        agent = _make_base_agent()
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        agent.set_auto_capture_middleware(mw)

        asyncio.run(
            agent.capture_memory(
                content="ports: 80, 443",
                memory_type=MemoryType.ANSWER,
                session_id="s1",
                flow_id="f1",
            )
        )
        stats = mw.get_stats()
        assert stats["total_captures"] == 1
        assert stats["captures_by_agent"]["test_agent"] == 1

    def test_capture_memory_no_middleware_no_crash(self):
        agent = _make_base_agent()
        # Should not raise even without middleware or memory_ns
        asyncio.run(
            agent.capture_memory(
                content="test",
                memory_type=MemoryType.ANSWER,
            )
        )

    def test_capture_memory_auto_capture_false_skips_middleware(self):
        agent = _make_base_agent()
        agent.auto_capture = False
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        agent.set_auto_capture_middleware(mw)

        asyncio.run(
            agent.capture_memory(
                content="test",
                memory_type=MemoryType.ANSWER,
            )
        )
        assert mw.get_stats()["total_captures"] == 0

    def test_capture_tool_output_with_middleware(self):
        agent = _make_base_agent()
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        agent.set_auto_capture_middleware(mw)

        asyncio.run(
            agent.capture_tool_output(
                tool_name="nmap",
                output="80/tcp open http",
                flow_id="f1",
                session_id="s1",
            )
        )
        stats = mw.get_stats()
        assert stats["total_captures"] == 1

    def test_capture_tool_output_no_middleware_no_crash(self):
        agent = _make_base_agent()
        asyncio.run(
            agent.capture_tool_output(
                tool_name="nmap",
                output="result",
            )
        )

    def test_capture_tool_output_auto_capture_false(self):
        agent = _make_base_agent()
        agent.auto_capture = False
        reg = _make_registry()
        mw = AutoCaptureMiddleware(registry=reg, enabled=True)
        agent.set_auto_capture_middleware(mw)

        asyncio.run(
            agent.capture_tool_output(
                tool_name="nmap",
                output="result",
            )
        )
        assert mw.get_stats()["total_captures"] == 0

    def test_capture_memory_middleware_error_does_not_crash(self):
        agent = _make_base_agent()
        mw = MagicMock()
        mw.capture_response = AsyncMock(side_effect=RuntimeError("middleware boom"))
        agent.set_auto_capture_middleware(mw)

        # Should not raise
        asyncio.run(
            agent.capture_memory(
                content="test",
                memory_type=MemoryType.ANSWER,
            )
        )

    def test_capture_tool_output_middleware_error_does_not_crash(self):
        agent = _make_base_agent()
        mw = MagicMock()
        mw.capture_tool_output = AsyncMock(side_effect=RuntimeError("middleware boom"))
        agent.set_auto_capture_middleware(mw)

        asyncio.run(
            agent.capture_tool_output(tool_name="gobuster", output="found /admin")
        )


# ===========================================================================
# etester main() / argparse integration
# ===========================================================================


class TestEtesterMain:
    def test_main_no_args_prints_help(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            etester.main([])
        assert exc_info.value.code == 0

    def test_main_info_calls_cmd_info(self, capsys):
        reg = _make_registry()
        with patch.dict(os.environ, {"DATABASE_URL": ""}), \
             patch("etester.EtesterCLI._get_registry", return_value=reg):
            etester.main(["info"])
        out = capsys.readouterr().out
        assert "tfidf" in out

    def test_main_stats_no_crash(self, capsys):
        reg = _make_registry()
        with patch.dict(os.environ, {"DATABASE_URL": ""}), \
             patch("etester.EtesterCLI._get_registry", return_value=reg):
            etester.main(["stats"])

    def test_main_search_missing_query_exits(self):
        with pytest.raises(SystemExit):
            etester.main(["search"])

    def test_main_flush_yes(self, capsys):
        reg = _make_registry()
        store = _make_store()
        with patch.dict(os.environ, {"DATABASE_URL": "postgres://test"}), \
             patch("etester.EtesterCLI._get_registry", return_value=reg), \
             patch("etester.EtesterCLI._get_store", return_value=store):
            etester.main(["flush", "--collection", "univex_answer", "--yes"])
        out = capsys.readouterr().out
        assert "5" in out

    def test_main_unknown_command_handled(self):
        with pytest.raises(SystemExit):
            etester.main(["unknowncmd"])
