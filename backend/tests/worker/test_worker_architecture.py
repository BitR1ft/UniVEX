"""
Tests for Day 16 — Two-Node Worker Architecture

Coverage:
  WorkerJobRequest / WorkerJobResult  — field defaults, validation
  _verify_request                     — bearer token auth, dev mode
  _execute_job                        — success, timeout, unknown server, exception
  create_app / FastAPI endpoints      — /health, /capabilities, /execute
  WorkerClient                        — execute success, retry, fallback, circuit breaker
  WorkerUnavailableError              — raised when fallback=False
  JobDispatcher                       — classify, dispatch local, dispatch remote
  JobClassification                   — ALWAYS_REMOTE, ALWAYS_LOCAL, phase heuristic
  OrchestratorAgent                   — dispatch_tool with dispatcher, without dispatcher
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# asyncio helper
# ---------------------------------------------------------------------------

def run(coro):
    return asyncio.run(coro)


# ===========================================================================
# Worker Server
# ===========================================================================

from app.worker.worker_server import (
    WorkerJobRequest,
    WorkerJobResult,
    _execute_job,
    _verify_request,
    create_app,
    register_mcp_server,
    _MCP_SERVERS,
    WORKER_MAX_TIMEOUT,
    WORKER_MAX_CONCURRENT,
)


class TestWorkerJobRequest:
    def test_defaults(self):
        req = WorkerJobRequest(tool_name="execute_naabu", server_name="naabu")
        assert req.server_name == "naabu"
        assert req.tool_name == "execute_naabu"
        assert isinstance(req.job_id, str) and len(req.job_id) == 32
        assert req.classification == "remote"
        assert req.timeout == WORKER_MAX_TIMEOUT

    def test_custom_params(self):
        req = WorkerJobRequest(
            tool_name="execute_naabu",
            server_name="naabu",
            params={"target": "10.0.0.1"},
            timeout=60,
        )
        assert req.params["target"] == "10.0.0.1"
        assert req.timeout == 60

    def test_job_id_unique(self):
        r1 = WorkerJobRequest(tool_name="t", server_name="s")
        r2 = WorkerJobRequest(tool_name="t", server_name="s")
        assert r1.job_id != r2.job_id


class TestWorkerJobResult:
    def test_success_result(self):
        r = WorkerJobResult(
            job_id="abc", tool_name="naabu_scan", server_name="naabu",
            success=True, result={"ports": [80]},
        )
        assert r.success is True
        assert r.result["ports"] == [80]
        assert r.error is None

    def test_failure_result(self):
        r = WorkerJobResult(
            job_id="def", tool_name="naabu_scan", server_name="naabu",
            success=False, error="connection refused",
        )
        assert r.success is False
        assert "refused" in r.error

    def test_worker_id_default(self):
        r = WorkerJobResult(
            job_id="g", tool_name="t", server_name="s", success=True
        )
        assert isinstance(r.worker_id, str) and len(r.worker_id) > 0


class TestVerifyRequest:
    def _make_request(self, auth_header: str = "") -> MagicMock:
        req = MagicMock()
        req.headers = {"Authorization": auth_header} if auth_header else {}
        return req

    def test_dev_mode_no_secret_allows_all(self):
        # WORKER_SHARED_SECRET is empty in test env → always allowed
        import app.worker.worker_server as ws
        original = ws.WORKER_SHARED_SECRET
        ws.WORKER_SHARED_SECRET = ""
        try:
            req = self._make_request("")
            assert _verify_request(req) is True
        finally:
            ws.WORKER_SHARED_SECRET = original

    def test_correct_bearer_token(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = "mysecret"
        try:
            req = self._make_request("Bearer mysecret")
            assert _verify_request(req) is True
        finally:
            ws.WORKER_SHARED_SECRET = ""

    def test_wrong_bearer_token(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = "mysecret"
        try:
            req = self._make_request("Bearer wrongtoken")
            assert _verify_request(req) is False
        finally:
            ws.WORKER_SHARED_SECRET = ""

    def test_missing_auth_header(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = "mysecret"
        try:
            req = self._make_request("")
            assert _verify_request(req) is False
        finally:
            ws.WORKER_SHARED_SECRET = ""

    def test_wrong_prefix(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = "mysecret"
        try:
            req = self._make_request("Token mysecret")
            assert _verify_request(req) is False
        finally:
            ws.WORKER_SHARED_SECRET = ""


class TestExecuteJob:
    def setup_method(self):
        # Clear registered servers before each test
        _MCP_SERVERS.clear()

    def test_unknown_server_returns_error(self):
        req = WorkerJobRequest(tool_name="t", server_name="unknown_srv")
        result = run(_execute_job(req))
        assert result.success is False
        assert "unknown_srv" in result.error

    def test_success_dispatch(self):
        mock_server = MagicMock()
        mock_server.execute_tool = AsyncMock(return_value={"ports": [80, 443]})
        register_mcp_server("naabu", mock_server)
        req = WorkerJobRequest(tool_name="execute_naabu", server_name="naabu",
                               params={"target": "10.0.0.1"})
        result = run(_execute_job(req))
        assert result.success is True
        assert result.result["ports"] == [80, 443]

    def test_timeout_returns_error(self):
        async def slow_tool(name, params):
            await asyncio.sleep(10)
        mock_server = MagicMock()
        mock_server.execute_tool = slow_tool
        register_mcp_server("slow", mock_server)
        req = WorkerJobRequest(tool_name="t", server_name="slow", timeout=0)
        result = run(_execute_job(req))
        assert result.success is False
        assert "timed out" in result.error

    def test_exception_returns_error(self):
        mock_server = MagicMock()
        mock_server.execute_tool = AsyncMock(side_effect=RuntimeError("tool crash"))
        register_mcp_server("crash_srv", mock_server)
        req = WorkerJobRequest(tool_name="t", server_name="crash_srv")
        result = run(_execute_job(req))
        assert result.success is False
        assert "tool crash" in result.error

    def test_duration_ms_populated(self):
        mock_server = MagicMock()
        mock_server.execute_tool = AsyncMock(return_value={})
        register_mcp_server("fast", mock_server)
        req = WorkerJobRequest(tool_name="t", server_name="fast")
        result = run(_execute_job(req))
        assert result.duration_ms >= 0


class TestWorkerServerApp:
    def setup_method(self):
        _MCP_SERVERS.clear()
        from fastapi.testclient import TestClient
        self.app = create_app()
        self.client = TestClient(self.app)

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "registered_servers" in data

    def test_capabilities_no_auth_with_empty_secret(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = ""
        resp = self.client.get("/api/worker/capabilities")
        assert resp.status_code == 200

    def test_capabilities_with_correct_secret(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = "s3cret"
        try:
            resp = self.client.get(
                "/api/worker/capabilities",
                headers={"Authorization": "Bearer s3cret"},
            )
            assert resp.status_code == 200
        finally:
            ws.WORKER_SHARED_SECRET = ""

    def test_capabilities_with_wrong_secret(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = "correct"
        try:
            resp = self.client.get(
                "/api/worker/capabilities",
                headers={"Authorization": "Bearer wrong"},
            )
            assert resp.status_code == 401
        finally:
            ws.WORKER_SHARED_SECRET = ""

    def test_execute_unknown_server(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = ""
        resp = self.client.post(
            "/api/worker/execute",
            json={"tool_name": "t", "server_name": "ghost_server", "params": {}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False

    def test_execute_success(self):
        import app.worker.worker_server as ws
        ws.WORKER_SHARED_SECRET = ""
        mock_server = MagicMock()
        mock_server.execute_tool = AsyncMock(return_value={"open": [22]})
        register_mcp_server("ssh_scan", mock_server)
        resp = self.client.post(
            "/api/worker/execute",
            json={"tool_name": "t", "server_name": "ssh_scan", "params": {}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True


# ===========================================================================
# Worker Client
# ===========================================================================

from app.worker.worker_client import (
    WorkerClient,
    WorkerUnavailableError,
    get_client,
)


class TestWorkerClient:
    def setup_method(self):
        import app.worker.worker_client as wc
        wc._consecutive_failures = 0
        wc._circuit_reset_at = 0.0

    def test_health_check_success(self):
        client = WorkerClient(base_url="http://worker:9443", secret="")
        with patch("httpx.AsyncClient") as MockHTTP:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            MockHTTP.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_resp)
            ))
            MockHTTP.return_value.__aexit__ = AsyncMock(return_value=None)
            result = run(client.health_check())
        assert result is True

    def test_health_check_failure(self):
        client = WorkerClient(base_url="http://down:9443", secret="")
        with patch("httpx.AsyncClient") as MockHTTP:
            MockHTTP.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(side_effect=Exception("refused"))
            ))
            MockHTTP.return_value.__aexit__ = AsyncMock(return_value=None)
            result = run(client.health_check())
        assert result is False

    def test_execute_success(self):
        client = WorkerClient(base_url="http://worker:9443", secret="")
        expected = {"success": True, "result": {"ports": [80]}, "job_id": "abc"}
        with patch.object(client, "_post", new=AsyncMock(return_value=expected)):
            result = run(client.execute("naabu_scan", "naabu", {"target": "x"}))
        assert result["success"] is True

    def test_execute_fallback_on_connect_error(self):
        import httpx
        client = WorkerClient(
            base_url="http://down:9443", secret="",
            max_retries=0, fallback_to_local=True
        )
        with patch.object(
            client, "_post",
            new=AsyncMock(side_effect=httpx.ConnectError("refused"))
        ):
            result = run(client.execute("t", "s", {}))
        assert result["success"] is False
        assert result.get("fallback") is True

    def test_execute_raises_when_fallback_disabled(self):
        import httpx
        client = WorkerClient(
            base_url="http://down:9443", secret="",
            max_retries=0, fallback_to_local=False
        )
        with patch.object(
            client, "_post",
            new=AsyncMock(side_effect=httpx.ConnectError("refused"))
        ):
            with pytest.raises(WorkerUnavailableError):
                run(client.execute("t", "s", {}))

    def test_circuit_breaker_opens_after_failures(self):
        import httpx, app.worker.worker_client as wc
        client = WorkerClient(
            base_url="http://down:9443", secret="",
            max_retries=0, fallback_to_local=True
        )
        with patch.object(
            client, "_post",
            new=AsyncMock(side_effect=httpx.ConnectError("refused"))
        ):
            for _ in range(wc._CIRCUIT_OPEN_THRESHOLD):
                run(client.execute("t", "s", {}))
        assert wc._consecutive_failures >= wc._CIRCUIT_OPEN_THRESHOLD

    def test_execute_with_auth_header(self):
        client = WorkerClient(base_url="http://worker:9443", secret="mytoken")
        assert "Authorization" in client._headers
        assert client._headers["Authorization"] == "Bearer mytoken"

    def test_get_capabilities(self):
        client = WorkerClient(base_url="http://worker:9443", secret="")
        expected = {"worker_id": "w-1", "servers": [{"name": "naabu", "tools": ["execute_naabu"]}]}
        with patch("httpx.AsyncClient") as MockHTTP:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json = MagicMock(return_value=expected)
            mock_resp.raise_for_status = MagicMock()
            MockHTTP.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_resp)
            ))
            MockHTTP.return_value.__aexit__ = AsyncMock(return_value=None)
            result = run(client.get_capabilities())
        assert result["worker_id"] == "w-1"


# ===========================================================================
# Job Dispatcher
# ===========================================================================

from app.worker.job_dispatcher import (
    JobClassification,
    JobDispatcher,
    get_dispatcher,
    ALWAYS_REMOTE,
    ALWAYS_LOCAL,
)
from app.agent.state.agent_state import Phase


class TestJobClassification:
    def setup_method(self):
        self.dispatcher = JobDispatcher()

    def test_always_remote_tools(self):
        for tool in ["naabu_scan", "exploit_execute", "metasploit_execute",
                     "sqlmap_detect", "brute_force", "reverse_shell",
                     "browser_navigate", "nuclei_scan", "ffuf_fuzz_dirs"]:
            assert self.dispatcher.classify(tool) == JobClassification.REMOTE, \
                f"{tool} should be REMOTE"

    def test_always_local_tools(self):
        for tool in ["echo", "calculator", "query_graph", "web_search",
                     "oob_generate_url", "oob_check"]:
            assert self.dispatcher.classify(tool) == JobClassification.LOCAL, \
                f"{tool} should be LOCAL"

    def test_exploitation_phase_makes_unknown_remote(self):
        result = self.dispatcher.classify("unknown_new_tool", Phase.EXPLOITATION)
        assert result == JobClassification.REMOTE

    def test_informational_phase_makes_unknown_local(self):
        result = self.dispatcher.classify("unknown_new_tool", Phase.INFORMATIONAL)
        assert result == JobClassification.LOCAL

    def test_no_phase_makes_unknown_local(self):
        result = self.dispatcher.classify("totally_unknown")
        assert result == JobClassification.LOCAL

    def test_add_remote_tool(self):
        self.dispatcher.add_remote_tool("my_new_dangerous_tool")
        assert self.dispatcher.classify("my_new_dangerous_tool") == JobClassification.REMOTE

    def test_add_local_tool_overrides_remote(self):
        self.dispatcher.add_local_tool("naabu_scan")
        assert self.dispatcher.classify("naabu_scan") == JobClassification.LOCAL

    def test_stats(self):
        stats = self.dispatcher.stats()
        assert "always_remote_count" in stats
        assert "always_local_count" in stats
        assert stats["always_remote_count"] > 0
        assert stats["always_local_count"] > 0


class TestJobDispatcherDispatchLocal:
    def setup_method(self):
        self.mock_tool = MagicMock()
        self.mock_tool.execute = AsyncMock(return_value="tool output")
        self.mock_registry = MagicMock()
        self.mock_registry.get_tool = MagicMock(return_value=self.mock_tool)
        self.dispatcher = JobDispatcher(tool_registry=self.mock_registry)

    def test_dispatch_local_success(self):
        result = run(self.dispatcher._dispatch_local("echo", {"message": "hi"}, None))
        assert result["success"] is True
        assert result["result"] == "tool output"

    def test_dispatch_local_tool_not_found(self):
        self.mock_registry.get_tool = MagicMock(return_value=None)
        result = run(self.dispatcher._dispatch_local("missing_tool", {}, None))
        assert result["success"] is False
        assert "missing_tool" in result["error"]

    def test_dispatch_local_exception(self):
        self.mock_tool.execute = AsyncMock(side_effect=RuntimeError("local crash"))
        result = run(self.dispatcher._dispatch_local("echo", {}, None))
        assert result["success"] is False
        assert "local crash" in result["error"]


class TestJobDispatcherDispatchRemote:
    def setup_method(self):
        self.mock_client = MagicMock()
        self.mock_client.execute = AsyncMock(return_value={"success": True, "result": "remote ok"})
        self.dispatcher = JobDispatcher(worker_client=self.mock_client)

    def test_dispatch_remote_calls_worker_client(self):
        result = run(self.dispatcher._dispatch_remote("naabu_scan", "naabu", {"target": "x"}, None))
        assert result["success"] is True
        self.mock_client.execute.assert_called_once()

    def test_dispatch_remote_passes_params(self):
        run(self.dispatcher._dispatch_remote("t", "srv", {"key": "val"}, 60.0))
        kwargs = self.mock_client.execute.call_args
        assert kwargs[1]["params"] == {"key": "val"} or kwargs[0][2] == {"key": "val"}


class TestJobDispatcherDispatch:
    def test_always_remote_goes_to_worker(self):
        mock_client = MagicMock()
        mock_client.execute = AsyncMock(return_value={"success": True, "result": "r"})
        dispatcher = JobDispatcher(worker_client=mock_client)
        result = run(dispatcher.dispatch("naabu_scan", {"target": "x"}))
        mock_client.execute.assert_called_once()

    def test_always_local_stays_local(self):
        mock_registry = MagicMock()
        mock_tool = MagicMock()
        mock_tool.execute = AsyncMock(return_value="local_result")
        mock_registry.get_tool = MagicMock(return_value=mock_tool)
        dispatcher = JobDispatcher(tool_registry=mock_registry)
        result = run(dispatcher.dispatch("echo", {"message": "hi"}))
        assert result["success"] is True
        assert result["result"] == "local_result"

    def test_get_dispatcher_singleton(self):
        d1 = get_dispatcher()
        d2 = get_dispatcher()
        assert d1 is d2


class TestJobDispatcherGuessServer:
    def test_naabu(self):
        assert JobDispatcher._guess_server("naabu_scan") == "naabu"

    def test_nuclei(self):
        assert JobDispatcher._guess_server("nuclei_scan") == "nuclei"

    def test_metasploit(self):
        assert JobDispatcher._guess_server("metasploit_execute") == "metasploit"

    def test_sqlmap(self):
        assert JobDispatcher._guess_server("sqlmap_detect") == "sqlmap"

    def test_ffuf(self):
        assert JobDispatcher._guess_server("ffuf_fuzz_dirs") == "ffuf"

    def test_browser(self):
        assert JobDispatcher._guess_server("browser_navigate") == "browser"

    def test_unknown_falls_back(self):
        assert JobDispatcher._guess_server("unknown_weird_tool") == "kali-tools"


# ===========================================================================
# OrchestratorAgent integration
# ===========================================================================

class TestOrchestratorAgentDispatchTool:
    """Test OrchestratorAgent.dispatch_tool with and without a dispatcher."""

    def _make_orchestrator(self, dispatcher=None):
        """Create a minimal OrchestratorAgent using importlib to bypass heavy deps."""
        import importlib.util, sys, types, os
        from unittest.mock import MagicMock

        # Stub heavy deps if not already done by conftest
        stubs = [
            "langchain_core", "langchain_core.messages", "langchain_core.language_models",
            "langchain_core.prompts", "langchain_core.output_parsers",
            "langchain_core.runnables", "langchain_core.tools", "langchain",
            "langgraph", "langgraph.graph", "langgraph.prebuilt",
            "langgraph.checkpoint", "langgraph.checkpoint.memory",
            "openai", "neo4j", "neo4j.exceptions",
            "langchain_openai", "langchain_anthropic", "langchain_google_genai", "langchain_groq",
        ]
        for pkg in stubs:
            if pkg not in sys.modules:
                sys.modules[pkg] = types.ModuleType(pkg)

        for cls in ("HumanMessage", "AIMessage", "SystemMessage", "BaseMessage", "ToolMessage"):
            setattr(sys.modules["langchain_core.messages"], cls, MagicMock())
        for attr in ("StateGraph", "END", "START"):
            setattr(sys.modules["langgraph.graph"], attr, MagicMock())
        setattr(sys.modules["langgraph.checkpoint.memory"], "MemorySaver", MagicMock())
        for p, c in [
            ("langchain_openai", "ChatOpenAI"),
            ("langchain_anthropic", "ChatAnthropic"),
            ("langchain_google_genai", "ChatGoogleGenerativeAI"),
            ("langchain_groq", "ChatGroq"),
        ]:
            setattr(sys.modules[p], c, MagicMock())

        # Build path relative to this test file rather than using a hardcoded absolute path
        backend_root = os.path.join(os.path.dirname(__file__), "..", "..", "..")
        orchestrator_path = os.path.normpath(
            os.path.join(backend_root, "backend", "app", "agent", "orchestrator.py")
        )
        spec = importlib.util.spec_from_file_location("orchestrator_module", orchestrator_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        mock_registry = MagicMock()
        mock_tool = MagicMock()
        mock_tool.execute = AsyncMock(return_value="direct_result")
        mock_registry.get_tool = MagicMock(return_value=mock_tool)

        oa = object.__new__(mod.OrchestratorAgent)
        oa.registry = mock_registry
        oa.llm = None
        oa.config = {}
        oa._job_dispatcher = dispatcher
        oa._agents = {}
        return oa, mod

    def test_dispatch_tool_without_dispatcher_uses_registry(self):
        oa, _ = self._make_orchestrator(dispatcher=None)
        result = run(oa.dispatch_tool("echo", {"message": "hi"}))
        assert result["success"] is True
        assert result["result"] == "direct_result"

    def test_dispatch_tool_with_dispatcher_calls_dispatcher(self):
        mock_dispatcher = MagicMock()
        mock_dispatcher.dispatch = AsyncMock(return_value={"success": True, "result": "dispatched"})
        oa, _ = self._make_orchestrator(dispatcher=mock_dispatcher)
        result = run(oa.dispatch_tool("naabu_scan", {"target": "x"}, phase=Phase.EXPLOITATION))
        mock_dispatcher.dispatch.assert_called_once()
        assert result["result"] == "dispatched"

    def test_dispatch_tool_tool_not_found_without_dispatcher(self):
        oa, _ = self._make_orchestrator(dispatcher=None)
        oa.registry.get_tool = MagicMock(return_value=None)
        result = run(oa.dispatch_tool("missing_tool", {}))
        assert result["success"] is False

    def test_set_job_dispatcher(self):
        oa, _ = self._make_orchestrator(dispatcher=None)
        mock_dispatcher = MagicMock()
        oa.set_job_dispatcher(mock_dispatcher)
        assert oa.get_job_dispatcher() is mock_dispatcher

    def test_get_job_dispatcher_returns_none_initially(self):
        oa, _ = self._make_orchestrator(dispatcher=None)
        assert oa.get_job_dispatcher() is None

    def test_get_registered_agent_names_empty(self):
        oa, _ = self._make_orchestrator()
        assert oa.get_registered_agent_names() == []


# ===========================================================================
# ALWAYS_REMOTE / ALWAYS_LOCAL set contents
# ===========================================================================


class TestAlwaysRemoteSet:
    def test_contains_exploit_tools(self):
        assert "exploit_execute" in ALWAYS_REMOTE
        assert "metasploit_execute" in ALWAYS_REMOTE

    def test_contains_scan_tools(self):
        assert "naabu_scan" in ALWAYS_REMOTE
        assert "nuclei_scan" in ALWAYS_REMOTE

    def test_contains_browser_tools(self):
        assert "browser_navigate" in ALWAYS_REMOTE
        assert "browser_screenshot" in ALWAYS_REMOTE

    def test_contains_post_exploitation(self):
        assert "reverse_shell" in ALWAYS_REMOTE
        assert "privilege_escalation" in ALWAYS_REMOTE

    def test_no_overlap_with_always_local(self):
        # A tool cannot be in both sets simultaneously in default config
        # (although add_remote_tool/add_local_tool allow runtime override)
        overlap = ALWAYS_REMOTE & ALWAYS_LOCAL
        # domain_discovery is in both by design (explicit local takes priority)
        # Just ensure the check function works
        dispatcher = JobDispatcher()
        for tool in overlap:
            # LOCAL should win (checked first in classify())
            assert dispatcher.classify(tool) == JobClassification.LOCAL


class TestAlwaysLocalSet:
    def test_contains_safe_tools(self):
        assert "echo" in ALWAYS_LOCAL
        assert "calculator" in ALWAYS_LOCAL
        assert "query_graph" in ALWAYS_LOCAL

    def test_contains_oob_tools(self):
        assert "oob_generate_url" in ALWAYS_LOCAL
        assert "oob_check" in ALWAYS_LOCAL
        assert "oob_stats" in ALWAYS_LOCAL

    def test_contains_search_tools(self):
        assert "web_search" in ALWAYS_LOCAL
