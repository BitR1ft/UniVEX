"""
Tests for Week 2 Betterment Plan — ffuf Web Fuzzing

Coverage:
  - FfufServer MCP server (fuzz_dirs, fuzz_files, fuzz_params)
  - Input validation (URL, allow_internal, rate capping)
  - Output normalisation (_normalise_endpoint, _sort_endpoints)
  - WORDLIST_MAP registry
  - FfufFuzzDirsTool / FfufFuzzFilesTool / FfufFuzzParamsTool adapters
  - GraphIngestion.ingest_ffuf_results()
  - ToolRegistry registration of ffuf tools
  - AttackPathRouter WEB_APP_ATTACK includes ffuf
  - AttackPathRouter classifies ffuf/directory keywords to WEB_APP_ATTACK
"""

from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.ffuf_tool import (
    FfufFuzzDirsTool,
    FfufFuzzFilesTool,
    FfufFuzzParamsTool,
    _sort_endpoints,
)
from app.mcp.servers.ffuf_server import (
    WORDLIST_MAP,
    FfufServer,
    _is_internal,
    _normalise_endpoint,
    _validate_url,
)


# ===========================================================================
# Helpers
# ===========================================================================


def make_ffuf_hit(
    fuzz_value: str = "admin",
    status: int = 200,
    length: int = 1024,
    words: int = 50,
    redirect: str = "",
) -> Dict[str, Any]:
    return {
        "input": {"FUZZ": fuzz_value},
        "status": status,
        "length": length,
        "words": words,
        "redirectlocation": redirect,
    }


def make_ffuf_json_output(hits: list) -> str:
    return json.dumps({"results": hits})


def _make_mock_ffuf_client(
    tool_name: str = "fuzz_dirs",
    results: list = None,
    success: bool = True,
    error: str = "",
) -> MagicMock:
    """Return a mock MCPClient that returns canned ffuf data."""
    results = results or []

    async def call_tool(name, params):
        if not success:
            return {"success": False, "error": error, "url": params.get("url", "")}
        return {
            "success": True,
            "url": params.get("url", ""),
            "wordlist": params.get("wordlist", "common"),
            "results": results,
            "total_found": len(results),
        }

    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


# ===========================================================================
# FfufServer — _is_internal
# ===========================================================================


class TestIsInternal:
    def test_localhost(self):
        assert _is_internal("localhost") is True

    def test_loopback_ip(self):
        assert _is_internal("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert _is_internal("::1") is True

    def test_rfc1918_10(self):
        assert _is_internal("10.10.10.10") is True

    def test_rfc1918_192(self):
        assert _is_internal("192.168.1.1") is True

    def test_rfc1918_172(self):
        assert _is_internal("172.16.0.1") is True

    def test_public_ip(self):
        assert _is_internal("8.8.8.8") is False

    def test_public_hostname(self):
        assert _is_internal("example.com") is False


# ===========================================================================
# FfufServer — _validate_url
# ===========================================================================


class TestValidateUrl:
    def test_valid_http(self):
        _validate_url("http://example.com/", allow_internal=False)

    def test_valid_https(self):
        _validate_url("https://example.com/", allow_internal=False)

    def test_missing_scheme_raises(self):
        with pytest.raises(ValueError, match="http://"):
            _validate_url("example.com", allow_internal=False)

    def test_internal_blocked_by_default(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_url("http://10.10.10.10/", allow_internal=False)

    def test_internal_allowed_with_flag(self):
        # Should not raise
        _validate_url("http://10.10.10.10/", allow_internal=True)

    def test_localhost_blocked(self):
        with pytest.raises(ValueError):
            _validate_url("http://localhost/admin", allow_internal=False)


# ===========================================================================
# FfufServer — _normalise_endpoint
# ===========================================================================


class TestNormaliseEndpoint:
    def test_path_gets_leading_slash(self):
        hit = make_ffuf_hit(fuzz_value="admin")
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["path"] == "/admin"

    def test_path_preserves_existing_slash(self):
        hit = make_ffuf_hit(fuzz_value="/admin")
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["path"] == "/admin"

    def test_status_code_preserved(self):
        hit = make_ffuf_hit(status=301)
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["status_code"] == 301

    def test_content_length(self):
        hit = make_ffuf_hit(length=2048)
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["content_length"] == 2048

    def test_discovered_by_is_ffuf(self):
        hit = make_ffuf_hit()
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["discovered_by"] == "ffuf"

    def test_method_is_get(self):
        hit = make_ffuf_hit()
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["method"] == "GET"

    def test_base_url_stored(self):
        hit = make_ffuf_hit()
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["base_url"] == "http://host/"

    def test_redirect_captured(self):
        hit = make_ffuf_hit(redirect="http://host/login")
        ep = _normalise_endpoint(hit, "http://host/")
        assert ep["redirect"] == "http://host/login"


# ===========================================================================
# FfufServer — WORDLIST_MAP
# ===========================================================================


class TestWordlistMap:
    def test_common_key_present(self):
        assert "common" in WORDLIST_MAP

    def test_raft_medium_key_present(self):
        assert "raft-medium" in WORDLIST_MAP

    def test_raft_large_key_present(self):
        assert "raft-large" in WORDLIST_MAP

    def test_api_endpoints_key_present(self):
        assert "api-endpoints" in WORDLIST_MAP

    def test_all_values_are_absolute_paths(self):
        for v in WORDLIST_MAP.values():
            assert v.startswith("/"), f"Wordlist path must be absolute: {v}"


# ===========================================================================
# FfufServer — tool definitions
# ===========================================================================


class TestFfufServerToolDefinitions:
    def setup_method(self):
        self.server = FfufServer()

    def test_three_tools_registered(self):
        tools = self.server.get_tools()
        names = [t.name for t in tools]
        assert "fuzz_dirs" in names
        assert "fuzz_files" in names
        assert "fuzz_params" in names

    def test_fuzz_dirs_requires_url(self):
        tools = {t.name: t for t in self.server.get_tools()}
        required = tools["fuzz_dirs"].parameters.get("required", [])
        assert "url" in required

    def test_fuzz_files_requires_url(self):
        tools = {t.name: t for t in self.server.get_tools()}
        required = tools["fuzz_files"].parameters.get("required", [])
        assert "url" in required

    def test_fuzz_params_requires_url(self):
        tools = {t.name: t for t in self.server.get_tools()}
        required = tools["fuzz_params"].parameters.get("required", [])
        assert "url" in required

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            import asyncio
            asyncio.run(self.server.execute_tool("bad_tool", {}))

    def test_server_port_is_8004(self):
        assert self.server.port == 8004


# ===========================================================================
# FfufServer — _run_ffuf (mocked subprocess)
# ===========================================================================


class TestFfufServerRunFfuf:
    @pytest.mark.asyncio
    async def test_successful_run_returns_normalised_results(self):
        server = FfufServer()
        hits = [make_ffuf_hit("admin"), make_ffuf_hit("login", status=302)]
        fake_json = make_ffuf_json_output(hits)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(
                return_value=(fake_json.encode(), b"")
            )
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            result = await server._run_ffuf(
                ["ffuf", "-u", "http://host/FUZZ", "-w", "/wordlist.txt"],
                "http://host/",
                "common",
            )

        assert result["success"] is True
        assert result["total_found"] == 2
        paths = [r["path"] for r in result["results"]]
        assert "/admin" in paths
        assert "/login" in paths

    @pytest.mark.asyncio
    async def test_empty_output_returns_no_results(self):
        server = FfufServer()
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            result = await server._run_ffuf(
                ["ffuf", "-u", "http://host/FUZZ", "-w", "/wordlist.txt"],
                "http://host/",
                "common",
            )

        assert result["success"] is True
        assert result["total_found"] == 0

    @pytest.mark.asyncio
    async def test_ffuf_binary_not_found_returns_error(self):
        server = FfufServer()
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            result = await server._run_ffuf(
                ["ffuf", "-u", "http://host/FUZZ", "-w", "/wordlist.txt"],
                "http://host/",
                "common",
            )

        assert result["success"] is False
        assert "ffuf binary not found" in result["error"]

    @pytest.mark.asyncio
    async def test_invalid_json_returns_error(self):
        server = FfufServer()
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"not-json{", b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            result = await server._run_ffuf(
                ["ffuf", "-u", "http://host/FUZZ", "-w", "/wordlist.txt"],
                "http://host/",
                "common",
            )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_internal_target_blocked(self):
        server = FfufServer()
        result = await server._fuzz_dirs(
            {"url": "http://127.0.0.1/", "allow_internal": False}
        )
        assert result["success"] is False
        assert "internal" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_internal_target_allowed_with_flag(self):
        """allow_internal=True bypasses the IP check and reaches ffuf."""
        server = FfufServer()
        fake_json = make_ffuf_json_output([])
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(fake_json.encode(), b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            result = await server._fuzz_dirs(
                {"url": "http://10.10.10.10/", "allow_internal": True}
            )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_rate_capped_at_500(self):
        """Rates above 500 should be silently capped."""
        server = FfufServer()
        fake_json = make_ffuf_json_output([])
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(fake_json.encode(), b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            # pass rate=9999; the _fuzz_dirs method clamps it
            await server._fuzz_dirs(
                {"url": "http://example.com/", "rate": 9999, "allow_internal": False}
            )
            # Check that the ffuf command had "-rate", "500"
            cmd = mock_exec.call_args[0]
            rate_idx = cmd.index("-rate")
            assert cmd[rate_idx + 1] == "500"

    @pytest.mark.asyncio
    async def test_fuzz_params_post_requires_data(self):
        server = FfufServer()
        result = await server._fuzz_params(
            {"url": "http://example.com/", "method": "POST", "data": ""}
        )
        assert result["success"] is False
        assert "data" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_extensions_formatted_with_leading_dots(self):
        """fuzz_dirs must pass extensions as .php,.txt,.html not php,txt,html."""
        server = FfufServer()
        fake_json = make_ffuf_json_output([])
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(fake_json.encode(), b""))
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            await server._fuzz_dirs(
                {"url": "http://example.com/", "extensions": "php,txt,html"}
            )

            cmd = mock_exec.call_args[0]
            # Find the -e argument
            e_idx = cmd.index("-e")
            ext_value = cmd[e_idx + 1]
            # Each extension must start with a dot
            for ext in ext_value.split(","):
                assert ext.startswith("."), f"Extension '{ext}' must start with '.'"
            assert ext_value == ".php,.txt,.html"


# ===========================================================================
# _sort_endpoints helper
# ===========================================================================


class TestSortEndpoints:
    def test_2xx_before_3xx(self):
        eps = [
            {"path": "/redir", "status_code": 302},
            {"path": "/ok", "status_code": 200},
        ]
        sorted_eps = _sort_endpoints(eps)
        assert sorted_eps[0]["path"] == "/ok"
        assert sorted_eps[1]["path"] == "/redir"

    def test_3xx_before_other(self):
        eps = [
            {"path": "/error", "status_code": 500},
            {"path": "/redir", "status_code": 301},
        ]
        sorted_eps = _sort_endpoints(eps)
        assert sorted_eps[0]["path"] == "/redir"

    def test_alphabetical_within_tier(self):
        eps = [
            {"path": "/z-page", "status_code": 200},
            {"path": "/a-page", "status_code": 200},
        ]
        sorted_eps = _sort_endpoints(eps)
        assert sorted_eps[0]["path"] == "/a-page"

    def test_empty_list(self):
        assert _sort_endpoints([]) == []


# ===========================================================================
# FfufFuzzDirsTool adapter
# ===========================================================================


class TestFfufFuzzDirsTool:
    def test_tool_name(self):
        tool = FfufFuzzDirsTool()
        assert tool.name == "ffuf_fuzz_dirs"

    def test_description_mentions_directory(self):
        tool = FfufFuzzDirsTool()
        assert "director" in tool.description.lower() or "path" in tool.description.lower()

    def test_url_is_required(self):
        tool = FfufFuzzDirsTool()
        assert "url" in tool.metadata.parameters["required"]

    @pytest.mark.asyncio
    async def test_execute_returns_found_paths(self):
        tool = FfufFuzzDirsTool()
        hits = [
            {"path": "/admin", "status_code": 200, "content_length": 512,
             "word_count": 10, "redirect": "", "method": "GET",
             "base_url": "http://host/", "discovered_by": "ffuf"},
            {"path": "/login", "status_code": 302, "content_length": 0,
             "word_count": 0, "redirect": "/auth", "method": "GET",
             "base_url": "http://host/", "discovered_by": "ffuf"},
        ]
        tool._client = _make_mock_ffuf_client("fuzz_dirs", hits)
        result = await tool.execute(url="http://example.com/")
        assert "admin" in result
        assert "login" in result

    @pytest.mark.asyncio
    async def test_execute_no_results_message(self):
        tool = FfufFuzzDirsTool()
        tool._client = _make_mock_ffuf_client("fuzz_dirs", [])
        result = await tool.execute(url="http://example.com/")
        assert "No" in result or "not found" in result.lower() or "found" in result.lower()

    @pytest.mark.asyncio
    async def test_execute_error_returns_error_message(self):
        tool = FfufFuzzDirsTool()
        tool._client = _make_mock_ffuf_client("fuzz_dirs", success=False, error="binary not found")
        result = await tool.execute(url="http://example.com/")
        assert "error" in result.lower() or "binary" in result.lower()


# ===========================================================================
# FfufFuzzFilesTool adapter
# ===========================================================================


class TestFfufFuzzFilesTool:
    def test_tool_name(self):
        tool = FfufFuzzFilesTool()
        assert tool.name == "ffuf_fuzz_files"

    def test_default_extensions(self):
        tool = FfufFuzzFilesTool()
        props = tool.metadata.parameters["properties"]
        assert props["extensions"]["default"] == "php,txt,html"

    @pytest.mark.asyncio
    async def test_execute_returns_files(self):
        tool = FfufFuzzFilesTool()
        hits = [
            {"path": "/config.php", "status_code": 200, "content_length": 100,
             "word_count": 5, "redirect": "", "method": "GET",
             "base_url": "http://host/", "discovered_by": "ffuf"},
        ]
        tool._client = _make_mock_ffuf_client("fuzz_files", hits)
        result = await tool.execute(url="http://example.com/")
        assert "config.php" in result


# ===========================================================================
# FfufFuzzParamsTool adapter
# ===========================================================================


class TestFfufFuzzParamsTool:
    def test_tool_name(self):
        tool = FfufFuzzParamsTool()
        assert tool.name == "ffuf_fuzz_params"

    def test_default_wordlist_is_api_endpoints(self):
        tool = FfufFuzzParamsTool()
        props = tool.metadata.parameters["properties"]
        assert props["wordlist"]["default"] == "api-endpoints"

    @pytest.mark.asyncio
    async def test_execute_returns_params(self):
        tool = FfufFuzzParamsTool()
        hits = [
            {"path": "/?id=test", "status_code": 200, "content_length": 200,
             "word_count": 20, "redirect": "", "method": "GET",
             "base_url": "http://host/", "discovered_by": "ffuf"},
        ]
        tool._client = _make_mock_ffuf_client("fuzz_params", hits)
        result = await tool.execute(url="http://example.com/?FUZZ=test")
        assert "200" in result


# ===========================================================================
# GraphIngestion.ingest_ffuf_results
# ===========================================================================


class TestIngestFfufResults:
    def _make_ingestion(self):
        from app.graph.ingestion import GraphIngestion

        mock_client = MagicMock()
        ingestion = GraphIngestion.__new__(GraphIngestion)
        ingestion.client = mock_client
        # Mock node handlers
        ingestion.endpoint_node = MagicMock()
        ingestion.endpoint_node.create = MagicMock(
            side_effect=lambda path, method, **kw: {"id": f"{method}:{path}"}
        )
        return ingestion

    def test_ingests_all_results(self):
        ingestion = self._make_ingestion()
        data = {
            "url": "http://host/",
            "results": [
                {"path": "/admin", "method": "GET", "base_url": "http://host/",
                 "status_code": 200, "content_length": 512, "discovered_by": "ffuf"},
                {"path": "/login", "method": "GET", "base_url": "http://host/",
                 "status_code": 302, "content_length": 0, "discovered_by": "ffuf"},
            ],
        }
        with patch("app.graph.relationships.link_baseurl_endpoint", return_value=True):
            stats = ingestion.ingest_ffuf_results(data)

        assert stats["endpoints"] == 2

    def test_skips_entries_without_path(self):
        ingestion = self._make_ingestion()
        data = {
            "url": "http://host/",
            "results": [{"method": "GET", "status_code": 200}],
        }
        with patch("app.graph.relationships.link_baseurl_endpoint", return_value=True):
            stats = ingestion.ingest_ffuf_results(data)

        assert stats["endpoints"] == 0

    def test_empty_results_returns_zero_stats(self):
        ingestion = self._make_ingestion()
        stats = ingestion.ingest_ffuf_results({"url": "http://host/", "results": []})
        assert stats["endpoints"] == 0
        assert stats["relationships"] == 0

    def test_discovered_by_ffuf_property_passed(self):
        ingestion = self._make_ingestion()
        data = {
            "url": "http://host/",
            "results": [
                {"path": "/admin", "method": "GET", "base_url": "http://host/",
                 "status_code": 200, "content_length": 0, "discovered_by": "ffuf"},
            ],
        }
        with patch("app.graph.relationships.link_baseurl_endpoint", return_value=True):
            ingestion.ingest_ffuf_results(data)

        # Confirm endpoint_node.create was called with discovered_by='ffuf'
        call_kwargs = ingestion.endpoint_node.create.call_args[1]
        assert call_kwargs.get("discovered_by") == "ffuf"


# ===========================================================================
# ToolRegistry — ffuf tools registered
# ===========================================================================


class TestToolRegistryFfuf:
    def _make_registry(self):
        from app.agent.tools.tool_registry import create_default_registry
        return create_default_registry()

    def test_ffuf_fuzz_dirs_registered(self):
        reg = self._make_registry()
        assert reg.get_tool("ffuf_fuzz_dirs") is not None

    def test_ffuf_fuzz_files_registered(self):
        reg = self._make_registry()
        assert reg.get_tool("ffuf_fuzz_files") is not None

    def test_ffuf_fuzz_params_registered(self):
        reg = self._make_registry()
        assert reg.get_tool("ffuf_fuzz_params") is not None

    def test_ffuf_tools_available_in_informational(self):
        reg = self._make_registry()
        tools = reg.get_tools_for_phase(Phase.INFORMATIONAL)
        assert "ffuf_fuzz_dirs" in tools
        assert "ffuf_fuzz_files" in tools
        assert "ffuf_fuzz_params" in tools

    def test_ffuf_tools_available_in_exploitation(self):
        reg = self._make_registry()
        tools = reg.get_tools_for_phase(Phase.EXPLOITATION)
        assert "ffuf_fuzz_dirs" in tools

    def test_ffuf_tools_not_available_in_post_exploitation(self):
        reg = self._make_registry()
        tools = reg.get_tools_for_phase(Phase.POST_EXPLOITATION)
        assert "ffuf_fuzz_dirs" not in tools


# ===========================================================================
# AttackPathRouter — ffuf integration
# ===========================================================================


class TestAttackPathRouterFfuf:
    def setup_method(self):
        self.router = AttackPathRouter()

    def test_ffuf_in_web_app_attack_tools(self):
        tools = self.router.get_required_tools(AttackCategory.WEB_APP_ATTACK)
        assert "ffuf" in tools

    def test_fuzz_keyword_classifies_web_app(self):
        result = self.router.classify_intent("fuzz the web application for hidden directories")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_ffuf_keyword_classifies_web_app(self):
        result = self.router.classify_intent("run ffuf to discover hidden paths")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_gobuster_keyword_classifies_web_app(self):
        result = self.router.classify_intent("use gobuster to enumerate directories")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_directory_keyword_classifies_web_app(self):
        result = self.router.classify_intent("discover hidden directory on the web server")
        assert result == AttackCategory.WEB_APP_ATTACK
