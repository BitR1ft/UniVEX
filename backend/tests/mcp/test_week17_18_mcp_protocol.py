"""
Tests for Week 17 & 18 — MCP Protocol Implementation + Tool Server Implementation.

Week 17:
            MCPProtocolValidator, ProtocolComplianceTestCase

Week 18:
"""

import asyncio
import pytest
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

# MCP core
from app.mcp.base_server import (
    MCPServer,
    MCPTool,
    MCPRequest,
    MCPResponse,
    ToolRegistry,
    _RateLimiter,
    _error_response,
    _make_error,
)
from app.mcp.protocol import (
    ErrorCode,
    JSONRPC_VERSION,
    MCP_PROTOCOL_VERSION,
    COMPLIANCE_CHECKLIST,
    InitializeResult,
    ToolCallResult,
    get_compliance_report,
    ClientInfo,
    ServerInfo,
    ServerCapabilities,
)
from app.mcp.testing import (
    MCPServerTestClient,
    MockMCPServer,
    MCPProtocolValidator,
    ProtocolComplianceTestCase,
    assert_rpc_ok,
    assert_rpc_error,
    build_rpc_request as build_req,
)
from app.mcp.phase_control import (
    PhaseAccessController,
    PhaseRestrictionMiddleware,
    get_phase_permissions,
    validate_tool_phase,
    PHASE_PERMISSIONS,
    ALL_TOOLS,
)
from app.mcp.servers.graph_server import GraphQueryServer
from app.mcp.servers.web_search_server import WebSearchServer
from app.mcp.servers.naabu_server import NaabuServer
from app.mcp.servers.nuclei_server import NucleiServer
from app.mcp.servers.curl_server import CurlServer
from app.mcp.servers.metasploit_server import MetasploitServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_server(tools=None, responses=None, raise_on=None) -> MockMCPServer:
    """Build a MockMCPServer with a single default tool if none given."""
    if tools is None:
        tools = [
            MCPTool(
                name="echo",
                description="Echo input back",
                parameters={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            )
        ]
    if responses is None:
        responses = {"echo": lambda p: {"success": True, "output": p.get("text", "")}}
    return MockMCPServer(tools=tools, responses=responses, raise_on=raise_on or {})


# ===========================================================================
# ===========================================================================

class TestDay106Protocol:
    def test_jsonrpc_version_constant(self):
        assert JSONRPC_VERSION == "2.0"

    def test_mcp_protocol_version(self):
        assert MCP_PROTOCOL_VERSION == "2024-11-05"

    def test_error_codes_standard(self):
        assert ErrorCode.PARSE_ERROR == -32700
        assert ErrorCode.INVALID_REQUEST == -32600
        assert ErrorCode.METHOD_NOT_FOUND == -32601
        assert ErrorCode.INVALID_PARAMS == -32602
        assert ErrorCode.INTERNAL_ERROR == -32603

    def test_error_codes_application(self):
        assert ErrorCode.TOOL_EXECUTION_ERROR == -32000
        assert ErrorCode.TOOL_NOT_FOUND == -32001
        assert ErrorCode.PERMISSION_DENIED == -32002
        assert ErrorCode.RATE_LIMITED == -32003
        assert ErrorCode.TOOL_TIMEOUT == -32004
        assert ErrorCode.SCHEMA_VALIDATION == -32005

    def test_error_code_messages(self):
        msg = ErrorCode.message(ErrorCode.PARSE_ERROR)
        assert "parse" in msg.lower()

    def test_compliance_checklist_has_10_items(self):
        assert len(COMPLIANCE_CHECKLIST) >= 10

    def test_compliance_checklist_all_pass(self):
        report = get_compliance_report()
        assert report["failed"] == 0
        assert report["passed"] == report["total"]

    def test_compliance_report_structure(self):
        report = get_compliance_report()
        assert "total" in report
        assert "passed" in report
        assert "failed" in report
        assert "items" in report

    def test_initialize_result_model(self):
        result = InitializeResult(
            server_info=ServerInfo(name="Test"),
            capabilities=ServerCapabilities(),
        )
        assert result.protocol_version == MCP_PROTOCOL_VERSION

    def test_tool_call_result_success(self):
        r = ToolCallResult.success("hello")
        assert r.is_error is False
        assert r.content[0].text == "hello"

    def test_tool_call_result_error(self):
        r = ToolCallResult.error("failed")
        assert r.is_error is True
        assert r.content[0].text == "failed"


# ===========================================================================
# ===========================================================================

class TestDay107InitializeHandshake:
    def setup_method(self):
        self.server = _make_mock_server()
        self.client = MCPServerTestClient(self.server)

    def test_initialize_returns_protocol_version(self):
        resp = self.client.initialize()
        result = assert_rpc_ok(resp)
        assert result["protocolVersion"] == "2024-11-05"

    def test_initialize_returns_server_info(self):
        resp = self.client.initialize()
        result = assert_rpc_ok(resp)
        assert "serverInfo" in result
        assert "name" in result["serverInfo"]

    def test_initialize_returns_capabilities(self):
        resp = self.client.initialize()
        result = assert_rpc_ok(resp)
        assert "capabilities" in result

    def test_ping_supported(self):
        resp = self.client.rpc("ping")
        result = assert_rpc_ok(resp)
        assert result is not None

    def test_mcp_client_default_api_key_none(self):
        from app.mcp.base_server import MCPClient
        c = MCPClient("http://localhost:9000")
        assert c._api_key is None

    def test_mcp_client_stores_api_key(self):
        from app.mcp.base_server import MCPClient
        c = MCPClient("http://localhost:9000", api_key="secret")
        assert c._api_key == "secret"

    def test_mcp_client_headers_without_key(self):
        from app.mcp.base_server import MCPClient
        c = MCPClient("http://localhost:9000")
        headers = c._headers()
        assert "Authorization" not in headers

    def test_mcp_client_headers_with_key(self):
        from app.mcp.base_server import MCPClient
        c = MCPClient("http://localhost:9000", api_key="my-token")
        headers = c._headers()
        assert headers["Authorization"] == "Bearer my-token"


# ===========================================================================
# ===========================================================================

class TestDay108ToolRegistry:
    def test_register_and_get(self):
        reg = ToolRegistry()
        tool = MCPTool(name="t1", description="test", parameters={})
        reg.register(tool)
        assert reg.get("t1") == tool

    def test_get_nonexistent_returns_none(self):
        reg = ToolRegistry()
        assert reg.get("missing") is None

    def test_list_sorted_by_name(self):
        reg = ToolRegistry()
        for name in ["c", "a", "b"]:
            reg.register(MCPTool(name=name, description="d", parameters={}))
        names = [t.name for t in reg.list()]
        assert names == ["a", "b", "c"]

    def test_names_returns_set(self):
        reg = ToolRegistry()
        reg.register(MCPTool(name="x", description="d", parameters={}))
        assert "x" in reg.names()

    def test_overwrite_existing_tool(self):
        reg = ToolRegistry()
        reg.register(MCPTool(name="t", description="v1", parameters={}))
        reg.register(MCPTool(name="t", description="v2", parameters={}))
        assert reg.get("t").description == "v2"

    def test_tools_list_endpoint(self):
        server = _make_mock_server()
        tc = MCPServerTestClient(server)
        resp = tc.tools_list()
        result = assert_rpc_ok(resp)
        assert "tools" in result
        assert len(result["tools"]) >= 1

    def test_tool_inputSchema_exposed(self):
        server = _make_mock_server()
        tc = MCPServerTestClient(server)
        resp = tc.tools_list()
        result = assert_rpc_ok(resp)
        tool = result["tools"][0]
        assert "inputSchema" in tool


# ===========================================================================
# ===========================================================================

class TestDay109RequestRouting:
    def setup_method(self):
        self.server = _make_mock_server()
        self.client = MCPServerTestClient(self.server)

    def test_tools_call_success(self):
        resp = self.client.tools_call("echo", {"text": "hello"})
        result = assert_rpc_ok(resp)
        assert result["success"] is True

    def test_tools_call_missing_name_param(self):
        resp = self.client.rpc("tools/call", params={"arguments": {}})
        assert_rpc_error(resp, expected_code=ErrorCode.INVALID_PARAMS)

    def test_tools_call_no_params(self):
        resp = self.client.rpc("tools/call")
        assert_rpc_error(resp, expected_code=ErrorCode.INVALID_PARAMS)

    def test_tools_call_missing_required_arg(self):
        # 'text' is required for echo; omitting it should fail validation
        resp = self.client.tools_call("echo", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_tools_call_unknown_tool(self):
        resp = self.client.tools_call("nonexistent", {"x": "y"})
        assert_rpc_error(resp, expected_code=ErrorCode.TOOL_NOT_FOUND)

    def test_unknown_method_returns_method_not_found(self):
        resp = self.client.rpc("unknown/method")
        assert_rpc_error(resp, expected_code=ErrorCode.METHOD_NOT_FOUND)

    def test_invalid_json_body_returns_parse_error(self):
        # TestClient normally validates bodies; simulate by using raw POST
        raw = self.client._client.post(
            "/rpc",
            content=b"{ invalid json }",
            headers={"Content-Type": "application/json"},
        )
        data = raw.json()
        assert "error" in data

    def test_type_mismatch_in_params(self):
        # echo.text is "string" — passing an integer should fail validation
        resp = self.client.tools_call("echo", {"text": 42})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_enum_validation(self):
        tool = MCPTool(
            name="mode_tool",
            description="Mode test",
            parameters={
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["a", "b"]},
                },
                "required": ["mode"],
            },
        )
        server = MockMCPServer(tools=[tool], responses={"mode_tool": {"success": True}})
        tc = MCPServerTestClient(server)
        resp = tc.tools_call("mode_tool", {"mode": "c"})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)


# ===========================================================================
# ===========================================================================

class TestDay110ErrorHandling:
    def test_make_error_structure(self):
        err = _make_error(-32000, "fail")
        assert err["code"] == -32000
        assert err["message"] == "fail"
        assert "data" not in err

    def test_make_error_with_data(self):
        err = _make_error(-32000, "fail", data={"detail": "bad"})
        assert err["data"]["detail"] == "bad"

    def test_error_response_structure(self):
        resp = _error_response(-32001, "not found", req_id="42")
        assert resp.error["code"] == -32001
        assert resp.id == "42"

    def test_tool_exception_returns_tool_execution_error(self):
        server = MockMCPServer(
            tools=[MCPTool(name="fail_tool", description="Fails", parameters={})],
            raise_on={"fail_tool": RuntimeError("boom")},
        )
        tc = MCPServerTestClient(server)
        resp = tc.tools_call("fail_tool", {})
        assert_rpc_error(resp, expected_code=ErrorCode.TOOL_EXECUTION_ERROR)

    def test_permission_error_returns_permission_denied(self):
        server = MockMCPServer(
            tools=[MCPTool(name="perm_tool", description="PermFail", parameters={})],
            raise_on={"perm_tool": PermissionError("no access")},
        )
        tc = MCPServerTestClient(server)
        resp = tc.tools_call("perm_tool", {})
        assert_rpc_error(resp, expected_code=ErrorCode.PERMISSION_DENIED)

    def test_value_error_returns_invalid_params(self):
        server = MockMCPServer(
            tools=[MCPTool(name="val_tool", description="ValueError", parameters={})],
            raise_on={"val_tool": ValueError("bad value")},
        )
        tc = MCPServerTestClient(server)
        resp = tc.tools_call("val_tool", {})
        assert_rpc_error(resp, expected_code=ErrorCode.INVALID_PARAMS)


# ===========================================================================
# ===========================================================================

class TestDay111Security:
    def test_rate_limiter_allows_within_limit(self):
        rl = _RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert rl.is_allowed("client1") is True

    def test_rate_limiter_blocks_over_limit(self):
        rl = _RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            rl.is_allowed("client1")
        assert rl.is_allowed("client1") is False

    def test_rate_limiter_separate_clients(self):
        rl = _RateLimiter(max_requests=2, window_seconds=60)
        for _ in range(2):
            rl.is_allowed("a")
        # client b should still be allowed
        assert rl.is_allowed("b") is True

    def test_rate_limiter_reset(self):
        rl = _RateLimiter(max_requests=1, window_seconds=60)
        rl.is_allowed("x")
        assert rl.is_allowed("x") is False
        rl.reset("x")
        assert rl.is_allowed("x") is True

    def test_auth_enabled_rejects_no_header(self):
        server = MockMCPServer(
            tools=[MCPTool(name="t", description="d", parameters={})],
            api_key="secret123",
        )
        tc = MCPServerTestClient(server)
        resp = tc.rpc("tools/list")  # no auth header
        err = resp.get("error") or {}
        assert err.get("code") == ErrorCode.PERMISSION_DENIED

    def test_auth_enabled_rejects_wrong_key(self):
        server = MockMCPServer(
            tools=[MCPTool(name="t", description="d", parameters={})],
            api_key="secret123",
        )
        tc = MCPServerTestClient(server, api_key="wrongkey")
        resp = tc.rpc("tools/list")
        err = resp.get("error") or {}
        assert err.get("code") == ErrorCode.PERMISSION_DENIED

    def test_auth_enabled_allows_correct_key(self):
        server = MockMCPServer(
            tools=[MCPTool(name="t", description="d", parameters={})],
            api_key="secret123",
        )
        tc = MCPServerTestClient(server, api_key="secret123")
        resp = tc.tools_list()
        assert_rpc_ok(resp)

    def test_auth_disabled_allows_any_request(self):
        server = _make_mock_server()  # api_key=None
        tc = MCPServerTestClient(server)
        resp = tc.tools_list()
        assert_rpc_ok(resp)


# ===========================================================================
# ===========================================================================

class TestDay112TestingFramework:
    def test_mock_server_records_calls(self):
        server = _make_mock_server()
        tc = MCPServerTestClient(server)
        tc.tools_call("echo", {"text": "test"})
        assert server.was_called("echo")

    def test_mock_server_call_count(self):
        server = _make_mock_server()
        tc = MCPServerTestClient(server)
        for _ in range(3):
            tc.tools_call("echo", {"text": "x"})
        assert server.call_count("echo") == 3

    def test_mock_server_reset_log(self):
        server = _make_mock_server()
        tc = MCPServerTestClient(server)
        tc.tools_call("echo", {"text": "x"})
        server.reset_log()
        assert server.call_count("echo") == 0

    def test_assert_rpc_ok_passes(self):
        result = assert_rpc_ok({"jsonrpc": "2.0", "result": {"key": "value"}, "id": "1"})
        assert result["key"] == "value"

    def test_assert_rpc_ok_fails_on_error(self):
        with pytest.raises(AssertionError):
            assert_rpc_ok({"jsonrpc": "2.0", "error": {"code": -32000, "message": "fail"}, "id": "1"})

    def test_assert_rpc_error_passes(self):
        err = assert_rpc_error(
            {"jsonrpc": "2.0", "error": {"code": -32001, "message": "not found"}, "id": "1"},
            expected_code=-32001,
            message_contains="not found",
        )
        assert err["code"] == -32001

    def test_assert_rpc_error_fails_on_success(self):
        with pytest.raises(AssertionError):
            assert_rpc_error({"jsonrpc": "2.0", "result": {}, "id": "1"})

    def test_build_rpc_request(self):
        req = build_req("tools/list", req_id="42")
        assert req["jsonrpc"] == "2.0"
        assert req["method"] == "tools/list"
        assert req["id"] == "42"

    def test_protocol_validator_passes(self):
        server = _make_mock_server()
        tc = MCPServerTestClient(server)
        validator = MCPProtocolValidator(tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"Protocol failures: {failed}"

    def test_protocol_compliance_test_case(self):
        class _Case(ProtocolComplianceTestCase):
            def make_server(self):
                return _make_mock_server()
        _Case().test_protocol_compliance()


# ===========================================================================
# ===========================================================================

class TestDay113NaabuServer:
    def setup_method(self):
        self.server = NaabuServer()
        self.tc = MCPServerTestClient(self.server)

    def test_has_execute_naabu_tool(self):
        resp = self.tc.tools_list()
        result = assert_rpc_ok(resp)
        names = [t["name"] for t in result["tools"]]
        assert "execute_naabu" in names

    def test_execute_naabu_validates_target(self):
        resp = self.tc.tools_call("execute_naabu", {"target": "INVALID TARGET!!!"})
        result = resp.get("result", {})
        assert result.get("success") is False or "error" in result

    def test_execute_naabu_requires_target(self):
        resp = self.tc.tools_call("execute_naabu", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_naabu_protocol_compliance(self):
        validator = MCPProtocolValidator(self.tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"Naabu protocol failures: {failed}"


# ===========================================================================
# ===========================================================================

class TestDay114NucleiServer:
    def setup_method(self):
        self.server = NucleiServer()
        self.tc = MCPServerTestClient(self.server)

    def test_has_execute_nuclei_tool(self):
        resp = self.tc.tools_list()
        result = assert_rpc_ok(resp)
        names = [t["name"] for t in result["tools"]]
        assert "execute_nuclei" in names

    def test_execute_nuclei_requires_target(self):
        resp = self.tc.tools_call("execute_nuclei", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_nuclei_protocol_compliance(self):
        validator = MCPProtocolValidator(self.tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"Nuclei protocol failures: {failed}"


# ===========================================================================
# ===========================================================================

class TestDay115CurlServer:
    def setup_method(self):
        self.server = CurlServer()
        self.tc = MCPServerTestClient(self.server)

    def test_has_execute_curl_tool(self):
        resp = self.tc.tools_list()
        result = assert_rpc_ok(resp)
        names = [t["name"] for t in result["tools"]]
        assert "execute_curl" in names

    def test_execute_curl_requires_url(self):
        resp = self.tc.tools_call("execute_curl", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_curl_protocol_compliance(self):
        validator = MCPProtocolValidator(self.tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"Curl protocol failures: {failed}"


# ===========================================================================
# ===========================================================================

class TestDay116MetasploitServer:
    def setup_method(self):
        self.server = MetasploitServer()
        self.tc = MCPServerTestClient(self.server)

    def test_has_search_modules_tool(self):
        resp = self.tc.tools_list()
        result = assert_rpc_ok(resp)
        names = [t["name"] for t in result["tools"]]
        assert "search_modules" in names

    def test_search_modules_requires_query(self):
        resp = self.tc.tools_call("search_modules", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_metasploit_protocol_compliance(self):
        validator = MCPProtocolValidator(self.tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"Metasploit protocol failures: {failed}"


# ===========================================================================
# ===========================================================================

class TestDay117GraphQueryServer:
    def setup_method(self):
        self.server = GraphQueryServer()
        self.tc = MCPServerTestClient(self.server)

    def test_has_four_tools(self):
        resp = self.tc.tools_list()
        result = assert_rpc_ok(resp)
        names = {t["name"] for t in result["tools"]}
        assert "query_graph_cypher" in names
        assert "get_attack_surface" in names
        assert "find_attack_paths" in names
        assert "get_vulnerabilities" in names

    def test_query_graph_cypher_requires_params(self):
        resp = self.tc.tools_call("query_graph_cypher", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_query_graph_cypher_blocks_write_ops(self):
        resp = self.tc.tools_call(
            "query_graph_cypher",
            {"cypher": "DELETE n", "user_id": "u1", "project_id": "p1"},
        )
        result = resp.get("result", {})
        assert result.get("success") is False
        assert "write" in result.get("error", "").lower()

    def test_get_attack_surface_requires_project(self):
        resp = self.tc.tools_call("get_attack_surface", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_get_attack_surface_graceful_without_db(self):
        resp = self.tc.tools_call("get_attack_surface", {"user_id": "u1", "project_id": "p1"})
        result = resp.get("result", {})
        # Should fail gracefully (no real DB in test env)
        assert "success" in result

    def test_find_attack_paths_graceful_without_db(self):
        resp = self.tc.tools_call("find_attack_paths", {"user_id": "u1", "project_id": "p1"})
        result = resp.get("result", {})
        assert "success" in result

    def test_get_vulnerabilities_invalid_severity_blocked(self):
        resp = self.tc.tools_call(
            "get_vulnerabilities",
            {"user_id": "u1", "project_id": "p1", "severity": "INVALID_SEVERITY"},
        )
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_get_vulnerabilities_graceful_without_db(self):
        resp = self.tc.tools_call("get_vulnerabilities", {"user_id": "u1", "project_id": "p1"})
        result = resp.get("result", {})
        assert "success" in result

    def test_graph_protocol_compliance(self):
        validator = MCPProtocolValidator(self.tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"Graph server protocol failures: {failed}"


# ===========================================================================
# ===========================================================================

class TestDay118WebSearchServer:
    def setup_method(self):
        self.server = WebSearchServer(api_key=None)  # offline/stub mode
        self.tc = MCPServerTestClient(self.server)

    def test_has_four_tools(self):
        resp = self.tc.tools_list()
        result = assert_rpc_ok(resp)
        names = {t["name"] for t in result["tools"]}
        assert "web_search" in names
        assert "search_cve" in names
        assert "search_exploits" in names
        assert "enrich_technology" in names

    def test_web_search_requires_query(self):
        resp = self.tc.tools_call("web_search", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_web_search_stub_response(self):
        resp = self.tc.tools_call("web_search", {"query": "test search"})
        result = resp.get("result", {})
        assert result.get("success") is True
        assert "results" in result
        assert len(result["results"]) >= 1

    def test_search_cve_requires_cve_id(self):
        resp = self.tc.tools_call("search_cve", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_search_cve_stub_response(self):
        resp = self.tc.tools_call("search_cve", {"cve_id": "CVE-2024-1234"})
        result = resp.get("result", {})
        assert result.get("success") is True
        assert "cve_id" in result

    def test_search_exploits_requires_target(self):
        resp = self.tc.tools_call("search_exploits", {})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_search_exploits_stub_response(self):
        resp = self.tc.tools_call("search_exploits", {"target": "Apache Log4j"})
        result = resp.get("result", {})
        assert result.get("success") is True

    def test_enrich_technology_stub_response(self):
        resp = self.tc.tools_call("enrich_technology", {"technology": "nginx"})
        result = resp.get("result", {})
        assert result.get("success") is True

    def test_search_depth_enum_validation(self):
        resp = self.tc.tools_call("web_search", {"query": "test", "search_depth": "deep"})
        assert_rpc_error(resp, expected_code=ErrorCode.SCHEMA_VALIDATION)

    def test_web_search_protocol_compliance(self):
        validator = MCPProtocolValidator(self.tc)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, f"WebSearch protocol failures: {failed}"


# ===========================================================================
# ===========================================================================

class TestDay119PhaseRestriction:
    def test_all_phases_defined(self):
        for phase in ["recon", "scan", "exploit", "post"]:
            assert phase in PHASE_PERMISSIONS

    def test_recon_phase_allows_naabu(self):
        ctrl = PhaseAccessController("recon")
        assert ctrl.is_allowed("execute_naabu")

    def test_recon_phase_blocks_execute_module(self):
        ctrl = PhaseAccessController("recon")
        assert not ctrl.is_allowed("execute_module")

    def test_recon_phase_check_access_raises(self):
        ctrl = PhaseAccessController("recon")
        with pytest.raises(PermissionError):
            ctrl.check_access("execute_module")

    def test_exploit_phase_allows_execute_module(self):
        ctrl = PhaseAccessController("exploit")
        assert ctrl.is_allowed("execute_module")

    def test_exploit_phase_requires_approval(self):
        ctrl = PhaseAccessController("exploit")
        assert ctrl.requires_approval("execute_module")

    def test_scan_phase_allows_nuclei(self):
        ctrl = PhaseAccessController("scan")
        assert ctrl.is_allowed("execute_nuclei")

    def test_scan_phase_blocks_session_command(self):
        ctrl = PhaseAccessController("scan")
        assert not ctrl.is_allowed("session_command")

    def test_post_phase_allows_all_tools(self):
        ctrl = PhaseAccessController("post")
        for tool in ALL_TOOLS:
            assert ctrl.is_allowed(tool), f"post should allow {tool}"

    def test_invalid_phase_raises_value_error(self):
        with pytest.raises(ValueError):
            PhaseAccessController("invalid_phase")

    def test_get_access_report_structure(self):
        ctrl = PhaseAccessController("recon")
        report = ctrl.get_access_report()
        assert "phase" in report
        assert "allowed_tools" in report
        assert "require_approval_for" in report

    def test_validate_tool_phase_helper(self):
        assert validate_tool_phase("execute_naabu", "recon") is True
        assert validate_tool_phase("execute_module", "recon") is False

    def test_get_phase_permissions_single(self):
        perms = get_phase_permissions("recon")
        assert perms["phase"] == "recon"

    def test_get_phase_permissions_all(self):
        perms = get_phase_permissions()
        assert set(perms.keys()) == {"recon", "scan", "exploit", "post"}

    def test_get_phase_permissions_invalid_raises(self):
        with pytest.raises(ValueError):
            get_phase_permissions("unknown")

    def test_phase_restriction_middleware_wraps_server(self):
        import asyncio
        server = _make_mock_server()
        middleware = PhaseRestrictionMiddleware("recon")
        middleware.wrap(server)

        # Calling a blocked tool should raise PermissionError
        async def call_blocked():
            await server.execute_tool("execute_module", {})

        with pytest.raises(PermissionError):
            asyncio.run(call_blocked())

    def test_phase_restriction_middleware_allows_permitted(self):
        import asyncio
        # echo tool is not in ALL_TOOLS, so we need a server with a recon-allowed tool
        server = MockMCPServer(
            tools=[MCPTool(name="execute_naabu", description="port scan", parameters={})],
            responses={"execute_naabu": {"success": True, "ports": []}},
        )
        middleware = PhaseRestrictionMiddleware("recon")
        middleware.wrap(server)

        async def call_allowed():
            return await server.execute_tool("execute_naabu", {"target": "127.0.0.1"})

        result = asyncio.run(call_allowed())
        assert result["success"] is True

    def test_phase_restriction_middleware_unwrap(self):
        import asyncio
        server = MockMCPServer(
            tools=[MCPTool(name="execute_module", description="msf", parameters={})],
            responses={"execute_module": {"success": True}},
        )
        middleware = PhaseRestrictionMiddleware("recon")
        middleware.wrap(server)
        middleware.unwrap(server)

        # After unwrap, tool should execute without PermissionError
        async def call_after_unwrap():
            return await server.execute_tool("execute_module", {})

        result = asyncio.run(call_after_unwrap())
        assert result["success"] is True


# ===========================================================================
# ===========================================================================

class TestDay120NaabuCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return NaabuServer()


class TestDay120NucleiCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return NucleiServer()


class TestDay120CurlCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return CurlServer()


class TestDay120MetasploitCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return MetasploitServer()


class TestDay120GraphCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return GraphQueryServer()


class TestDay120WebSearchCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return WebSearchServer(api_key=None)


class TestDay120MockCompliance(ProtocolComplianceTestCase):
    def make_server(self):
        return _make_mock_server()


class TestDay120Documentation:
    """Verify all servers have sufficient tool documentation."""

    def _check_server_docs(self, server: MCPServer) -> None:
        tc = MCPServerTestClient(server)
        resp = tc.tools_list()
        result = assert_rpc_ok(resp)
        for tool in result["tools"]:
            assert len(tool["name"]) > 0, "Tool must have a non-empty name"
            assert len(tool["description"]) >= 20, (
                f"Tool '{tool['name']}' description is too short: '{tool['description']}'"
            )
            assert "inputSchema" in tool, f"Tool '{tool['name']}' missing inputSchema"

    def test_naabu_tool_docs(self):
        self._check_server_docs(NaabuServer())

    def test_nuclei_tool_docs(self):
        self._check_server_docs(NucleiServer())

    def test_curl_tool_docs(self):
        self._check_server_docs(CurlServer())

    def test_metasploit_tool_docs(self):
        self._check_server_docs(MetasploitServer())

    def test_graph_tool_docs(self):
        self._check_server_docs(GraphQueryServer())

    def test_web_search_tool_docs(self):
        self._check_server_docs(WebSearchServer(api_key=None))
