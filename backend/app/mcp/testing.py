"""
MCP Testing Framework

Provides utilities for testing MCP servers without live network connections:

  - ``MCPServerTestClient``  — in-process ASGI test client wrapping TestClient
  - ``MockMCPServer``         — configurable mock for unit-testing tool callers
  - ``MCPProtocolValidator``  — validates JSON-RPC 2.0 + MCP compliance
  - ``assert_rpc_ok``         — assertion helper for successful RPC responses
  - ``assert_rpc_error``      — assertion helper for expected error responses
  - ``build_rpc_request``     — builds a JSON-RPC 2.0 request dict
  - ``ProtocolComplianceTestCase`` — reusable compliance test suite
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.mcp.base_server import MCPServer, MCPTool
from app.mcp.protocol import (
    JSONRPC_VERSION,
    METHOD_INITIALIZE,
    METHOD_TOOLS_CALL,
    METHOD_TOOLS_LIST,
    ErrorCode,
)


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

def build_rpc_request(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    req_id: str = "1",
) -> Dict[str, Any]:
    """Return a minimal JSON-RPC 2.0 request dict."""
    req: Dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method, "id": req_id}
    if params is not None:
        req["params"] = params
    return req


def build_tools_call(tool_name: str, arguments: Dict[str, Any], req_id: str = "1") -> Dict[str, Any]:
    """Convenience: build a ``tools/call`` request dict."""
    return build_rpc_request(
        METHOD_TOOLS_CALL,
        params={"name": tool_name, "arguments": arguments},
        req_id=req_id,
    )


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def assert_rpc_ok(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assert that *response* is a successful JSON-RPC 2.0 response.

    Returns:
        The ``result`` value for further assertions.

    Raises:
        AssertionError: If the response contains an error or is malformed.
    """
    assert "error" not in response or response["error"] is None, (
        f"Expected success but got error: {response.get('error')}"
    )
    assert "result" in response, "Response is missing 'result' field"
    assert response.get("jsonrpc") == JSONRPC_VERSION, (
        f"Expected jsonrpc='{JSONRPC_VERSION}', got '{response.get('jsonrpc')}'"
    )
    return response["result"]


def assert_rpc_error(
    response: Dict[str, Any],
    expected_code: Optional[int] = None,
    message_contains: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Assert that *response* is a JSON-RPC error response.

    Args:
        response: The response dict to check
        expected_code: If given, assert ``error.code == expected_code``
        message_contains: If given, assert the substring appears in ``error.message``

    Returns:
        The ``error`` object for further assertions.
    """
    assert "error" in response and response["error"] is not None, (
        f"Expected an error response but got result: {response.get('result')}"
    )
    err = response["error"]
    if expected_code is not None:
        assert err.get("code") == expected_code, (
            f"Expected error code {expected_code}, got {err.get('code')}"
        )
    if message_contains is not None:
        msg = err.get("message", "")
        assert message_contains.lower() in msg.lower(), (
            f"Expected error message to contain '{message_contains}', got '{msg}'"
        )
    return err


# ---------------------------------------------------------------------------
# In-process test client
# ---------------------------------------------------------------------------

class MCPServerTestClient:
    """
    Thin wrapper around FastAPI's ``TestClient`` for synchronous testing of
    MCPServer subclasses — no live HTTP server needed.

    Usage::

        client = MCPServerTestClient(MyMCPServer())
        resp = client.rpc("tools/list")
        result = assert_rpc_ok(resp)
        assert len(result["tools"]) > 0
    """

    def __init__(self, server: MCPServer, api_key: Optional[str] = None) -> None:
        try:
            from fastapi.testclient import TestClient
        except ImportError:  # pragma: no cover
            raise ImportError("Install 'httpx' to use MCPServerTestClient: pip install httpx")
        self._server = server
        self._client = TestClient(server.app, raise_server_exceptions=False)
        self._api_key = api_key

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def rpc(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        req_id: str = "1",
    ) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the parsed response dict."""
        payload = build_rpc_request(method, params, req_id)
        resp = self._client.post("/rpc", json=payload, headers=self._headers())
        return resp.json()

    def tools_list(self) -> Dict[str, Any]:
        """Shortcut: call ``tools/list``."""
        return self.rpc(METHOD_TOOLS_LIST)

    def tools_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Shortcut: call ``tools/call``."""
        return self.rpc(
            METHOD_TOOLS_CALL,
            params={"name": tool_name, "arguments": arguments},
        )

    def initialize(self) -> Dict[str, Any]:
        """Shortcut: call ``initialize``."""
        return self.rpc(
            METHOD_INITIALIZE,
            params={
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "TestClient", "version": "0.1"},
                "capabilities": {},
            },
        )

    def health(self) -> Dict[str, Any]:
        """Call the ``/health`` endpoint."""
        return self._client.get("/health", headers=self._headers()).json()


# ---------------------------------------------------------------------------
# Mock MCP Server
# ---------------------------------------------------------------------------

class MockMCPServer(MCPServer):
    """
    Configurable mock MCP server for unit testing tool callers.

    Tools and their responses are injected at construction time::

        mock = MockMCPServer(
            tools=[MCPTool(name="scan", description="...", parameters={})],
            responses={"scan": {"success": True, "ports": [80, 443]}},
        )
    """

    def __init__(
        self,
        tools: Optional[List[MCPTool]] = None,
        responses: Optional[Dict[str, Any]] = None,
        raise_on: Optional[Dict[str, Exception]] = None,
        api_key: Optional[str] = None,
    ) -> None:
        """
        Args:
            tools: List of MCPTool definitions this mock exposes.
            responses: Dict mapping tool_name → return value from execute_tool.
            raise_on: Dict mapping tool_name → Exception to raise instead.
            api_key: Optional bearer token to enable authentication testing.
        """
        self._mock_tools = tools or []
        self._mock_responses = responses or {}
        self._raise_on = raise_on or {}
        self.call_log: List[Dict[str, Any]] = []
        super().__init__(name="MockServer", description="Mock MCP server for tests", port=9999, api_key=api_key)

    def get_tools(self) -> List[MCPTool]:
        return self._mock_tools

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.call_log.append({"tool": tool_name, "params": params})
        if tool_name in self._raise_on:
            raise self._raise_on[tool_name]
        if tool_name in self._mock_responses:
            resp = self._mock_responses[tool_name]
            return resp(params) if callable(resp) else resp
        return {"success": True, "result": f"mock result for {tool_name}"}

    def reset_log(self) -> None:
        """Clear the call log between tests."""
        self.call_log.clear()

    def was_called(self, tool_name: str) -> bool:
        """Return True if *tool_name* was called at least once."""
        return any(c["tool"] == tool_name for c in self.call_log)

    def call_count(self, tool_name: str) -> int:
        """Return the number of times *tool_name* was called."""
        return sum(1 for c in self.call_log if c["tool"] == tool_name)


# ---------------------------------------------------------------------------
# Protocol compliance validator
# ---------------------------------------------------------------------------

class MCPProtocolValidator:
    """
    Validates that an MCPServer is fully protocol-compliant.

    Runs a sequence of mandatory checks and reports pass/fail per item.
    """

    def __init__(self, test_client: MCPServerTestClient) -> None:
        self._client = test_client
        self._results: List[Dict[str, Any]] = []

    def _record(self, check_id: str, description: str, passed: bool, detail: str = "") -> None:
        self._results.append(
            {"id": check_id, "description": description, "passed": passed, "detail": detail}
        )

    def run_all(self) -> Dict[str, Any]:
        """Run all compliance checks and return a report dict."""
        self._results.clear()

        # 1. initialize handshake
        try:
            resp = self._client.initialize()
            result = assert_rpc_ok(resp)
            self._record("initialize", "initialize handshake", True)
            self._record(
                "protocol-version",
                "protocolVersion returned",
                "protocolVersion" in result,
            )
            self._record(
                "server-info",
                "serverInfo present in initialize response",
                "serverInfo" in result,
            )
        except Exception as exc:
            self._record("initialize", "initialize handshake", False, str(exc))

        # 2. tools/list
        try:
            resp = self._client.tools_list()
            result = assert_rpc_ok(resp)
            self._record("tools-list", "tools/list returns list", "tools" in result)
        except Exception as exc:
            self._record("tools-list", "tools/list returns list", False, str(exc))

        # 3. Unknown method returns -32601
        try:
            resp = self._client.rpc("nonexistent/method")
            assert_rpc_error(resp, expected_code=ErrorCode.METHOD_NOT_FOUND)
            self._record("method-not-found", "Unknown method → -32601", True)
        except Exception as exc:
            self._record("method-not-found", "Unknown method → -32601", False, str(exc))

        # 4. tools/call with missing name → -32602
        try:
            resp = self._client.rpc(METHOD_TOOLS_CALL, params={"arguments": {}})
            assert_rpc_error(resp, expected_code=ErrorCode.INVALID_PARAMS)
            self._record("invalid-params", "Missing 'name' → -32602", True)
        except Exception as exc:
            self._record("invalid-params", "Missing 'name' → -32602", False, str(exc))

        # 5. tools/call with unknown tool → -32001
        try:
            resp = self._client.tools_call("__does_not_exist__", {})
            assert_rpc_error(resp, expected_code=ErrorCode.TOOL_NOT_FOUND)
            self._record("tool-not-found", "Unknown tool → -32001", True)
        except Exception as exc:
            self._record("tool-not-found", "Unknown tool → -32001", False, str(exc))

        # 6. ping
        try:
            resp = self._client.rpc("ping")
            assert_rpc_ok(resp)
            self._record("ping", "ping method supported", True)
        except Exception as exc:
            self._record("ping", "ping method supported", False, str(exc))

        # 7. health endpoint
        try:
            health = self._client.health()
            self._record("health", "GET /health returns status", health.get("status") == "healthy")
        except Exception as exc:
            self._record("health", "GET /health returns status", False, str(exc))

        passed = [r for r in self._results if r["passed"]]
        failed = [r for r in self._results if not r["passed"]]
        return {
            "total": len(self._results),
            "passed": len(passed),
            "failed": len(failed),
            "items": self._results,
        }

    @property
    def all_passed(self) -> bool:
        """True if every compliance check passed."""
        return all(r["passed"] for r in self._results)


# ---------------------------------------------------------------------------
# Reusable protocol compliance test case (for pytest)
# ---------------------------------------------------------------------------

class ProtocolComplianceTestCase:
    """
    Mix-in providing a ``test_protocol_compliance`` method suitable for
    use with any pytest test class.

    Subclasses must implement ``make_server()`` returning an MCPServer
    that has at least one tool registered.

    Example::

        class TestNaabuCompliance(ProtocolComplianceTestCase):
            def make_server(self):
                return NaabuServer()
    """

    def make_server(self) -> MCPServer:  # pragma: no cover
        raise NotImplementedError

    def test_protocol_compliance(self) -> None:
        """Assert full MCP protocol compliance for the server under test."""
        server = self.make_server()
        client = MCPServerTestClient(server)
        validator = MCPProtocolValidator(client)
        report = validator.run_all()
        failed = [r for r in report["items"] if not r["passed"]]
        assert not failed, (
            f"Protocol compliance failures ({len(failed)}/{report['total']}):\n"
            + "\n".join(f"  [{r['id']}] {r['description']}: {r.get('detail', '')}" for r in failed)
        )
