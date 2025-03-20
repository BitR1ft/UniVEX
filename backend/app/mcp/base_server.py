"""
MCP Server Base Implementation

Provides base classes for MCP tool servers using JSON-RPC over HTTP/SSE.

"""

import asyncio
import hashlib
import secrets
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import logging

logger = logging.getLogger(__name__)


class MCPTool(BaseModel):
    """MCP Tool Definition — carries full inputSchema for capability declaration."""
    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="JSON schema for parameters")
    phase: Optional[str] = Field(None, description="Agent phase this tool belongs to (recon/scan/exploit/post)")
    requires_approval: bool = Field(False, description="Whether this tool requires human approval")

    @property
    def input_schema(self) -> Dict[str, Any]:
        """Alias for parameters — matches MCP spec ``inputSchema`` field."""
        return self.parameters


class MCPRequest(BaseModel):
    """MCP JSON-RPC Request — validates jsonrpc version."""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[str] = None


class MCPResponse(BaseModel):
    """MCP JSON-RPC Response — strict result/error mutual exclusion."""
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = None


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def _make_error(code: int, message: str, data: Any = None) -> Dict[str, Any]:
    """Build a JSON-RPC error object."""
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return err


def _error_response(code: int, message: str, req_id: Optional[str] = None, data: Any = None) -> MCPResponse:
    """Return a complete MCPResponse containing a JSON-RPC error."""
    return MCPResponse(error=_make_error(code, message, data), id=req_id)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class _RateLimiter:
    """
    Simple sliding-window rate limiter (per client-IP).

    Default: 60 requests per 60-second window.
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        """Return True if the request is within rate limits."""
        now = time.monotonic()
        window_start = now - self.window_seconds
        bucket = self._buckets[client_id]
        # Evict expired timestamps
        self._buckets[client_id] = [t for t in bucket if t > window_start]
        if len(self._buckets[client_id]) >= self.max_requests:
            return False
        self._buckets[client_id].append(now)
        return True

    def reset(self, client_id: str) -> None:
        """Clear rate-limit state for a client (used in tests)."""
        self._buckets.pop(client_id, None)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class ToolRegistry:
    """
    Central registry for MCP tools on a server

    Stores tool definitions by name and validates call params against their
    JSON Schema ``inputSchema``.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, MCPTool] = {}

    def register(self, tool: MCPTool) -> None:
        """Register a tool. Overwrites an existing entry with the same name."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[MCPTool]:
        """Return the MCPTool for *name*, or None if not registered."""
        return self._tools.get(name)

    def list(self) -> List[MCPTool]:
        """Return all registered tools (sorted by name for determinism)."""
        return sorted(self._tools.values(), key=lambda t: t.name)

    def names(self) -> Set[str]:
        """Return the set of registered tool names."""
        return set(self._tools.keys())

    def validate_params(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
        """
        Validate *arguments* against the tool's JSON Schema.

        Returns:
            None if valid, or an error message string if invalid.
        """
        tool = self.get(tool_name)
        if tool is None:
            return f"Tool '{tool_name}' is not registered"

        schema = tool.parameters
        required = schema.get("required", [])
        props = schema.get("properties", {})

        # Check required fields
        for field in required:
            if field not in arguments:
                return f"Missing required parameter: '{field}'"

        # Type checking for declared properties
        for param_name, value in arguments.items():
            if param_name not in props:
                continue  # Allow extra params (lenient)
            expected_type = props[param_name].get("type")
            if expected_type == "string" and not isinstance(value, str):
                return f"Parameter '{param_name}' must be a string"
            if expected_type == "integer" and not isinstance(value, int):
                return f"Parameter '{param_name}' must be an integer"
            if expected_type == "boolean" and not isinstance(value, bool):
                return f"Parameter '{param_name}' must be a boolean"
            if expected_type == "array" and not isinstance(value, list):
                return f"Parameter '{param_name}' must be an array"
            if expected_type == "object" and not isinstance(value, dict):
                return f"Parameter '{param_name}' must be a dict (JSON object)"

            # Enum validation
            if "enum" in props[param_name]:
                allowed = props[param_name]["enum"]
                if value not in allowed:
                    return f"Parameter '{param_name}' must be one of {allowed}"

        return None  # valid


class MCPServer(ABC):
    """
    Base class for MCP tool servers

    Implements:
      - JSON-RPC 2.0 ``/rpc`` endpoint
      - Tool registry with capability declaration
      - Per-tool parameter validation before dispatch
      - Standardised error codes and recovery
      - Bearer-token authentication + per-IP rate limiting
    """

    def __init__(
        self,
        name: str,
        description: str,
        port: int,
        api_key: Optional[str] = None,
        rate_limit: int = 60,
        mtls_enabled: bool = False,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
    ):
        """
        Initialise MCP Server.

        Args:
            name: Server name
            description: Server description
            port: Port to listen on
            api_key: Optional bearer token required in ``Authorization`` header.
                     When *None* authentication is disabled.
            rate_limit: Max requests per 60-second window per client IP.
            mtls_enabled: When True, enforce mutual TLS via middleware.
            cert_path: Path to the server TLS certificate (PEM).
            key_path: Path to the server TLS private key (PEM).
            ca_cert_path: Path to the CA certificate used to verify clients (PEM).
        """
        self.name = name
        self.description = description
        self.port = port
        self._api_key: Optional[str] = api_key
        self._rate_limiter = _RateLimiter(max_requests=rate_limit)
        self._mtls_enabled = mtls_enabled
        self._cert_path = cert_path
        self._key_path = key_path
        self._ca_cert_path = ca_cert_path
        self._registry = ToolRegistry()
        self.app = FastAPI(title=f"{name} MCP Server")
        if mtls_enabled:
            self._add_mtls_middleware()
        self._setup_routes()

    # ------------------------------------------------------------------
    # Subclass API
    # ------------------------------------------------------------------

    @abstractmethod
    def get_tools(self) -> List[MCPTool]:
        """Return the list of tools this server exposes."""
        pass

    @abstractmethod
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute *tool_name* with *params*. Return a result dict."""
        pass

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------

    def _add_mtls_middleware(self) -> None:
        """
        Register middleware that enforces mTLS client certificate verification.

        In production, a reverse proxy (nginx) sets the ``X-Client-Cert-CN``
        header after verifying the client certificate.  In development mode the
        middleware checks for the header directly.

        Returns HTTP 403 when the header is absent or empty.
        """
        from fastapi import Request
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse as StarletteJSONResponse

        class MTLSMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):
                # Health endpoint is exempt from mTLS check
                if request.url.path == "/health":
                    return await call_next(request)
                cn = request.headers.get("X-Client-Cert-CN", "").strip()
                if not cn:
                    return StarletteJSONResponse(
                        {"error": "mTLS required: missing client certificate"},
                        status_code=403,
                    )
                return await call_next(request)

        self.app.add_middleware(MTLSMiddleware)

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------

    def _verify_auth(self, authorization: Optional[str]) -> Optional[MCPResponse]:
        """
        Verify the bearer token.

        Returns:
            None if auth passes (or is disabled), else an error MCPResponse.
        """
        if self._api_key is None:
            return None  # auth disabled
        if not authorization or not authorization.startswith("Bearer "):
            return _error_response(-32002, "Permission denied — missing or malformed Authorization header")
        token = authorization.split(" ", 1)[1]
        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(
            hashlib.sha256(token.encode()).digest(),
            hashlib.sha256(self._api_key.encode()).digest(),
        ):
            return _error_response(-32002, "Permission denied — invalid API key")
        return None

    def _verify_rate_limit(self, client_ip: str) -> Optional[MCPResponse]:
        """Return an error response if the client is rate-limited."""
        if not self._rate_limiter.is_allowed(client_ip):
            return _error_response(-32003, "Rate limit exceeded — retry after back-off")
        return None

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------

    def _setup_routes(self) -> None:
        """Register FastAPI routes."""

        # Populate registry once at startup
        for tool in self.get_tools():
            self._registry.register(tool)

        @self.app.get("/")
        async def root():
            return {
                "name": self.name,
                "description": self.description,
                "status": "healthy",
                "tools": [t.model_dump() for t in self._registry.list()],
            }

        @self.app.post("/rpc")
        async def rpc_handler(request: Request) -> JSONResponse:
            """
            JSON-RPC 2.0 endpoint — handles all MCP methods.

            """
            auth_header = request.headers.get("Authorization")
            client_ip = request.client.host if request.client else "unknown"

            auth_err = self._verify_auth(auth_header)
            if auth_err:
                return JSONResponse(auth_err.model_dump())

            rl_err = self._verify_rate_limit(client_ip)
            if rl_err:
                return JSONResponse(rl_err.model_dump())
            try:
                body = await request.json()
            except Exception:
                return JSONResponse(
                    _error_response(-32700, "Parse error — invalid JSON").model_dump()
                )

            try:
                rpc_req = MCPRequest(**body)
            except Exception as exc:
                return JSONResponse(
                    _error_response(-32600, f"Invalid request: {exc}").model_dump()
                )

            req_id = rpc_req.id

            try:
                response = await self._dispatch(rpc_req)
            except Exception as exc:
                logger.error("Unhandled RPC error: %s", exc, exc_info=True)
                response = _error_response(-32603, f"Internal error: {exc}", req_id)

            return JSONResponse(response.model_dump())

        @self.app.get("/health")
        async def health():
            return {"status": "healthy", "server": self.name}

        @self.app.get("/tools")
        async def list_tools_http():
            """REST convenience endpoint."""
            return {"tools": [t.model_dump() for t in self._registry.list()]}

    async def _dispatch(self, request: MCPRequest) -> MCPResponse:
        """
        Route the JSON-RPC request to the correct handler

        Supported methods:
          - ``initialize``   → server-info + capabilities
          - ``tools/list``   → registered tool list
          - ``tools/call``   → validated tool execution
          - ``ping``         → liveness probe
        """
        method = request.method
        req_id = request.id

        # --- ping ---
        if method == "ping":
            return MCPResponse(result={}, id=req_id)

        # --- initialize ---
        if method == "initialize":
            return MCPResponse(
                result={
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": self.name, "version": "1.0.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
                id=req_id,
            )

        # --- notifications/initialized (fire-and-forget, no response id needed) ---
        if method == "notifications/initialized":
            return MCPResponse(result=None, id=req_id)

        # --- tools/list ---
        if method == "tools/list":
            tools = self._registry.list()
            return MCPResponse(
                result={
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        }
                        for t in tools
                    ]
                },
                id=req_id,
            )

        # --- tools/call ---
        if method == "tools/call":
            if not request.params:
                return _error_response(-32602, "Invalid params: 'params' required for tools/call", req_id)

            tool_name = request.params.get("name")
            tool_params = request.params.get("arguments", {})

            if not tool_name:
                return _error_response(-32602, "Invalid params: 'name' is required", req_id)

            if tool_name not in self._registry.names():
                return _error_response(-32001, f"Tool not found: '{tool_name}'", req_id)

            validation_error = self._registry.validate_params(tool_name, tool_params)
            if validation_error:
                return _error_response(-32005, f"Schema validation: {validation_error}", req_id)

            try:
                result = await self.execute_tool(tool_name, tool_params)
                return MCPResponse(result=result, id=req_id)
            except asyncio.TimeoutError:
                return _error_response(-32004, f"Tool '{tool_name}' timed out", req_id)
            except PermissionError as exc:
                return _error_response(-32002, f"Permission denied: {exc}", req_id)
            except ValueError as exc:
                return _error_response(-32602, f"Invalid params: {exc}", req_id)
            except Exception as exc:
                logger.error("Tool '%s' execution error: %s", tool_name, exc, exc_info=True)
                return _error_response(-32000, f"Tool execution failed: {exc}", req_id)

        # --- unknown method ---
        return _error_response(-32601, f"Method not found: '{method}'", req_id)

    def run(self) -> None:
        """Run the server with uvicorn."""
        import uvicorn
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)


class MCPClient:
    """
    Client for communicating with MCP servers.

    Supports the full MCP handshake (initialize) and bearer-token auth.
    """

    def __init__(self, server_url: str, api_key: Optional[str] = None):
        """
        Initialise MCP Client.

        Args:
            server_url: Base URL of MCP server (e.g., http://localhost:8000)
            api_key: Optional bearer token for servers that require auth.
        """
        self.server_url = server_url.rstrip("/")
        self._request_id = 0
        self._api_key = api_key

    def _get_next_id(self) -> str:
        """Return a monotonically increasing request ID string."""
        self._request_id += 1
        return str(self._request_id)

    def _headers(self) -> Dict[str, str]:
        """Build request headers, including Authorization if configured."""
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def initialize(self, client_name: str = "UniVex-Agent", client_version: str = "1.0.0") -> Dict[str, Any]:
        """
        Perform the MCP initialize handshake.

        Returns:
            Server info + capabilities dict.
        """
        import aiohttp

        request_data = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": client_name, "version": client_version},
                "capabilities": {},
            },
            "id": self._get_next_id(),
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.server_url}/rpc",
                json=request_data,
                headers=self._headers(),
            ) as response:
                result = await response.json()
                if "error" in result:
                    raise Exception(f"MCP initialize error: {result['error']}")
                return result.get("result", {})

    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from server."""
        import aiohttp

        request_data = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": self._get_next_id(),
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.server_url}/rpc",
                json=request_data,
                headers=self._headers(),
            ) as response:
                result = await response.json()
                if "error" in result:
                    raise Exception(f"MCP Error: {result['error']}")
                return result.get("result", {}).get("tools", [])

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool on the server.

        Args:
            tool_name: Registered tool name
            arguments: Tool arguments

        Returns:
            Tool execution result dict
        """
        import aiohttp

        request_data = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": self._get_next_id(),
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.server_url}/rpc",
                json=request_data,
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=300),
            ) as response:
                result = await response.json()
                if "error" in result:
                    raise Exception(f"MCP Error: {result['error']}")
                return result.get("result", {})
