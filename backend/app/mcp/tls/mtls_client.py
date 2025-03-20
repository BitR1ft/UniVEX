"""
mTLS-aware HTTP client for MCP tool servers.

"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)


@dataclass
class MTLSConfig:
    """Configuration for mutual TLS connections."""
    client_cert_path: str
    client_key_path: str
    ca_cert_path: str
    verify_server: bool = True
    timeout: float = 30.0


class MTLSClient:
    """
    Async HTTP client with mutual TLS authentication.

    Wraps ``httpx.AsyncClient`` configured with client certificates and
    CA verification for both client→server and server→client validation.

    Usage::

        config = MTLSConfig(
            client_cert_path="certs/client/cert.pem",
            client_key_path="certs/client/key.pem",
            ca_cert_path="certs/ca/cert.pem",
        )
        async with MTLSClient(config) as client:
            response = await client.request("GET", "https://mcp-server/health")
    """

    def __init__(self, config: MTLSConfig) -> None:
        self._config = config
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.AsyncClient:
        ssl_context_kwargs: Dict[str, Any] = {
            "cert": (self._config.client_cert_path, self._config.client_key_path),
        }
        if self._config.verify_server:
            ssl_context_kwargs["verify"] = self._config.ca_cert_path
        else:
            ssl_context_kwargs["verify"] = False

        return httpx.AsyncClient(
            **ssl_context_kwargs,
            timeout=self._config.timeout,
        )

    async def __aenter__(self) -> "MTLSClient":
        self._client = self._build_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("MTLSClient not entered. Use 'async with MTLSClient(...) as client:'")
        return self._client

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send an mTLS-authenticated HTTP request."""
        logger.debug("mTLS %s %s", method, url)
        return await self._http.request(method, url, **kwargs)

    async def call_tool(
        self,
        server_url: str,
        tool_name: str,
        params: Dict[str, Any],
        request_id: str = "1",
    ) -> Dict[str, Any]:
        """
        Call an MCP tool endpoint via mTLS.

        Args:
            server_url: Base URL of the MCP server.
            tool_name: Tool name to invoke.
            params: Tool arguments.
            request_id: JSON-RPC request ID.

        Returns:
            Result dict from the server.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": params},
            "id": request_id,
        }
        response = await self.request(
            "POST",
            f"{server_url.rstrip('/')}/rpc",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {})


class MCPClientmTLS(MCPClient):
    """
    MCPClient subclass that adds mTLS support.

    Extends the base :class:`~app.mcp.base_server.MCPClient` to send all
    requests over a mutually-authenticated TLS channel.
    """

    def __init__(
        self,
        server_url: str,
        mtls_config: MTLSConfig,
        api_key: Optional[str] = None,
    ) -> None:
        super().__init__(server_url=server_url, api_key=api_key)
        self._mtls_config = mtls_config
        self._mtls_client: Optional[MTLSClient] = None

    async def __aenter__(self) -> "MCPClientmTLS":
        self._mtls_client = MTLSClient(self._mtls_config)
        await self._mtls_client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._mtls_client is not None:
            await self._mtls_client.__aexit__(*args)
            self._mtls_client = None

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Override: send tool call over mTLS channel."""
        if self._mtls_client is None:
            raise RuntimeError("MCPClientmTLS must be used as an async context manager")
        return await self._mtls_client.call_tool(self.server_url, tool_name, arguments)
