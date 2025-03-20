"""
Proxy MCP Server — HTTP/HTTPS Intercepting Proxy (Port 8008)

MCP JSON-RPC 2.0 wrapper around the UniVex proxy engine.  Agents call these
tools to control the proxy, query captured traffic, manage scope, and replay
requests — all through a standard MCP call interface.

Tools exposed:
  proxy_start           — start the proxy on a specified port
  proxy_stop            — stop the proxy
  proxy_status          — return running status + statistics
  proxy_list_requests   — list captured requests (paginated)
  proxy_get_request     — get full detail for a single captured request
  proxy_search          — search captured traffic by URL/method/status/body
  proxy_clear           — clear all captured traffic
  proxy_add_rule        — add an intercept rule (URL pattern, method, content type)
  proxy_remove_rule     — remove an intercept rule by index
  proxy_list_rules      — list active intercept rules
  proxy_export          — export captured traffic as HAR, JSON, or CSV
  proxy_set_scope       — set in-scope / out-of-scope URL patterns
  proxy_get_ca_cert     — retrieve the proxy CA certificate PEM for client installation

Environment variables:
  PROXY_PORT           — default proxy listen port (default 8080)
  PROXY_UPSTREAM       — optional upstream proxy URL
  PROXY_SSL_VERIFY     — verify upstream SSL (default false)
  PROXY_MCP_API_KEY    — bearer token for this MCP server (optional)
  PROXY_MCP_PORT       — port for this MCP server (default 8008)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from app.mcp.base_server import MCPServer, MCPTool
from app.proxy.interceptor import InterceptRule, ProxyInterceptor, ScopeFilter
from app.proxy.request_store import RequestStore

logger = logging.getLogger(__name__)

_PROXY_MCP_PORT = int(os.getenv("PROXY_MCP_PORT", "8008"))
_PROXY_MCP_API_KEY = os.getenv("PROXY_MCP_API_KEY", "")

# ---------------------------------------------------------------------------
# Singleton proxy engine shared across all tool invocations
# ---------------------------------------------------------------------------

_request_store = RequestStore()
_scope_filter = ScopeFilter()
_proxy_interceptor = ProxyInterceptor(
    store=_request_store,
    scope=_scope_filter,
)


def _get_proxy() -> ProxyInterceptor:
    """Return the module-level singleton ProxyInterceptor."""
    return _proxy_interceptor


# ---------------------------------------------------------------------------
# ProxyMCPServer
# ---------------------------------------------------------------------------


class ProxyMCPServer(MCPServer):
    """
    MCP Server that wraps the UniVex proxy engine.

    Agents interact with the proxy through this standard MCP interface rather
    than spawning a subprocess or connecting directly to the proxy engine.
    """

    PORT = _PROXY_MCP_PORT

    def __init__(self) -> None:
        super().__init__(
            name="Proxy",
            description="HTTP/HTTPS intercepting proxy MCP server for traffic capture, replay, and analysis",
            port=self.PORT,
            api_key=_PROXY_MCP_API_KEY or None,
        )

    # ------------------------------------------------------------------
    # Tool declarations
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="proxy_start",
                description="Start the intercepting proxy on a specified port.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "port": {
                            "type": "integer",
                            "description": "TCP port to listen on.",
                            "default": 8080,
                        },
                        "upstream": {
                            "type": "string",
                            "description": "Optional upstream proxy URL (e.g. http://proxy.corp:3128).",
                            "default": "",
                        },
                        "ssl_verify": {
                            "type": "boolean",
                            "description": "Verify upstream TLS certificate.",
                            "default": False,
                        },
                    },
                    "required": [],
                },
            ),
            MCPTool(
                name="proxy_stop",
                description="Stop the intercepting proxy.",
                phase="recon",
                parameters={"type": "object", "properties": {}, "required": []},
            ),
            MCPTool(
                name="proxy_status",
                description="Return proxy running status and statistics.",
                phase="recon",
                parameters={"type": "object", "properties": {}, "required": []},
            ),
            MCPTool(
                name="proxy_list_requests",
                description="List captured HTTP requests, newest first, paginated.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "page": {"type": "integer", "default": 1},
                        "page_size": {"type": "integer", "default": 50},
                    },
                    "required": [],
                },
            ),
            MCPTool(
                name="proxy_get_request",
                description="Get full detail of a captured request by ID.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "request_id": {"type": "string", "description": "UUID of the captured request."},
                    },
                    "required": ["request_id"],
                },
            ),
            MCPTool(
                name="proxy_search",
                description=(
                    "Search captured traffic by URL substring, HTTP method, status code, "
                    "content-type substring, body regex, or tag."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url_contains": {"type": "string"},
                        "method": {"type": "string"},
                        "status_code": {"type": "integer"},
                        "content_type_contains": {"type": "string"},
                        "body_regex": {"type": "string"},
                        "tag": {"type": "string"},
                    },
                    "required": [],
                },
            ),
            MCPTool(
                name="proxy_clear",
                description="Clear all captured traffic from the store.",
                phase="recon",
                parameters={"type": "object", "properties": {}, "required": []},
            ),
            MCPTool(
                name="proxy_add_rule",
                description="Add an intercept rule to filter/tag captured requests.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url_pattern": {
                            "type": "string",
                            "description": "Regex applied to the full URL.",
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method filter (GET/POST/etc.).",
                        },
                        "content_type": {
                            "type": "string",
                            "description": "Substring matched against Content-Type.",
                        },
                        "tag": {
                            "type": "string",
                            "description": "Tag applied to matching captured requests.",
                            "default": "",
                        },
                    },
                    "required": [],
                },
            ),
            MCPTool(
                name="proxy_remove_rule",
                description="Remove an intercept rule by its 0-based index.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer", "description": "Rule index to remove."},
                    },
                    "required": ["index"],
                },
            ),
            MCPTool(
                name="proxy_list_rules",
                description="List all active intercept rules.",
                phase="recon",
                parameters={"type": "object", "properties": {}, "required": []},
            ),
            MCPTool(
                name="proxy_export",
                description="Export captured traffic as HAR, JSON, or CSV.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["har", "json", "csv"],
                            "default": "json",
                        },
                        "url_contains": {"type": "string"},
                        "method": {"type": "string"},
                        "status_code": {"type": "integer"},
                        "tag": {"type": "string"},
                    },
                    "required": [],
                },
            ),
            MCPTool(
                name="proxy_set_scope",
                description="Define in-scope and out-of-scope URL patterns for the proxy.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "in_scope": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regex patterns that must match for a URL to be captured.",
                            "default": [],
                        },
                        "out_scope": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regex patterns that cause a URL to be excluded from capture.",
                            "default": [],
                        },
                        "clear_existing": {
                            "type": "boolean",
                            "description": "Whether to clear existing scope rules first.",
                            "default": True,
                        },
                    },
                    "required": [],
                },
            ),
            MCPTool(
                name="proxy_get_ca_cert",
                description=(
                    "Return the proxy CA certificate PEM for installation in browsers/tools "
                    "so that HTTPS connections are trusted."
                ),
                phase="recon",
                parameters={"type": "object", "properties": {}, "required": []},
            ),
        ]

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        dispatch = {
            "proxy_start": self._proxy_start,
            "proxy_stop": self._proxy_stop,
            "proxy_status": self._proxy_status,
            "proxy_list_requests": self._proxy_list_requests,
            "proxy_get_request": self._proxy_get_request,
            "proxy_search": self._proxy_search,
            "proxy_clear": self._proxy_clear,
            "proxy_add_rule": self._proxy_add_rule,
            "proxy_remove_rule": self._proxy_remove_rule,
            "proxy_list_rules": self._proxy_list_rules,
            "proxy_export": self._proxy_export,
            "proxy_set_scope": self._proxy_set_scope,
            "proxy_get_ca_cert": self._proxy_get_ca_cert,
        }
        handler = dispatch.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        return await handler(params)

    # ------------------------------------------------------------------
    # Implementation
    # ------------------------------------------------------------------

    async def _proxy_start(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        if proxy.running:
            return {"success": False, "error": "Proxy is already running.", "port": proxy.port}
        try:
            port = int(params.get("port", 8080))
            await proxy.start(port=port)
            return {"success": True, "port": proxy.port, "message": f"Proxy started on port {proxy.port}"}
        except Exception as exc:
            logger.error("proxy_start error: %s", exc)
            return {"success": False, "error": str(exc)}

    async def _proxy_stop(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        if not proxy.running:
            return {"success": False, "error": "Proxy is not running."}
        try:
            await proxy.stop()
            return {"success": True, "message": "Proxy stopped."}
        except Exception as exc:
            logger.error("proxy_stop error: %s", exc)
            return {"success": False, "error": str(exc)}

    async def _proxy_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        stats = proxy.get_stats()
        total = await _request_store.count()
        stats["captured_requests"] = total
        return {"success": True, "status": stats}

    async def _proxy_list_requests(self, params: Dict[str, Any]) -> Dict[str, Any]:
        page = int(params.get("page", 1))
        page_size = int(params.get("page_size", 50))
        entries = await _request_store.list_all(page=page, page_size=page_size)
        total = await _request_store.count()
        return {
            "success": True,
            "total": total,
            "page": page,
            "page_size": page_size,
            "requests": [e.to_dict() for e in entries],
        }

    async def _proxy_get_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        request_id = params["request_id"]
        entry = await _request_store.get(request_id)
        if entry is None:
            return {"success": False, "error": f"Request {request_id} not found."}
        return {"success": True, "request": entry.to_dict()}

    async def _proxy_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        try:
            results = await _request_store.search(
                url_contains=params.get("url_contains"),
                method=params.get("method"),
                status_code=params.get("status_code"),
                content_type_contains=params.get("content_type_contains"),
                body_regex=params.get("body_regex"),
                tag=params.get("tag"),
            )
            return {
                "success": True,
                "count": len(results),
                "requests": [r.to_dict() for r in results],
            }
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

    async def _proxy_clear(self, params: Dict[str, Any]) -> Dict[str, Any]:
        count = await _request_store.clear()
        return {"success": True, "cleared": count}

    async def _proxy_add_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        try:
            rule = InterceptRule(
                url_pattern=params.get("url_pattern") or None,
                method=params.get("method") or None,
                content_type=params.get("content_type") or None,
                tag=params.get("tag", ""),
            )
            proxy.add_rule(rule)
            return {
                "success": True,
                "message": "Rule added.",
                "rule_count": len(proxy.rules),
            }
        except ValueError as exc:
            return {"success": False, "error": str(exc)}

    async def _proxy_remove_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        index = int(params["index"])
        if index < 0 or index >= len(proxy.rules):
            return {"success": False, "error": f"Rule index {index} out of range."}
        proxy.remove_rule(index)
        return {"success": True, "message": f"Rule {index} removed.", "rule_count": len(proxy.rules)}

    async def _proxy_list_rules(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        rules = [
            {
                "index": i,
                "url_pattern": r.url_pattern,
                "method": r.method,
                "content_type": r.content_type,
                "tag": r.tag,
                "pause_for_inspection": r.pause_for_inspection,
            }
            for i, r in enumerate(proxy.rules)
        ]
        return {"success": True, "rules": rules}

    async def _proxy_export(self, params: Dict[str, Any]) -> Dict[str, Any]:
        fmt = params.get("format", "json").lower()
        if fmt not in ("har", "json", "csv"):
            return {"success": False, "error": f"Unsupported format: {fmt}"}

        results = await _request_store.search(
            url_contains=params.get("url_contains"),
            method=params.get("method"),
            status_code=params.get("status_code"),
            tag=params.get("tag"),
        )

        if fmt == "har":
            data = _request_store.export_har(results)
            content_type = "application/json"
        elif fmt == "csv":
            data = _request_store.export_csv(results)
            content_type = "text/csv"
        else:
            data = _request_store.export_json(results)
            content_type = "application/json"

        return {
            "success": True,
            "format": fmt,
            "content_type": content_type,
            "count": len(results),
            "data": data,
        }

    async def _proxy_set_scope(self, params: Dict[str, Any]) -> Dict[str, Any]:
        proxy = _get_proxy()
        clear_existing = params.get("clear_existing", True)
        if clear_existing:
            proxy.scope.clear()

        added_in = 0
        added_out = 0
        errors: List[str] = []

        for pattern in params.get("in_scope", []):
            try:
                proxy.scope.add_in_scope(pattern)
                added_in += 1
            except Exception as exc:
                errors.append(f"in_scope {pattern!r}: {exc}")

        for pattern in params.get("out_scope", []):
            try:
                proxy.scope.add_out_scope(pattern)
                added_out += 1
            except Exception as exc:
                errors.append(f"out_scope {pattern!r}: {exc}")

        result: Dict[str, Any] = {
            "success": True,
            "added_in_scope": added_in,
            "added_out_scope": added_out,
        }
        if errors:
            result["errors"] = errors
        return result

    async def _proxy_get_ca_cert(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from app.proxy.ssl_context import SSLContextManager

        try:
            mgr = SSLContextManager()
            mgr.initialize()
            ca_pem = mgr.ca_cert_pem.decode("utf-8")
            return {
                "success": True,
                "ca_cert_pem": ca_pem,
                "instructions": (
                    "Add this certificate to your browser/OS trust store so that "
                    "HTTPS connections intercepted by the proxy are trusted."
                ),
            }
        except Exception as exc:
            logger.error("proxy_get_ca_cert error: %s", exc)
            return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Factory for uvicorn
# ---------------------------------------------------------------------------


def create_app():
    """Entry point for: uvicorn app.mcp.servers.proxy_server:create_app --factory"""
    server = ProxyMCPServer()
    return server.app
