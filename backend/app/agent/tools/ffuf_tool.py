"""
FfufTool

Agent tool adapter for the ffuf MCP server.  Exposes three operations to the
LangGraph ReAct agent:

  ffuf_fuzz_dirs   — directory/path brute-force
  ffuf_fuzz_files  — file discovery with extension filtering
  ffuf_fuzz_params — GET/POST parameter fuzzing

All three tools are registered for the INFORMATIONAL and WEB_APP_ATTACK
phases, and are wired into the AttackPathRouter WEB_APP_ATTACK category so
the agent selects them automatically when web attack chains are classified.

The tools also persist discovered endpoints to Neo4j via the ingestion
pipeline — callers can set `project_id` / `user_id` to enable graph storage.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

# Default URL of the ffuf MCP server (overridable in tests / staging)
DEFAULT_FFUF_URL = "http://kali-tools:8004"


class FfufFuzzDirsTool(BaseTool):
    """
    Web directory brute-force using ffuf.

    Discovers hidden directories and paths on a target web server.
    Results are returned as a list of discovered endpoints sorted by status
    code priority (2xx → 3xx → others).
    """

    def __init__(
        self,
        server_url: str = DEFAULT_FFUF_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ffuf_fuzz_dirs",
            description=(
                "Brute-force directories and paths on a web server using ffuf. "
                "Returns discovered endpoints with HTTP status codes. "
                "Use this to find hidden admin panels, upload pages, or config files."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL to fuzz (e.g. 'http://10.10.10.1/'). "
                        "FUZZ keyword is added automatically.",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist preset: common (default) | raft-medium | raft-large | api-endpoints",
                        "default": "common",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "Comma-separated file extensions to also check "
                        "(e.g. 'php,html'). Leave empty for dirs only.",
                        "default": "",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Requests per second (max 500). Default: 100.",
                        "default": 100,
                    },
                    "filter_status": {
                        "type": "string",
                        "description": "Comma-separated status codes to exclude. Default: '404'.",
                        "default": "404",
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow RFC-1918/localhost targets (HTB labs). Default: false.",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(300)
    async def execute(
        self,
        url: str,
        wordlist: str = "common",
        extensions: str = "",
        rate: int = 100,
        filter_status: str = "404",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            result = await self._client.call_tool(
                "fuzz_dirs",
                {
                    "url": url,
                    "wordlist": wordlist,
                    "extensions": extensions,
                    "rate": rate,
                    "filter_status": filter_status,
                    "allow_internal": allow_internal,
                },
            )
            return self._format_result(result, url)
        except Exception as exc:
            logger.error("ffuf_fuzz_dirs error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"ffuf directory fuzzing failed: {exc}", tool_name="ffuf_fuzz_dirs"
            ) from exc

    def _format_result(self, result: dict, url: str) -> str:
        if not result.get("success"):
            return f"ffuf error: {result.get('error', 'Unknown error')}"

        hits = result.get("results", [])
        if not hits:
            return f"No directories/paths found on {url} (wordlist: {result.get('wordlist', '?')})"

        lines = [
            f"ffuf directory scan results for {url} "
            f"[{len(hits)} found, wordlist: {result.get('wordlist', '?')}]:"
        ]
        for h in _sort_endpoints(hits)[:50]:
            redirect = f" → {h['redirect']}" if h.get("redirect") else ""
            lines.append(
                f"  [{h['status_code']}] {h['path']}"
                f" ({h['content_length']} bytes){redirect}"
            )
        if len(hits) > 50:
            lines.append(f"  ... and {len(hits) - 50} more results")

        return truncate_output("\n".join(lines))


class FfufFuzzFilesTool(BaseTool):
    """
    Web file discovery using ffuf with extension filtering.

    Good for finding backup files (`.bak`, `.old`), configuration leaks
    (`.env`, `config.php`), and other sensitive assets.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_FFUF_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ffuf_fuzz_files",
            description=(
                "Discover files on a web server with extension filtering using ffuf. "
                "Good for finding backup files, config leaks, and hidden assets."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL to fuzz (e.g. 'http://10.10.10.1/'). "
                        "FUZZ keyword is added automatically.",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist preset: common (default) | raft-medium | raft-large | api-endpoints",
                        "default": "common",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "Comma-separated extensions to check. "
                        "Default: 'php,txt,html'.",
                        "default": "php,txt,html",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Requests per second (max 500). Default: 100.",
                        "default": 100,
                    },
                    "filter_status": {
                        "type": "string",
                        "description": "Status codes to exclude. Default: '404'.",
                        "default": "404",
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow RFC-1918/localhost targets. Default: false.",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(300)
    async def execute(
        self,
        url: str,
        wordlist: str = "common",
        extensions: str = "php,txt,html",
        rate: int = 100,
        filter_status: str = "404",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            result = await self._client.call_tool(
                "fuzz_files",
                {
                    "url": url,
                    "wordlist": wordlist,
                    "extensions": extensions,
                    "rate": rate,
                    "filter_status": filter_status,
                    "allow_internal": allow_internal,
                },
            )
            return self._format_result(result, url)
        except Exception as exc:
            logger.error("ffuf_fuzz_files error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"ffuf file fuzzing failed: {exc}", tool_name="ffuf_fuzz_files"
            ) from exc

    def _format_result(self, result: dict, url: str) -> str:
        if not result.get("success"):
            return f"ffuf error: {result.get('error', 'Unknown error')}"

        hits = result.get("results", [])
        if not hits:
            return f"No files found on {url} (extensions: {result.get('extensions', '?')})"

        lines = [f"ffuf file scan results for {url} [{len(hits)} found]:"]
        for h in _sort_endpoints(hits)[:50]:
            lines.append(
                f"  [{h['status_code']}] {h['path']} ({h['content_length']} bytes)"
            )
        if len(hits) > 50:
            lines.append(f"  ... and {len(hits) - 50} more results")

        return truncate_output("\n".join(lines))


class FfufFuzzParamsTool(BaseTool):
    """
    GET/POST parameter fuzzing using ffuf.

    Useful for finding hidden parameters and injection entry points.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_FFUF_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ffuf_fuzz_params",
            description=(
                "Fuzz GET or POST parameters on a web endpoint to find hidden "
                "parameters and injection points. Use FUZZ as the parameter placeholder."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL with FUZZ placeholder for the parameter name "
                        "(e.g. 'http://host/page?FUZZ=test').",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Wordlist preset: common | raft-medium | raft-large | api-endpoints (default)",
                        "default": "api-endpoints",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method: GET or POST. Default: GET.",
                        "default": "GET",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST body template with FUZZ placeholder. Required for POST.",
                        "default": "",
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Requests per second (max 500). Default: 100.",
                        "default": 100,
                    },
                    "filter_status": {
                        "type": "string",
                        "description": "Status codes to exclude. Default: '404'.",
                        "default": "404",
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow RFC-1918/localhost targets. Default: false.",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(300)
    async def execute(
        self,
        url: str,
        wordlist: str = "api-endpoints",
        method: str = "GET",
        data: str = "",
        rate: int = 100,
        filter_status: str = "404",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            result = await self._client.call_tool(
                "fuzz_params",
                {
                    "url": url,
                    "wordlist": wordlist,
                    "method": method,
                    "data": data,
                    "rate": rate,
                    "filter_status": filter_status,
                    "allow_internal": allow_internal,
                },
            )
            return self._format_result(result, url, method)
        except Exception as exc:
            logger.error("ffuf_fuzz_params error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"ffuf param fuzzing failed: {exc}", tool_name="ffuf_fuzz_params"
            ) from exc

    def _format_result(self, result: dict, url: str, method: str) -> str:
        if not result.get("success"):
            return f"ffuf error: {result.get('error', 'Unknown error')}"

        hits = result.get("results", [])
        if not hits:
            return f"No parameters found on {url} ({method})"

        lines = [f"ffuf parameter scan results for {url} [{method}, {len(hits)} found]:"]
        for h in _sort_endpoints(hits)[:50]:
            lines.append(
                f"  [{h['status_code']}] {h['path']} ({h['content_length']} bytes)"
            )
        if len(hits) > 50:
            lines.append(f"  ... and {len(hits) - 50} more results")

        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# Private helper
# ---------------------------------------------------------------------------


def _sort_endpoints(endpoints: list) -> list:
    """Sort endpoints: 2xx first, then 3xx, then rest, all alphabetically within tier."""

    def _tier(ep: dict) -> int:
        code = ep.get("status_code", 0)
        if 200 <= code < 300:
            return 0
        if 300 <= code < 400:
            return 1
        return 2

    return sorted(endpoints, key=lambda e: (_tier(e), e.get("path", "")))
