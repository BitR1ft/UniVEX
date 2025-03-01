"""
Browser Tool — Isolated Headless Browser Interaction

browser automation for web application testing. All operations run inside a
dedicated Playwright container; screenshots are persisted to MinIO and
returned as presigned URLs.

Features:
  navigate(url)                — navigate to a URL and return page status
  screenshot(url)              — full-page screenshot → MinIO presigned URL
  extract_text(url)            — extract visible text content for AI analysis
  click(url, selector)         — click a DOM element inside the sandbox
  fill_form(url, selectors, values) — fill and submit HTML forms
  get_cookies(url)             — extract cookies / session tokens
  get_local_storage(url)       — extract localStorage / sessionStorage data
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

_BROWSER_SERVER_URL = "http://browser:8015"


class BrowserTool(BaseTool):
    """
    Isolated headless browser tool powered by the BrowserMCPServer.

    All HTTP requests originate from a sandboxed Playwright container —
    never from the main API process — to prevent server-side request
    forgery against the internal network.
    """

    TOOL_NAME = "browser_navigate"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Navigate to a URL inside an isolated headless browser sandbox. "
                "Returns HTTP status, page title, and meta description."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Fully-qualified URL to navigate to (https://…)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Page load timeout in milliseconds (default 30 000).",
                        "default": 30_000,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(self, url: str, timeout: int = 30_000, **kwargs) -> str:  # noqa: D401
        """Navigate to *url* and return a human-readable summary."""
        try:
            result = await self._client.call_tool(
                "browser_navigate", {"url": url, "timeout": timeout}
            )
            if not result.get("success"):
                return f"Error: {result.get('error', 'Navigation failed')}"

            status = result.get("status_code", "?")
            title = result.get("title", "(no title)")
            return (
                f"Navigation to {url} succeeded.\n"
                f"  HTTP status : {status}\n"
                f"  Page title  : {title}\n"
            )
        except Exception as exc:
            logger.error("BrowserTool.navigate error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class BrowserScreenshotTool(BaseTool):
    """Capture a full-page screenshot and upload it to MinIO."""

    TOOL_NAME = "browser_screenshot"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Capture a full-page screenshot of a URL inside the isolated browser. "
                "The image is stored in MinIO and a presigned URL is returned."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to screenshot.",
                    },
                    "full_page": {
                        "type": "boolean",
                        "description": "Capture the full scrollable page (default true).",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(self, url: str, full_page: bool = True, **kwargs) -> str:
        """Capture screenshot and return presigned MinIO URL."""
        try:
            result = await self._client.call_tool(
                "browser_screenshot", {"url": url, "full_page": full_page}
            )
            if not result.get("success"):
                return f"Error: {result.get('error', 'Screenshot failed')}"

            presigned_url = result.get("presigned_url", "")
            object_name = result.get("object_name", "")
            return (
                f"Screenshot captured for {url}.\n"
                f"  Object  : {object_name}\n"
                f"  URL     : {presigned_url}\n"
            )
        except Exception as exc:
            logger.error("BrowserScreenshotTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class BrowserExtractTextTool(BaseTool):
    """Extract visible text content from a web page."""

    TOOL_NAME = "browser_extract_text"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Extract all visible text content from a web page for AI analysis. "
                "Strips scripts, styles, and HTML tags; returns clean plain text."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to extract text from."},
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum characters to return (default 50 000).",
                        "default": 50_000,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(self, url: str, max_chars: int = 50_000, **kwargs) -> str:
        try:
            result = await self._client.call_tool(
                "browser_extract_text", {"url": url, "max_chars": max_chars}
            )
            if not result.get("success"):
                return f"Error: {result.get('error', 'Text extraction failed')}"
            return result.get("text", "(empty page)")
        except Exception as exc:
            logger.error("BrowserExtractTextTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class BrowserClickTool(BaseTool):
    """Click a DOM element on a web page inside the isolated sandbox."""

    TOOL_NAME = "browser_click"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description="Click a DOM element on a page by CSS selector inside the isolated browser.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to load before clicking."},
                    "selector": {"type": "string", "description": "CSS selector of element to click."},
                    "wait_after_ms": {
                        "type": "integer",
                        "description": "Milliseconds to wait after click (default 1 000).",
                        "default": 1_000,
                    },
                },
                "required": ["url", "selector"],
            },
        )

    async def execute(self, url: str, selector: str, wait_after_ms: int = 1_000, **kwargs) -> str:
        try:
            result = await self._client.call_tool(
                "browser_click", {"url": url, "selector": selector, "wait_after_ms": wait_after_ms}
            )
            if not result.get("success"):
                return f"Error: {result.get('error', 'Click failed')}"
            page_title = result.get("page_title", "(unknown)")
            return f"Clicked '{selector}' on {url}. Resulting page title: {page_title}"
        except Exception as exc:
            logger.error("BrowserClickTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class BrowserFillFormTool(BaseTool):
    """Fill and optionally submit an HTML form inside the isolated browser."""

    TOOL_NAME = "browser_fill_form"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Fill one or more form fields on a page and optionally submit the form. "
                "Useful for testing authentication forms, search boxes, and upload endpoints."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL of the page containing the form."},
                    "selectors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of CSS selectors for form fields.",
                    },
                    "values": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of values to fill in (parallel to selectors).",
                    },
                    "submit_selector": {
                        "type": "string",
                        "description": "CSS selector of the submit button (optional).",
                        "default": "",
                    },
                },
                "required": ["url", "selectors", "values"],
            },
        )

    async def execute(
        self,
        url: str,
        selectors: List[str],
        values: List[str],
        submit_selector: str = "",
        **kwargs,
    ) -> str:
        if len(selectors) != len(values):
            return "Error: selectors and values lists must be the same length."
        try:
            result = await self._client.call_tool(
                "browser_fill_form",
                {
                    "url": url,
                    "selectors": selectors,
                    "values": values,
                    "submit_selector": submit_selector,
                },
            )
            if not result.get("success"):
                return f"Error: {result.get('error', 'Form fill failed')}"
            response_url = result.get("response_url", url)
            response_status = result.get("response_status", "?")
            return (
                f"Form filled on {url}.\n"
                f"  Final URL   : {response_url}\n"
                f"  HTTP status : {response_status}\n"
            )
        except Exception as exc:
            logger.error("BrowserFillFormTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class BrowserGetCookiesTool(BaseTool):
    """Extract cookies and session tokens from a page."""

    TOOL_NAME = "browser_get_cookies"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description="Extract all cookies set after loading a URL. Returns cookie name, value, domain, path, HttpOnly, Secure, SameSite flags.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to load."},
                },
                "required": ["url"],
            },
        )

    async def execute(self, url: str, **kwargs) -> str:
        try:
            result = await self._client.call_tool("browser_get_cookies", {"url": url})
            if not result.get("success"):
                return f"Error: {result.get('error', 'Cookie extraction failed')}"
            cookies: List[Dict[str, Any]] = result.get("cookies", [])
            if not cookies:
                return f"No cookies found on {url}."
            lines = [f"Cookies for {url} ({len(cookies)} total):"]
            for ck in cookies:
                flags = []
                if ck.get("httpOnly"):
                    flags.append("HttpOnly")
                if ck.get("secure"):
                    flags.append("Secure")
                same_site = ck.get("sameSite", "")
                if same_site:
                    flags.append(f"SameSite={same_site}")
                flag_str = ", ".join(flags) if flags else "none"
                lines.append(
                    f"  [{ck.get('domain', '')}] {ck.get('name', '')}={ck.get('value', '')} "
                    f"({flag_str})"
                )
            return "\n".join(lines)
        except Exception as exc:
            logger.error("BrowserGetCookiesTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class BrowserGetLocalStorageTool(BaseTool):
    """Extract localStorage and sessionStorage data from a page."""

    TOOL_NAME = "browser_get_local_storage"

    def __init__(self, server_url: str = _BROWSER_SERVER_URL) -> None:
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description="Extract localStorage and sessionStorage key-value pairs from a page.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to load."},
                },
                "required": ["url"],
            },
        )

    async def execute(self, url: str, **kwargs) -> str:
        try:
            result = await self._client.call_tool("browser_get_local_storage", {"url": url})
            if not result.get("success"):
                return f"Error: {result.get('error', 'Storage extraction failed')}"
            local_storage: Dict[str, str] = result.get("local_storage", {})
            session_storage: Dict[str, str] = result.get("session_storage", {})
            lines: List[str] = [f"Web storage for {url}:"]
            lines.append(f"\n  localStorage ({len(local_storage)} keys):")
            for k, v in local_storage.items():
                lines.append(f"    {k} = {v[:120]}")
            lines.append(f"\n  sessionStorage ({len(session_storage)} keys):")
            for k, v in session_storage.items():
                lines.append(f"    {k} = {v[:120]}")
            return "\n".join(lines)
        except Exception as exc:
            logger.error("BrowserGetLocalStorageTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


__all__ = [
    "BrowserTool",
    "BrowserScreenshotTool",
    "BrowserExtractTextTool",
    "BrowserClickTool",
    "BrowserFillFormTool",
    "BrowserGetCookiesTool",
    "BrowserGetLocalStorageTool",
]
