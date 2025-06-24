"""
Tests for Day 15 — Isolated Browser Tool & OOB Attack Infrastructure
(browser_tool.py, browser_server.py)

Coverage:
  BrowserTool                — navigate, metadata, error handling
  BrowserScreenshotTool      — screenshot, upload, presigned URL
  BrowserExtractTextTool     — text extraction
  BrowserClickTool           — click action
  BrowserFillFormTool        — form fill + submit
  BrowserGetCookiesTool      — cookie extraction with security flags
  BrowserGetLocalStorageTool — localStorage/sessionStorage extraction
  BrowserMCPServer           — tool declarations, URL validation, dispatch
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import isolation helpers (mirrors existing conftest patterns)
# ---------------------------------------------------------------------------

import sys
import types

for _pkg in [
    "playwright",
    "playwright.async_api",
    "miniopy_async",
]:
    if _pkg not in sys.modules:
        mod = types.ModuleType(_pkg)
        sys.modules[_pkg] = mod


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# BrowserTool
# ---------------------------------------------------------------------------

from app.agent.tools.browser_tool import (
    BrowserTool,
    BrowserScreenshotTool,
    BrowserExtractTextTool,
    BrowserClickTool,
    BrowserFillFormTool,
    BrowserGetCookiesTool,
    BrowserGetLocalStorageTool,
)


class TestBrowserToolMetadata:
    def test_name(self):
        t = BrowserTool()
        assert t.name == "browser_navigate"

    def test_description_non_empty(self):
        t = BrowserTool()
        assert len(t.description) > 10

    def test_parameters_has_url(self):
        t = BrowserTool()
        assert "url" in t.metadata.parameters["properties"]

    def test_screenshot_name(self):
        t = BrowserScreenshotTool()
        assert t.name == "browser_screenshot"

    def test_screenshot_params_full_page(self):
        t = BrowserScreenshotTool()
        assert "full_page" in t.metadata.parameters["properties"]

    def test_extract_text_name(self):
        t = BrowserExtractTextTool()
        assert t.name == "browser_extract_text"

    def test_extract_text_has_max_chars(self):
        t = BrowserExtractTextTool()
        assert "max_chars" in t.metadata.parameters["properties"]

    def test_click_name(self):
        t = BrowserClickTool()
        assert t.name == "browser_click"

    def test_click_requires_selector(self):
        t = BrowserClickTool()
        assert "selector" in t.metadata.parameters["required"]

    def test_fill_form_name(self):
        t = BrowserFillFormTool()
        assert t.name == "browser_fill_form"

    def test_fill_form_requires_selectors_and_values(self):
        t = BrowserFillFormTool()
        req = t.metadata.parameters["required"]
        assert "selectors" in req and "values" in req

    def test_get_cookies_name(self):
        t = BrowserGetCookiesTool()
        assert t.name == "browser_get_cookies"

    def test_get_local_storage_name(self):
        t = BrowserGetLocalStorageTool()
        assert t.name == "browser_get_local_storage"


class TestBrowserToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserTool:
        t = BrowserTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_navigate_success(self):
        t = self._make_tool({"success": True, "status_code": 200, "title": "Home"})
        out = run(t.execute(url="http://example.com"))
        assert "200" in out
        assert "Home" in out

    def test_navigate_failure(self):
        t = self._make_tool({"success": False, "error": "Connection refused"})
        out = run(t.execute(url="http://bad.local"))
        assert "Error" in out
        assert "Connection refused" in out

    def test_navigate_exception(self):
        t = BrowserTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(side_effect=RuntimeError("boom"))
        out = run(t.execute(url="http://crash.local"))
        assert "Error" in out
        assert "boom" in out

    def test_navigate_passes_timeout(self):
        t = BrowserTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value={"success": True, "status_code": 200, "title": "X"})
        run(t.execute(url="http://x.com", timeout=5000))
        call_kwargs = t._client.call_tool.call_args
        assert call_kwargs[0][1]["timeout"] == 5000


class TestBrowserScreenshotToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserScreenshotTool:
        t = BrowserScreenshotTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_screenshot_success_returns_presigned_url(self):
        t = self._make_tool({
            "success": True,
            "presigned_url": "https://minio.local/screenshots/abc.png",
            "object_name": "screenshots/abc.png",
        })
        out = run(t.execute(url="http://example.com"))
        assert "minio.local" in out
        assert "screenshots/abc.png" in out

    def test_screenshot_failure(self):
        t = self._make_tool({"success": False, "error": "page load timeout"})
        out = run(t.execute(url="http://slow.local"))
        assert "Error" in out

    def test_screenshot_passes_full_page_flag(self):
        t = BrowserScreenshotTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value={"success": True, "presigned_url": "x", "object_name": "y"})
        run(t.execute(url="http://x.com", full_page=False))
        call_kwargs = t._client.call_tool.call_args
        assert call_kwargs[0][1]["full_page"] is False


class TestBrowserExtractTextToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserExtractTextTool:
        t = BrowserExtractTextTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_extract_text_success(self):
        t = self._make_tool({"success": True, "text": "Hello World login form"})
        out = run(t.execute(url="http://example.com"))
        assert "Hello World" in out

    def test_extract_text_failure(self):
        t = self._make_tool({"success": False, "error": "JS error"})
        out = run(t.execute(url="http://broken.local"))
        assert "Error" in out

    def test_extract_text_empty_page(self):
        t = self._make_tool({"success": True, "text": ""})
        out = run(t.execute(url="http://empty.local"))
        assert "(empty page)" in out or out == ""


class TestBrowserClickToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserClickTool:
        t = BrowserClickTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_click_success(self):
        t = self._make_tool({"success": True, "page_title": "Dashboard"})
        out = run(t.execute(url="http://example.com", selector="#login-btn"))
        assert "Dashboard" in out

    def test_click_failure(self):
        t = self._make_tool({"success": False, "error": "element not found"})
        out = run(t.execute(url="http://example.com", selector=".missing"))
        assert "Error" in out


class TestBrowserFillFormToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserFillFormTool:
        t = BrowserFillFormTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_fill_form_success(self):
        t = self._make_tool({
            "success": True,
            "response_url": "http://example.com/dashboard",
            "response_status": 200,
        })
        out = run(t.execute(
            url="http://example.com/login",
            selectors=["#username", "#password"],
            values=["admin", "secret"],
            submit_selector="#submit",
        ))
        assert "dashboard" in out.lower() or "200" in out

    def test_fill_form_length_mismatch(self):
        t = BrowserFillFormTool()
        out = run(t.execute(
            url="http://example.com",
            selectors=["#a"],
            values=["x", "y"],
        ))
        assert "same length" in out

    def test_fill_form_failure(self):
        t = self._make_tool({"success": False, "error": "submit failed"})
        out = run(t.execute(
            url="http://example.com",
            selectors=["#u"],
            values=["v"],
        ))
        assert "Error" in out


class TestBrowserGetCookiesToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserGetCookiesTool:
        t = BrowserGetCookiesTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_cookies_success(self):
        t = self._make_tool({
            "success": True,
            "cookies": [
                {
                    "name": "session",
                    "value": "abc123",
                    "domain": "example.com",
                    "path": "/",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Strict",
                }
            ],
        })
        out = run(t.execute(url="http://example.com"))
        assert "session" in out
        assert "HttpOnly" in out
        assert "Secure" in out

    def test_cookies_empty(self):
        t = self._make_tool({"success": True, "cookies": []})
        out = run(t.execute(url="http://nocookies.local"))
        assert "No cookies" in out

    def test_cookies_failure(self):
        t = self._make_tool({"success": False, "error": "network error"})
        out = run(t.execute(url="http://bad.local"))
        assert "Error" in out

    def test_cookie_flags_none(self):
        t = self._make_tool({
            "success": True,
            "cookies": [{"name": "plain", "value": "v", "domain": "x.com",
                         "path": "/", "httpOnly": False, "secure": False, "sameSite": ""}],
        })
        out = run(t.execute(url="http://x.com"))
        assert "plain" in out
        assert "none" in out


class TestBrowserGetLocalStorageToolExecute:
    def _make_tool(self, result: Dict[str, Any]) -> BrowserGetLocalStorageTool:
        t = BrowserGetLocalStorageTool()
        t._client = MagicMock()
        t._client.call_tool = AsyncMock(return_value=result)
        return t

    def test_local_storage_success(self):
        t = self._make_tool({
            "success": True,
            "local_storage": {"token": "eyJ0...", "user_id": "42"},
            "session_storage": {"cart": "[1,2,3]"},
        })
        out = run(t.execute(url="http://example.com"))
        assert "token" in out
        assert "user_id" in out
        assert "cart" in out

    def test_local_storage_empty(self):
        t = self._make_tool({
            "success": True,
            "local_storage": {},
            "session_storage": {},
        })
        out = run(t.execute(url="http://empty.local"))
        assert "0 keys" in out

    def test_local_storage_failure(self):
        t = self._make_tool({"success": False, "error": "JS disabled"})
        out = run(t.execute(url="http://bad.local"))
        assert "Error" in out


# ---------------------------------------------------------------------------
# BrowserMCPServer
# ---------------------------------------------------------------------------

from app.mcp.servers.browser_server import BrowserMCPServer


class TestBrowserMCPServerDeclarations:
    def setup_method(self):
        self.server = BrowserMCPServer()

    def test_server_name(self):
        assert self.server.name == "Browser"

    def test_server_port(self):
        assert self.server.port == 8015

    def test_tools_declared(self):
        tools = self.server.get_tools()
        names = {t.name for t in tools}
        assert "browser_navigate" in names
        assert "browser_screenshot" in names
        assert "browser_extract_text" in names
        assert "browser_click" in names
        assert "browser_fill_form" in names
        assert "browser_get_cookies" in names
        assert "browser_get_local_storage" in names

    def test_all_tools_have_descriptions(self):
        for tool in self.server.get_tools():
            assert len(tool.description) > 5, f"{tool.name} has no description"

    def test_fill_form_requires_approval(self):
        tools = {t.name: t for t in self.server.get_tools()}
        assert tools["browser_fill_form"].requires_approval is True

    def test_navigate_is_recon_phase(self):
        tools = {t.name: t for t in self.server.get_tools()}
        assert tools["browser_navigate"].phase == "recon"

    def test_click_is_scan_phase(self):
        tools = {t.name: t for t in self.server.get_tools()}
        assert tools["browser_click"].phase == "scan"


class TestBrowserMCPServerURLValidation:
    def setup_method(self):
        self.server = BrowserMCPServer()

    def test_http_allowed(self):
        from app.mcp.servers.browser_server import _validate_url
        _validate_url("http://example.com")  # should not raise

    def test_https_allowed(self):
        from app.mcp.servers.browser_server import _validate_url
        _validate_url("https://secure.example.com/path?q=1")

    def test_file_blocked(self):
        from app.mcp.servers.browser_server import _validate_url
        with pytest.raises(ValueError, match="Disallowed"):
            _validate_url("file:///etc/passwd")

    def test_javascript_blocked(self):
        from app.mcp.servers.browser_server import _validate_url
        with pytest.raises(ValueError, match="Disallowed"):
            _validate_url("javascript:alert(1)")

    def test_ftp_blocked(self):
        from app.mcp.servers.browser_server import _validate_url
        with pytest.raises(ValueError, match="Disallowed"):
            _validate_url("ftp://files.local")

    def test_data_url_blocked(self):
        from app.mcp.servers.browser_server import _validate_url
        with pytest.raises(ValueError, match="Disallowed"):
            _validate_url("data:text/html,<h1>XSS</h1>")


class TestBrowserMCPServerDispatch:
    def setup_method(self):
        self.server = BrowserMCPServer()

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            run(self.server.execute_tool("does_not_exist", {}))

    def test_navigate_calls_handler(self):
        async def _fake_navigate(params):
            return {"success": True, "status_code": 200, "title": "T"}
        self.server._navigate = _fake_navigate
        result = run(self.server.execute_tool("browser_navigate", {"url": "http://x.com"}))
        assert result["success"] is True

    def test_screenshot_calls_handler(self):
        async def _fake(params):
            return {"success": True, "presigned_url": "http://minio/x.png", "object_name": "x.png"}
        self.server._screenshot = _fake
        result = run(self.server.execute_tool("browser_screenshot", {"url": "http://x.com"}))
        assert result["success"] is True

    def test_extract_text_calls_handler(self):
        async def _fake(params):
            return {"success": True, "text": "hello"}
        self.server._extract_text = _fake
        result = run(self.server.execute_tool("browser_extract_text", {"url": "http://x.com"}))
        assert result["text"] == "hello"

    def test_click_calls_handler(self):
        async def _fake(params):
            return {"success": True, "page_title": "Result"}
        self.server._click = _fake
        result = run(self.server.execute_tool("browser_click", {"url": "http://x.com", "selector": "#btn"}))
        assert result["page_title"] == "Result"

    def test_fill_form_calls_handler(self):
        async def _fake(params):
            return {"success": True, "response_url": "http://x.com/done", "response_status": 200}
        self.server._fill_form = _fake
        result = run(self.server.execute_tool("browser_fill_form", {
            "url": "http://x.com", "selectors": [], "values": []
        }))
        assert result["success"] is True

    def test_get_cookies_calls_handler(self):
        async def _fake(params):
            return {"success": True, "cookies": []}
        self.server._get_cookies = _fake
        result = run(self.server.execute_tool("browser_get_cookies", {"url": "http://x.com"}))
        assert result["success"] is True

    def test_get_local_storage_calls_handler(self):
        async def _fake(params):
            return {"success": True, "local_storage": {}, "session_storage": {}}
        self.server._get_local_storage = _fake
        result = run(self.server.execute_tool("browser_get_local_storage", {"url": "http://x.com"}))
        assert result["success"] is True


class TestBrowserMCPServerNavigateInternal:
    """Tests for _navigate internals when Playwright is unavailable (mocked)."""

    def setup_method(self):
        self.server = BrowserMCPServer()

    def test_navigate_validates_url(self):
        result = run(self.server._navigate({"url": "file:///etc/passwd"}))
        assert result["success"] is False
        assert "Disallowed" in result["error"]

    def test_navigate_playwright_not_installed(self):
        # Patch _get_page to raise RuntimeError (simulating no Playwright)
        async def _fake_get_page(url, timeout=30000):
            raise RuntimeError("Playwright is not installed")
        self.server._get_page = _fake_get_page
        result = run(self.server._navigate({"url": "http://example.com"}))
        assert result["success"] is False
        assert "Playwright" in result["error"]

    def test_screenshot_validates_url(self):
        result = run(self.server._screenshot({"url": "ftp://bad.host"}))
        assert result["success"] is False
        assert "Disallowed" in result["error"]

    def test_extract_text_validates_url(self):
        result = run(self.server._extract_text({"url": "javascript:alert(1)"}))
        assert result["success"] is False

    def test_click_validates_url(self):
        result = run(self.server._click({"url": "data:text/html,x", "selector": "#x"}))
        assert result["success"] is False

    def test_get_cookies_validates_url(self):
        result = run(self.server._get_cookies({"url": "file:///tmp/x"}))
        assert result["success"] is False

    def test_get_local_storage_validates_url(self):
        result = run(self.server._get_local_storage({"url": "file:///tmp/x"}))
        assert result["success"] is False


# ---------------------------------------------------------------------------
# ToolRegistry integration
# ---------------------------------------------------------------------------


class TestBrowserToolsInRegistry:
    def test_browser_navigate_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_navigate") is not None

    def test_browser_screenshot_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_screenshot") is not None

    def test_browser_extract_text_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_extract_text") is not None

    def test_browser_click_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_click") is not None

    def test_browser_fill_form_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_fill_form") is not None

    def test_browser_get_cookies_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_get_cookies") is not None

    def test_browser_get_local_storage_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("browser_get_local_storage") is not None
