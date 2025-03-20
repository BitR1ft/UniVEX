"""
Browser MCP Server — Isolated Headless Browser (Port 8015)

dedicated sandboxed container. All browser actions are executed here, never
in the main API process.

Tools exposed:
  browser_navigate        — navigate to URL, return status + title
  browser_screenshot      — full-page screenshot → upload to MinIO → presigned URL
  browser_extract_text    — extract visible text for AI analysis
  browser_click           — click a CSS-selector element
  browser_fill_form       — fill multiple form fields + optional submit
  browser_get_cookies     — extract all cookies with security flags
  browser_get_local_storage — extract localStorage + sessionStorage

Environment variables:
  MINIO_ENDPOINT          — MinIO host:port (default minio:9000)
  MINIO_ACCESS_KEY        — MinIO access key
  MINIO_SECRET_KEY        — MinIO secret key
  MINIO_BUCKET_SCREENSHOTS — bucket name (default univex-screenshots)
  BROWSER_TIMEOUT_MS      — default navigation timeout ms (default 30000)
"""

from __future__ import annotations

import io
import logging
import os
import re
import uuid
from typing import Any, Dict, List

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

_MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
_MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "univex")
_MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "univex123")
_MINIO_BUCKET = os.getenv("MINIO_BUCKET_SCREENSHOTS", "univex-screenshots")
_BROWSER_TIMEOUT_MS = int(os.getenv("BROWSER_TIMEOUT_MS", "30000"))

# Allowed URL schemes — block file:// and other dangerous schemes
_ALLOWED_SCHEMES = re.compile(r"^https?://", re.IGNORECASE)


def _validate_url(url: str) -> None:
    """Raise ValueError if *url* uses a disallowed scheme."""
    if not _ALLOWED_SCHEMES.match(url):
        raise ValueError(f"Disallowed URL scheme. Only http:// and https:// are permitted. Got: {url!r}")


class BrowserMCPServer(MCPServer):
    """
    MCP Server that drives a headless Chromium browser via Playwright.

    In production this server runs inside a dedicated Docker container
    (service name: browser) so that all browser traffic is isolated from
    the main application network.
    """

    PORT = 8015

    def __init__(self) -> None:
        super().__init__(
            name="Browser",
            description="Isolated headless browser automation server using Playwright",
            port=self.PORT,
        )

    # ------------------------------------------------------------------
    # Tool declarations
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="browser_navigate",
                description="Navigate to a URL and return HTTP status code and page title.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to navigate to."},
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in milliseconds.",
                            "default": _BROWSER_TIMEOUT_MS,
                        },
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="browser_screenshot",
                description="Capture a full-page screenshot and upload it to MinIO. Returns a presigned URL.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to screenshot."},
                        "full_page": {
                            "type": "boolean",
                            "description": "Capture full scrollable page.",
                            "default": True,
                        },
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="browser_extract_text",
                description="Extract visible plain text content from a URL.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to extract text from."},
                        "max_chars": {
                            "type": "integer",
                            "description": "Maximum characters to return.",
                            "default": 50_000,
                        },
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="browser_click",
                description="Click a DOM element on a page by CSS selector.",
                phase="scan",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Page URL."},
                        "selector": {"type": "string", "description": "CSS selector to click."},
                        "wait_after_ms": {
                            "type": "integer",
                            "description": "Wait time after click in ms.",
                            "default": 1_000,
                        },
                    },
                    "required": ["url", "selector"],
                },
            ),
            MCPTool(
                name="browser_fill_form",
                description="Fill HTML form fields and optionally submit the form.",
                phase="scan",
                requires_approval=True,
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL of page with form."},
                        "selectors": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "CSS selectors for form fields.",
                        },
                        "values": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Values to fill (parallel to selectors).",
                        },
                        "submit_selector": {
                            "type": "string",
                            "description": "CSS selector of submit button (optional).",
                            "default": "",
                        },
                    },
                    "required": ["url", "selectors", "values"],
                },
            ),
            MCPTool(
                name="browser_get_cookies",
                description="Extract all cookies from a URL including HttpOnly, Secure, SameSite flags.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to load."},
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="browser_get_local_storage",
                description="Extract localStorage and sessionStorage key-value pairs from a page.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to load."},
                    },
                    "required": ["url"],
                },
            ),
        ]

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        dispatch: Dict[str, Any] = {
            "browser_navigate": self._navigate,
            "browser_screenshot": self._screenshot,
            "browser_extract_text": self._extract_text,
            "browser_click": self._click,
            "browser_fill_form": self._fill_form,
            "browser_get_cookies": self._get_cookies,
            "browser_get_local_storage": self._get_local_storage,
        }
        handler = dispatch.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        return await handler(params)

    # ------------------------------------------------------------------
    # Internal implementations — use Playwright when available
    # ------------------------------------------------------------------

    async def _get_page(self, url: str, timeout: int = _BROWSER_TIMEOUT_MS):
        """
        Launch a Playwright browser page and navigate to *url*.

        Returns ``(playwright_context, page, response_status)`` tuple.  The caller is
        responsible for closing the context when done.
        """
        _validate_url(url)
        try:
            from playwright.async_api import async_playwright  # type: ignore[import]

            pw = await async_playwright().start()
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                ],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (UniVex-Scanner/2.1) AppleWebKit/537.36",
            )
            page = await context.new_page()
            response = await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            status_code = response.status if response else 200
            return pw, browser, context, page, status_code
        except ImportError:
            raise RuntimeError(
                "Playwright is not installed. Run: pip install playwright && playwright install chromium"
            )

    async def _navigate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        timeout: int = params.get("timeout", _BROWSER_TIMEOUT_MS)
        try:
            _validate_url(url)
            pw, browser, context, page, status_code = await self._get_page(url, timeout)
            try:
                title = await page.title()
                return {
                    "success": True,
                    "url": url,
                    "final_url": page.url,
                    "status_code": status_code,
                    "title": title,
                }
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_navigate error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _screenshot(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        full_page: bool = params.get("full_page", True)
        try:
            _validate_url(url)
            pw, browser, context, page, _status = await self._get_page(url)
            try:
                png_bytes: bytes = await page.screenshot(full_page=full_page, type="png")
                object_name = f"screenshots/{uuid.uuid4().hex}.png"
                presigned_url = await self._upload_to_minio(png_bytes, object_name)
                return {
                    "success": True,
                    "url": url,
                    "object_name": object_name,
                    "presigned_url": presigned_url,
                    "size_bytes": len(png_bytes),
                }
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_screenshot error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _upload_to_minio(self, data: bytes, object_name: str) -> str:
        """Upload *data* to MinIO and return a presigned download URL."""
        try:
            from miniopy_async import Minio  # type: ignore[import]

            client = Minio(
                _MINIO_ENDPOINT,
                access_key=_MINIO_ACCESS_KEY,
                secret_key=_MINIO_SECRET_KEY,
                secure=False,
            )
            # Ensure bucket exists
            exists = await client.bucket_exists(_MINIO_BUCKET)
            if not exists:
                await client.make_bucket(_MINIO_BUCKET)
            await client.put_object(
                _MINIO_BUCKET,
                object_name,
                io.BytesIO(data),
                length=len(data),
                content_type="image/png",
            )
            from datetime import timedelta

            url = await client.presigned_get_object(
                _MINIO_BUCKET, object_name, expires=timedelta(hours=24)
            )
            return url
        except Exception as exc:
            logger.warning("MinIO upload failed: %s — returning empty URL", exc)
            return f"minio://{_MINIO_BUCKET}/{object_name}"

    async def _extract_text(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        max_chars: int = params.get("max_chars", 50_000)
        try:
            _validate_url(url)
            pw, browser, context, page, _status = await self._get_page(url)
            try:
                # Remove script/style tags and extract innerText
                text: str = await page.evaluate(
                    """() => {
                        const clone = document.cloneNode(true);
                        clone.querySelectorAll('script,style,noscript').forEach(el => el.remove());
                        return document.body ? document.body.innerText : '';
                    }"""
                )
                return {"success": True, "url": url, "text": text[:max_chars]}
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_extract_text error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _click(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        selector: str = params["selector"]
        wait_after_ms: int = params.get("wait_after_ms", 1_000)
        try:
            _validate_url(url)
            pw, browser, context, page, _status = await self._get_page(url)
            try:
                await page.click(selector)
                await page.wait_for_timeout(wait_after_ms)
                title = await page.title()
                return {"success": True, "url": url, "page_title": title, "final_url": page.url}
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_click error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _fill_form(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        selectors: List[str] = params["selectors"]
        values: List[str] = params["values"]
        submit_selector: str = params.get("submit_selector", "")
        try:
            _validate_url(url)
            pw, browser, context, page, _status = await self._get_page(url)
            try:
                for selector, value in zip(selectors, values):
                    await page.fill(selector, value)
                if submit_selector:
                    await page.click(submit_selector)
                    await page.wait_for_load_state("domcontentloaded")
                return {
                    "success": True,
                    "url": url,
                    "response_url": page.url,
                    "response_status": 200,
                }
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_fill_form error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _get_cookies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        try:
            _validate_url(url)
            pw, browser, context, page, _status = await self._get_page(url)
            try:
                raw_cookies = await context.cookies()
                cookies = [
                    {
                        "name": c.get("name"),
                        "value": c.get("value"),
                        "domain": c.get("domain"),
                        "path": c.get("path"),
                        "httpOnly": c.get("httpOnly", False),
                        "secure": c.get("secure", False),
                        "sameSite": c.get("sameSite", ""),
                    }
                    for c in raw_cookies
                ]
                return {"success": True, "url": url, "cookies": cookies}
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_get_cookies error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}

    async def _get_local_storage(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url: str = params["url"]
        try:
            _validate_url(url)
            pw, browser, context, page, _status = await self._get_page(url)
            try:
                local_storage: Dict[str, str] = await page.evaluate(
                    "() => Object.fromEntries(Object.entries(localStorage))"
                )
                session_storage: Dict[str, str] = await page.evaluate(
                    "() => Object.fromEntries(Object.entries(sessionStorage))"
                )
                return {
                    "success": True,
                    "url": url,
                    "local_storage": local_storage,
                    "session_storage": session_storage,
                }
            finally:
                await context.close()
                await browser.close()
                await pw.stop()
        except Exception as exc:
            logger.error("browser_get_local_storage error: %s", exc, exc_info=True)
            return {"success": False, "error": str(exc)}


__all__ = ["BrowserMCPServer"]
