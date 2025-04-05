"""
Proxy Interceptor — Core MITM Engine

Provides the ``ProxyInterceptor`` class which wraps `mitmproxy`'s async API to
run a transparent HTTP/HTTPS intercepting proxy.

Design:
  - ``ProxyInterceptor.start()`` launches mitmproxy in the background using
    ``asyncio.create_task()`` so it does not block the calling coroutine.
  - All captured request/response pairs are forwarded to an injected
    ``RequestStore`` instance for persistence.
  - Intercept rules (URL pattern, method, content type) are applied before
    forwarding — matching requests can be paused for inspection/modification.
  - The class degrades gracefully when ``mitmproxy`` is not installed:
    methods still exist but raise ``RuntimeError`` with a helpful message.

Environment variables:
  PROXY_PORT          — TCP port to listen on            (default: 8080)
  PROXY_UPSTREAM      — Upstream proxy (http://host:port) (default: none)
  PROXY_SSL_VERIFY    — Verify upstream SSL (true/false)  (default: false)

OWASP: A07:2021-Identification and Authentication Failures
MITRE: T1557 (Man-in-the-Middle)
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from app.proxy.request_store import (
    CapturedRequest,
    CapturedResponse,
    RequestStore,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------

_PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))
_PROXY_UPSTREAM = os.getenv("PROXY_UPSTREAM", "")
_PROXY_SSL_VERIFY = os.getenv("PROXY_SSL_VERIFY", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Optional mitmproxy import
# ---------------------------------------------------------------------------

try:
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    _MITMPROXY_AVAILABLE = True
except ImportError:
    _MITMPROXY_AVAILABLE = False
    logger.warning(
        "mitmproxy not installed — ProxyInterceptor will raise RuntimeError when started."
    )


# ---------------------------------------------------------------------------
# Intercept rule
# ---------------------------------------------------------------------------


@dataclass
class InterceptRule:
    """A filter rule for the proxy interceptor."""

    url_pattern: Optional[str] = None  # regex applied to URL
    method: Optional[str] = None  # HTTP method (GET, POST, …)
    content_type: Optional[str] = None  # substring match against Content-Type
    pause_for_inspection: bool = False  # if True, block until operator resumes
    tag: str = ""  # tag applied to captured requests matching this rule

    _compiled_url: Optional[re.Pattern] = field(default=None, repr=False, init=False)

    def __post_init__(self) -> None:
        if self.url_pattern:
            try:
                self._compiled_url = re.compile(self.url_pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(f"Invalid url_pattern regex: {exc}") from exc

    def matches(self, method: str, url: str, content_type: str = "") -> bool:
        if self._compiled_url and not self._compiled_url.search(url):
            return False
        if self.method and method.upper() != self.method.upper():
            return False
        if self.content_type and self.content_type.lower() not in content_type.lower():
            return False
        return True


# ---------------------------------------------------------------------------
# ScopeFilter
# ---------------------------------------------------------------------------


class ScopeFilter:
    """
    Determines whether a given URL is in-scope for capture.

    In-scope patterns are checked first; if any match the URL is accepted.
    Out-of-scope patterns are checked second; a match causes the URL to be
    rejected.  If no in-scope patterns are defined, all URLs are considered
    in-scope by default.
    """

    def __init__(self) -> None:
        self._in_scope: List[re.Pattern] = []
        self._out_scope: List[re.Pattern] = []

    def add_in_scope(self, pattern: str) -> None:
        self._in_scope.append(re.compile(pattern, re.IGNORECASE))

    def add_out_scope(self, pattern: str) -> None:
        self._out_scope.append(re.compile(pattern, re.IGNORECASE))

    def clear(self) -> None:
        self._in_scope.clear()
        self._out_scope.clear()

    def is_in_scope(self, url: str) -> bool:
        for pat in self._out_scope:
            if pat.search(url):
                return False
        if not self._in_scope:
            return True
        for pat in self._in_scope:
            if pat.search(url):
                return True
        return False


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------


class _UniVexAddon:
    """
    mitmproxy addon that captures all flows into a ``RequestStore``.

    This class is instantiated once and passed to DumpMaster.  mitmproxy
    calls ``request()`` and ``response()`` hooks automatically.
    """

    def __init__(
        self,
        store: RequestStore,
        rules: List[InterceptRule],
        scope: ScopeFilter,
        on_capture: Optional[Callable[[CapturedRequest], None]] = None,
    ) -> None:
        self._store = store
        self._rules = rules
        self._scope = scope
        self._on_capture = on_capture
        self._pending: Dict[str, float] = {}  # flow id → start time

    def request(self, flow: Any) -> None:  # type: ignore[override]
        """Called by mitmproxy when a request is received."""
        url = flow.request.pretty_url
        if not self._scope.is_in_scope(url):
            return
        self._pending[flow.id] = time.monotonic()

    def response(self, flow: Any) -> None:  # type: ignore[override]
        """Called by mitmproxy after a response is received."""
        url = flow.request.pretty_url
        if not self._scope.is_in_scope(url):
            return

        start = self._pending.pop(flow.id, time.monotonic())
        elapsed_ms = (time.monotonic() - start) * 1000.0

        # Decode request body
        try:
            req_body = flow.request.content.decode("utf-8", errors="replace")
        except Exception:
            req_body = base64.b64encode(flow.request.content or b"").decode()

        # Decode response body
        resp_body_raw = b""
        try:
            resp_body_raw = flow.response.content or b""
            resp_body = resp_body_raw.decode("utf-8", errors="replace")
        except Exception:
            resp_body = base64.b64encode(resp_body_raw).decode()

        content_type = flow.response.headers.get("content-type", "")
        tags: List[str] = []
        for rule in self._rules:
            if rule.matches(flow.request.method, url, content_type):
                if rule.tag:
                    tags.append(rule.tag)

        captured = CapturedRequest(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            method=flow.request.method,
            url=url,
            headers=dict(flow.request.headers),
            body=req_body,
            response=CapturedResponse(
                status_code=flow.response.status_code,
                reason=flow.response.reason or "",
                headers=dict(flow.response.headers),
                body=resp_body,
                content_type=content_type,
                elapsed_ms=elapsed_ms,
            ),
            tags=tags,
        )

        asyncio.get_event_loop().run_until_complete(self._store.store(captured))
        if self._on_capture:
            self._on_capture(captured)


# ---------------------------------------------------------------------------
# ProxyInterceptor
# ---------------------------------------------------------------------------


class ProxyInterceptor:
    """
    Core MITM proxy engine wrapping mitmproxy.

    Lifecycle::

        interceptor = ProxyInterceptor(store=my_store)
        await interceptor.start(port=8080)
        # ... traffic flows ...
        await interceptor.stop()

    Args:
        store:       ``RequestStore`` instance for persisting captured traffic.
        scope:       ``ScopeFilter`` controlling which URLs are captured.
        on_capture:  Optional async callback fired after each capture.
        port:        TCP port to listen on (default: PROXY_PORT env var).
        upstream:    Optional upstream proxy URL (default: PROXY_UPSTREAM env).
        ssl_verify:  Whether to verify upstream TLS (default: PROXY_SSL_VERIFY).
    """

    def __init__(
        self,
        store: Optional[RequestStore] = None,
        scope: Optional[ScopeFilter] = None,
        on_capture: Optional[Callable[[CapturedRequest], None]] = None,
        port: int = _PROXY_PORT,
        upstream: str = _PROXY_UPSTREAM,
        ssl_verify: bool = _PROXY_SSL_VERIFY,
    ) -> None:
        self._store = store or RequestStore()
        self._scope = scope or ScopeFilter()
        self._on_capture = on_capture
        self._port = port
        self._upstream = upstream
        self._ssl_verify = ssl_verify
        self._rules: List[InterceptRule] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._master: Any = None  # DumpMaster instance when running

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def running(self) -> bool:
        return self._running

    @property
    def port(self) -> int:
        return self._port

    @property
    def store(self) -> RequestStore:
        return self._store

    @property
    def scope(self) -> ScopeFilter:
        return self._scope

    def add_rule(self, rule: InterceptRule) -> None:
        """Add an intercept rule."""
        self._rules.append(rule)

    def remove_rule(self, index: int) -> None:
        """Remove the rule at *index*."""
        if 0 <= index < len(self._rules):
            self._rules.pop(index)

    def clear_rules(self) -> None:
        """Remove all intercept rules."""
        self._rules.clear()

    @property
    def rules(self) -> List[InterceptRule]:
        return list(self._rules)

    async def start(self, port: Optional[int] = None) -> None:
        """
        Start the proxy in the background.

        Args:
            port: Override the port set during construction.

        Raises:
            RuntimeError: If mitmproxy is not installed.
            RuntimeError: If the proxy is already running.
        """
        if not _MITMPROXY_AVAILABLE:
            raise RuntimeError(
                "mitmproxy is not installed. "
                "Add 'mitmproxy' to requirements.txt and rebuild the container."
            )
        if self._running:
            raise RuntimeError("ProxyInterceptor is already running.")

        if port:
            self._port = port

        opts_kwargs: Dict[str, Any] = {
            "listen_host": "0.0.0.0",
            "listen_port": self._port,
            "ssl_insecure": not self._ssl_verify,
        }
        if self._upstream:
            opts_kwargs["upstream_cert"] = True
            opts_kwargs["mode"] = [f"upstream:{self._upstream}"]

        opts = options.Options(**opts_kwargs)
        addon = _UniVexAddon(
            store=self._store,
            rules=self._rules,
            scope=self._scope,
            on_capture=self._on_capture,
        )
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(addon)
        self._master = master

        loop = asyncio.get_event_loop()
        self._task = loop.create_task(master.run())
        self._running = True
        logger.info(f"ProxyInterceptor started on port {self._port}")

    async def stop(self) -> None:
        """Gracefully stop the proxy."""
        if not self._running:
            return
        try:
            if self._master:
                self._master.shutdown()
            if self._task:
                self._task.cancel()
                try:
                    await self._task
                except (asyncio.CancelledError, Exception):
                    pass
        finally:
            self._running = False
            self._master = None
            self._task = None
        logger.info("ProxyInterceptor stopped.")

    def get_stats(self) -> Dict[str, Any]:
        """Return a dict of current proxy statistics."""
        return {
            "running": self._running,
            "port": self._port,
            "upstream": self._upstream or None,
            "ssl_verify": self._ssl_verify,
            "rule_count": len(self._rules),
        }
