"""
Worker Client — Async HTTP Client for the Worker Node

remote WorkerServer microservice.  Falls back to local execution when the
worker is unavailable (degraded mode).

Features
--------
  - Async HTTP dispatch via httpx
  - Shared-secret authentication (bearer token)
  - Automatic retry with exponential back-off (configurable)
  - Circuit-breaker pattern: after N consecutive failures, falls back to local
  - Per-request timeout configurable

Environment Variables
---------------------
  WORKER_URL           — base URL of the WorkerServer (default http://worker:9443)
  WORKER_SHARED_SECRET — must match the value set on the worker node
  WORKER_TIMEOUT       — HTTP request timeout in seconds (default 310)
  WORKER_MAX_RETRIES   — maximum retry attempts for transient errors (default 2)
  WORKER_FALLBACK      — if 'true', fall back to local when worker unavailable (default true)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

WORKER_URL: str = os.getenv("WORKER_URL", "http://worker:9443")
WORKER_SHARED_SECRET: str = os.getenv("WORKER_SHARED_SECRET", "")
WORKER_TIMEOUT: float = float(os.getenv("WORKER_TIMEOUT", "310"))
WORKER_MAX_RETRIES: int = int(os.getenv("WORKER_MAX_RETRIES", "2"))
WORKER_FALLBACK: bool = os.getenv("WORKER_FALLBACK", "true").lower() == "true"

# Circuit-breaker state
_consecutive_failures: int = 0
_CIRCUIT_OPEN_THRESHOLD: int = 5  # open after 5 consecutive failures
_circuit_reset_at: float = 0.0
_CIRCUIT_RESET_AFTER: float = 60.0  # retry after 60 seconds


class WorkerUnavailableError(Exception):
    """Raised when the worker node is unreachable and fallback is disabled."""


class WorkerClient:
    """
    Async HTTP client that dispatches tool execution jobs to the WorkerServer.

    Usage::

        client = WorkerClient()
        result = await client.execute(
            tool_name="execute_naabu",
            server_name="naabu",
            params={"target": "192.168.1.0/24", "ports": "top-1000"},
        )
        print(result)
    """

    def __init__(
        self,
        base_url: str = WORKER_URL,
        secret: str = WORKER_SHARED_SECRET,
        timeout: float = WORKER_TIMEOUT,
        max_retries: int = WORKER_MAX_RETRIES,
        fallback_to_local: bool = WORKER_FALLBACK,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._secret = secret
        self._timeout = timeout
        self._max_retries = max_retries
        self._fallback = fallback_to_local
        self._headers: Dict[str, str] = {}
        if self._secret:
            self._headers["Authorization"] = f"Bearer {self._secret}"
        self._headers["Content-Type"] = "application/json"
        self._headers["User-Agent"] = "UniVex-WorkerClient/2.1.0"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute(
        self,
        tool_name: str,
        server_name: str,
        params: Dict[str, Any],
        timeout: Optional[float] = None,
        job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Dispatch *tool_name* on *server_name* with *params* to the worker node.

        Returns a result dict with ``success``, ``result``, ``error``, and ``duration_ms``.
        If the worker is unavailable and fallback is enabled, returns a fallback error dict.
        """
        global _consecutive_failures, _circuit_reset_at

        # Circuit-breaker: check if circuit is open
        if _consecutive_failures >= _CIRCUIT_OPEN_THRESHOLD:
            now = time.monotonic()
            if now < _circuit_reset_at:
                logger.warning(
                    "WorkerClient circuit open — falling back to local execution "
                    "(resets in %.0fs)", _circuit_reset_at - now,
                )
                return self._fallback_result(tool_name, server_name, "Worker circuit is open")
            else:
                # Half-open: try one request
                _consecutive_failures = 0

        payload: Dict[str, Any] = {
            "tool_name": tool_name,
            "server_name": server_name,
            "params": params,
            "timeout": round(timeout or self._timeout - 5),
        }
        if job_id:
            payload["job_id"] = job_id

        for attempt in range(self._max_retries + 1):
            try:
                result = await self._post(payload, timeout or self._timeout)
                _consecutive_failures = 0  # reset on success
                return result
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                _consecutive_failures += 1
                if _consecutive_failures >= _CIRCUIT_OPEN_THRESHOLD:
                    _circuit_reset_at = time.monotonic() + _CIRCUIT_RESET_AFTER
                logger.warning(
                    "WorkerClient attempt %d/%d failed: %s",
                    attempt + 1, self._max_retries + 1, exc,
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(2 ** attempt)  # exponential back-off
            except Exception as exc:
                _consecutive_failures += 1
                logger.error("WorkerClient unexpected error: %s", exc, exc_info=True)
                break

        return self._fallback_result(tool_name, server_name, "Worker node unreachable")

    async def health_check(self) -> bool:
        """Return True if the worker node is reachable and healthy."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self._base_url}/health",
                    headers=self._headers,
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def get_capabilities(self) -> Dict[str, Any]:
        """Return the worker node's registered MCP servers and tools."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self._base_url}/api/worker/capabilities",
                    headers=self._headers,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.warning("WorkerClient.get_capabilities failed: %s", exc)
            return {"worker_id": "unknown", "servers": []}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _post(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        """POST the execute request and return the parsed JSON result."""
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{self._base_url}/api/worker/execute",
                json=payload,
                headers=self._headers,
            )
            if resp.status_code == 401:
                raise PermissionError("Worker authentication failed — check WORKER_SHARED_SECRET")
            if resp.status_code == 503:
                raise RuntimeError("Worker is at capacity")
            resp.raise_for_status()
            return resp.json()

    def _fallback_result(
        self, tool_name: str, server_name: str, reason: str
    ) -> Dict[str, Any]:
        """Return an error dict suitable for caller inspection."""
        if not self._fallback:
            raise WorkerUnavailableError(
                f"Worker node unavailable for {server_name}.{tool_name}: {reason}"
            )
        return {
            "job_id": "",
            "tool_name": tool_name,
            "server_name": server_name,
            "success": False,
            "result": None,
            "error": f"Worker unavailable ({reason}) — running in degraded mode",
            "duration_ms": 0.0,
            "fallback": True,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_client: Optional[WorkerClient] = None


def get_client() -> WorkerClient:
    """Return (or lazily create) the module-level WorkerClient singleton."""
    global _client
    if _client is None:
        _client = WorkerClient()
    return _client


__all__ = [
    "WorkerClient",
    "WorkerUnavailableError",
    "get_client",
    "WORKER_URL",
    "WORKER_SHARED_SECRET",
    "WORKER_TIMEOUT",
    "WORKER_MAX_RETRIES",
    "WORKER_FALLBACK",
]
