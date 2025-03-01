"""
OOB Tool — Out-of-Band Attack Coordination Tool

callback URLs, monitors for inbound callbacks, and correlates them back to
the originating penetration test.

Tools:
  oob_generate_url  — generate a unique callback URL for a finding
  oob_check         — check if a callback has been received for a token
  oob_wait          — block until a callback arrives (or timeout)
  oob_stats         — return OOB listener statistics
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.oob.oob_listener import OOBListener

logger = logging.getLogger(__name__)

_OOB_EXTERNAL_IP = os.getenv("OOB_EXTERNAL_IP", "127.0.0.1")
_OOB_HTTP_PORT = int(os.getenv("OOB_HTTP_PORT", "8080"))

# Module-level singleton so all tool instances share the same listener
_listener: Optional[OOBListener] = None


def get_listener() -> OOBListener:
    """Return (or lazily create) the module-level OOBListener singleton."""
    global _listener
    if _listener is None:
        _listener = OOBListener(
            external_ip=_OOB_EXTERNAL_IP,
            http_port=_OOB_HTTP_PORT,
        )
    return _listener


class OOBGenerateURLTool(BaseTool):
    """
    Generate a unique out-of-band callback URL for a given finding / test ID.

    The token is HMAC-signed to prevent forgery.  Pre-register the token so
    the callback store is ready before the exploit payload fires.
    """

    TOOL_NAME = "oob_generate_url"

    def __init__(self, listener: Optional[OOBListener] = None) -> None:
        self._listener = listener or get_listener()
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Generate a unique out-of-band callback URL for a penetration test finding. "
                "Embed this URL in payloads (SSRF, XXE, RCE) to detect blind vulnerabilities. "
                "Returns both an HTTP URL and a DNS hostname."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "test_id": {
                        "type": "string",
                        "description": "Unique identifier for the test or finding (e.g. 'ssrf-login-1').",
                    },
                    "channel": {
                        "type": "string",
                        "enum": ["http", "dns", "smtp"],
                        "description": "Callback channel to use (default: http).",
                        "default": "http",
                    },
                },
                "required": ["test_id"],
            },
        )

    async def execute(self, test_id: str, channel: str = "http", **kwargs) -> str:
        try:
            token = self._listener.generate_token(test_id)
            await self._listener.register_token(token)
            url = self._listener.callback_url(token, channel=channel)
            return (
                f"OOB callback URL generated for test '{test_id}':\n"
                f"  Token   : {token}\n"
                f"  Channel : {channel}\n"
                f"  URL     : {url}\n\n"
                f"Embed this URL in your payload. Call oob_check with token='{token}' "
                f"after the exploit fires."
            )
        except Exception as exc:
            logger.error("OOBGenerateURLTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class OOBCheckTool(BaseTool):
    """
    Check whether a callback has been received for a given token (non-blocking).
    """

    TOOL_NAME = "oob_check"

    def __init__(self, listener: Optional[OOBListener] = None) -> None:
        self._listener = listener or get_listener()
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Check (non-blocking) whether any out-of-band callbacks have been received "
                "for the given token. Returns all recorded callbacks."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "Token returned by oob_generate_url.",
                    },
                },
                "required": ["token"],
            },
        )

    async def execute(self, token: str, **kwargs) -> str:
        try:
            callbacks = await self._listener.get_callbacks(token)
            if not callbacks:
                return f"No callbacks received yet for token '{token}'."
            lines = [f"OOB callbacks for token '{token}' ({len(callbacks)} received):"]
            for i, cb in enumerate(callbacks, start=1):
                lines.append(
                    f"  [{i}] channel={cb.channel} from={cb.source_ip}:{cb.source_port} "
                    f"method={cb.method} path={cb.path} at={cb.to_dict()['datetime']}"
                )
            return "\n".join(lines)
        except Exception as exc:
            logger.error("OOBCheckTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class OOBWaitTool(BaseTool):
    """
    Block until a callback arrives for the given token or the timeout expires.
    """

    TOOL_NAME = "oob_wait"

    def __init__(self, listener: Optional[OOBListener] = None) -> None:
        self._listener = listener or get_listener()
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description=(
                "Wait (blocking) for an out-of-band callback for the given token. "
                "Returns the first callback received or a timeout message."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "Token to wait for.",
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Maximum seconds to wait (default 30).",
                        "default": 30.0,
                    },
                },
                "required": ["token"],
            },
        )

    async def execute(self, token: str, timeout: float = 30.0, **kwargs) -> str:
        try:
            cb = await self._listener.wait_for_callback(token, timeout=timeout)
            if cb is None:
                return (
                    f"Timeout: no callback received for token '{token}' within {timeout}s. "
                    f"The target may not be vulnerable, the payload may not have triggered, "
                    f"or the callback URL may be unreachable."
                )
            return (
                f"OOB callback received for token '{token}'!\n"
                f"  Channel    : {cb.channel}\n"
                f"  Source     : {cb.source_ip}:{cb.source_port}\n"
                f"  Method     : {cb.method}\n"
                f"  Path       : {cb.path}\n"
                f"  Timestamp  : {cb.to_dict()['datetime']}\n"
                f"\nThis confirms a blind {cb.channel.upper()} out-of-band interaction — "
                f"the target is likely vulnerable."
            )
        except Exception as exc:
            logger.error("OOBWaitTool error: %s", exc, exc_info=True)
            return f"Error: {exc}"


class OOBStatsTool(BaseTool):
    """Return OOB listener runtime statistics."""

    TOOL_NAME = "oob_stats"

    def __init__(self, listener: Optional[OOBListener] = None) -> None:
        self._listener = listener or get_listener()
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.TOOL_NAME,
            description="Return OOB listener runtime statistics (ports, external IP, running status).",
            parameters={
                "type": "object",
                "properties": {},
                "required": [],
            },
        )

    async def execute(self, **kwargs) -> str:
        stats = self._listener.stats()
        tokens = await self._listener.all_tokens()
        return (
            f"OOB Listener status:\n"
            f"  Running      : {stats['running']}\n"
            f"  External IP  : {stats['external_ip']}\n"
            f"  HTTP port    : {stats['http_port']}\n"
            f"  DNS port     : {stats['dns_port']}\n"
            f"  SMTP port    : {stats['smtp_port']}\n"
            f"  Active tokens: {len(tokens)}\n"
        )


__all__ = [
    "OOBGenerateURLTool",
    "OOBCheckTool",
    "OOBWaitTool",
    "OOBStatsTool",
    "get_listener",
]
