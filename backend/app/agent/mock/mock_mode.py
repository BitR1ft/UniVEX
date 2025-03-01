"""
MockMode — MOCK_MODE=true environment integration for UniVex
──────────────────────────────────────────────────────────────
When the environment variable ``MOCK_MODE=true`` is set, MockMode swaps all
real LLM providers and MCP tool servers for their mock equivalents, enabling
complete integration testing without live API credentials or Docker.

Usage::

    # In tests or CI:
    os.environ["MOCK_MODE"] = "true"

    mock_mode = MockMode()
    mock_mode.activate()

    # Run your integration test
    result = await my_agent.run(state, task)

    # Inspect what happened
    assert mock_mode.llm.call_count > 0
    assert mock_mode.tools.was_called("naabu")

    mock_mode.deactivate()
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.agent.mock.mock_llm import MockLLMProvider
from app.agent.mock.mock_tools import MockToolServer

logger = logging.getLogger(__name__)

# Environment variable that activates mock mode
MOCK_MODE_ENV_VAR = "MOCK_MODE"


def is_mock_mode() -> bool:
    """Return True if MOCK_MODE environment variable is set to a truthy value."""
    val = os.environ.get(MOCK_MODE_ENV_VAR, "").strip().lower()
    return val in ("1", "true", "yes", "on")


class MockMode:
    """
    Context manager that activates/deactivates mock mode.

    In mock mode:
      - All LLM providers are replaced by MockLLMProvider
      - All MCP tool servers are replaced by MockToolServer
      - No real network calls are made
      - All interactions are recorded for test assertion

    Can be used as a context manager or manually activated/deactivated.
    """

    def __init__(
        self,
        llm_responses: Optional[List[str]] = None,
        llm_keyword_map: Optional[Dict[str, str]] = None,
        llm_default_response: str = "[MOCK] OK",
        tool_outputs: Optional[Dict[str, Any]] = None,
        fail_tools: Optional[Dict[str, str]] = None,
        llm_fixture: Optional[Union[str, Path]] = None,
        tool_fixture: Optional[Union[str, Path]] = None,
    ) -> None:
        # Build LLM mock
        if llm_fixture:
            self._llm = MockLLMProvider.from_fixture(llm_fixture)
        else:
            self._llm = MockLLMProvider(
                responses=llm_responses or [],
                keyword_map=llm_keyword_map or {},
                default_response=llm_default_response,
            )

        # Build tool mock
        if tool_fixture:
            self._tools = MockToolServer.from_fixture(tool_fixture)
        else:
            self._tools = MockToolServer(
                tool_outputs=tool_outputs or {},
                fail_tools=fail_tools or {},
            )

        self._active: bool = False
        self._original_env: Optional[str] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def llm(self) -> MockLLMProvider:
        """The mock LLM provider for assertion."""
        return self._llm

    @property
    def tools(self) -> MockToolServer:
        """The mock tool server for assertion."""
        return self._tools

    @property
    def is_active(self) -> bool:
        return self._active

    # ------------------------------------------------------------------
    # Activation / deactivation
    # ------------------------------------------------------------------

    def activate(self) -> "MockMode":
        """Activate mock mode — sets MOCK_MODE=true in the environment."""
        if self._active:
            return self
        self._original_env = os.environ.get(MOCK_MODE_ENV_VAR)
        os.environ[MOCK_MODE_ENV_VAR] = "true"
        self._active = True
        logger.info("MockMode activated — LLM and tools replaced with mocks")
        return self

    def deactivate(self) -> None:
        """Deactivate mock mode — restores original environment."""
        if not self._active:
            return
        if self._original_env is None:
            os.environ.pop(MOCK_MODE_ENV_VAR, None)
        else:
            os.environ[MOCK_MODE_ENV_VAR] = self._original_env
        self._original_env = None
        self._active = False
        logger.info("MockMode deactivated")

    def reset(self) -> None:
        """Reset all call histories without deactivating."""
        self._llm.reset()
        self._tools.reset()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "MockMode":
        return self.activate()

    def __exit__(self, *args: Any) -> None:
        self.deactivate()

    # ------------------------------------------------------------------
    # Provider factory helpers
    # ------------------------------------------------------------------

    def get_llm_provider(
        self,
        provider_name: Optional[str] = None,
        model: Optional[str] = None,
    ) -> MockLLMProvider:
        """
        Return the mock LLM provider — compatible with the real ProviderRegistry API.

        This allows code that calls ``registry.get_provider(name)`` to receive
        the mock transparently when mock mode is active.
        """
        if not self._active and not is_mock_mode():
            raise RuntimeError(
                "MockMode.get_llm_provider() called outside active mock mode. "
                "Call mock_mode.activate() or use 'with mock_mode:' first."
            )
        return self._llm

    def get_tool_server(self, server_name: Optional[str] = None) -> MockToolServer:
        """
        Return the mock tool server — compatible with the real MCP server API.
        """
        if not self._active and not is_mock_mode():
            raise RuntimeError(
                "MockMode.get_tool_server() called outside active mock mode."
            )
        return self._tools

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Return a summary of all interactions during mock mode."""
        return {
            "active": self._active,
            "llm_calls": self._llm.call_count,
            "tool_calls": self._tools.call_count,
            "tools_invoked": list(
                {c.tool_name for c in self._tools.calls}
            ),
            "llm_call_details": [
                {
                    "call_id": c.call_id,
                    "content_snippet": c.response_content[:100],
                    "stream": c.stream,
                }
                for c in self._llm.calls
            ],
            "tool_call_details": [
                {
                    "tool_name": c.tool_name,
                    "success": c.result.success,
                    "error": c.result.error,
                }
                for c in self._tools.calls
            ],
        }


# ---------------------------------------------------------------------------
# Module-level singleton for convenience
# ---------------------------------------------------------------------------

_global_mock_mode: Optional[MockMode] = None


def get_global_mock_mode() -> Optional[MockMode]:
    """Return the currently active global MockMode, or None."""
    return _global_mock_mode


def activate_global_mock_mode(**kwargs: Any) -> MockMode:
    """Activate a global MockMode singleton — convenient for test fixtures."""
    global _global_mock_mode
    if _global_mock_mode is not None and _global_mock_mode.is_active:
        return _global_mock_mode
    _global_mock_mode = MockMode(**kwargs)
    _global_mock_mode.activate()
    return _global_mock_mode


def deactivate_global_mock_mode() -> None:
    """Deactivate the global MockMode singleton."""
    global _global_mock_mode
    if _global_mock_mode is not None:
        _global_mock_mode.deactivate()
        _global_mock_mode = None
