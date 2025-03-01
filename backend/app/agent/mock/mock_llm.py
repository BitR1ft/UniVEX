"""
MockLLMProvider — configurable mock LLM for UniVex testing
──────────────────────────────────────────────────────────
Provides a drop-in replacement for any BaseLLMProvider that:
  - Returns scripted responses from YAML fixture files or inline dicts
  - Supports streaming responses
  - Records all calls for assertion in tests
  - Never makes real API requests
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Union

import yaml


# ---------------------------------------------------------------------------
# Response models (mirrors app.llm.base_provider without requiring import)
# ---------------------------------------------------------------------------


@dataclass
class MockLLMResponse:
    """Lightweight stand-in for LLMResponse."""

    content: str
    model: str = "mock-model"
    provider: str = "mock"
    usage: Dict[str, int] = field(default_factory=lambda: {
        "prompt_tokens": 50,
        "completion_tokens": 80,
        "total_tokens": 130,
    })
    finish_reason: str = "stop"
    tool_calls: List[Any] = field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None


@dataclass
class MockLLMCall:
    """Record of a single LLM call — used for call inspection in tests."""

    call_id: str
    messages: List[Dict[str, str]]
    model: Optional[str]
    response_content: str
    timestamp: float = field(default_factory=time.monotonic)
    stream: bool = False


# ---------------------------------------------------------------------------
# MockLLMProvider
# ---------------------------------------------------------------------------


class MockLLMProvider:
    """
    Configurable mock LLM provider.

    Usage — inline responses::

        mock = MockLLMProvider(responses=["First answer", "Second answer"])
        resp = await mock.chat(messages=[...])
        assert resp.content == "First answer"

    Usage — YAML fixture::

        mock = MockLLMProvider.from_fixture("tests/fixtures/llm_responses.yaml")
        resp = await mock.chat(messages=[...])

    Usage — keyword matching::

        mock = MockLLMProvider(keyword_map={"port scan": "Found 3 open ports"})
        resp = await mock.chat(messages=[{"role": "user", "content": "port scan 1.2.3.4"}])
        assert "Found 3 open ports" in resp.content
    """

    provider_name: str = "mock"
    supported_models: List[str] = field(default_factory=lambda: ["mock-model"])

    def __init__(
        self,
        responses: Optional[List[str]] = None,
        keyword_map: Optional[Dict[str, str]] = None,
        default_response: str = "[MOCK] OK",
        model: str = "mock-model",
        simulate_latency_ms: int = 0,
        fail_after: Optional[int] = None,
        error_message: str = "MockLLMProvider: simulated error",
        stream_chunk_size: int = 5,
        token_usage: Optional[Dict[str, int]] = None,
    ) -> None:
        self._responses = list(responses or [])
        self._keyword_map = keyword_map or {}
        self._default_response = default_response
        self._model = model
        self._simulate_latency_ms = simulate_latency_ms
        self._fail_after = fail_after
        self._error_message = error_message
        self._stream_chunk_size = stream_chunk_size
        self._token_usage = token_usage or {
            "prompt_tokens": 50,
            "completion_tokens": 80,
            "total_tokens": 130,
        }

        self._call_index: int = 0
        self.calls: List[MockLLMCall] = []

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_fixture(cls, fixture_path: Union[str, Path], **kwargs: Any) -> "MockLLMProvider":
        """
        Load scripted responses from a YAML fixture file.

        Fixture format::

            responses:
              - "First answer"
              - "Second answer"
            keyword_map:
              "port scan": "Found 3 open ports on target"
              "sql inject": "Identified SQL injection at /login"
            default_response: "[MOCK] No matching response"
        """
        path = Path(fixture_path)
        if not path.exists():
            raise FileNotFoundError(f"LLM fixture file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        responses = data.get("responses", [])
        keyword_map = data.get("keyword_map", {})
        default = data.get("default_response", "[MOCK] OK")
        return cls(
            responses=responses,
            keyword_map=keyword_map,
            default_response=default,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pick_response(self, messages: List[Dict[str, str]]) -> str:
        """Choose the appropriate mock response."""
        # Check failure injection
        if self._fail_after is not None and self._call_index >= self._fail_after:
            raise RuntimeError(self._error_message)

        # Check sequential scripted responses
        if self._responses and self._call_index < len(self._responses):
            return self._responses[self._call_index]

        # Keyword map — scan all user message content
        last_user_content = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last_user_content = msg.get("content", "")
                break
        for kw, resp in self._keyword_map.items():
            if kw.lower() in last_user_content.lower():
                return resp

        return self._default_response

    async def _maybe_sleep(self) -> None:
        if self._simulate_latency_ms > 0:
            await asyncio.sleep(self._simulate_latency_ms / 1000)

    def _record_call(
        self,
        messages: List[Dict[str, str]],
        content: str,
        model: Optional[str] = None,
        stream: bool = False,
    ) -> MockLLMCall:
        call = MockLLMCall(
            call_id=str(uuid.uuid4()),
            messages=messages,
            model=model or self._model,
            response_content=content,
            stream=stream,
        )
        self.calls.append(call)
        return call

    # ------------------------------------------------------------------
    # Public API (mirrors BaseLLMProvider)
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> MockLLMResponse:
        """Non-streaming chat completion."""
        await self._maybe_sleep()
        content = self._pick_response(messages)
        self._record_call(messages, content, model=model)
        self._call_index += 1
        return MockLLMResponse(
            content=content,
            model=model or self._model,
            provider="mock",
            usage=dict(self._token_usage),
        )

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Streaming chat completion — yields tokens in chunks."""
        await self._maybe_sleep()
        content = self._pick_response(messages)
        self._record_call(messages, content, model=model, stream=True)
        self._call_index += 1

        # Yield in chunks
        chunk_size = max(1, self._stream_chunk_size)
        for i in range(0, len(content), chunk_size):
            yield content[i : i + chunk_size]
            await asyncio.sleep(0)  # yield control

    # ------------------------------------------------------------------
    # Assertion helpers
    # ------------------------------------------------------------------

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def assert_called_once(self) -> None:
        assert self.call_count == 1, f"Expected 1 call, got {self.call_count}"

    def assert_called_n_times(self, n: int) -> None:
        assert self.call_count == n, f"Expected {n} calls, got {self.call_count}"

    def assert_last_message_contains(self, text: str) -> None:
        assert self.calls, "No calls recorded"
        last_msgs = self.calls[-1].messages
        content = " ".join(m.get("content", "") for m in last_msgs)
        assert text.lower() in content.lower(), (
            f"Expected '{text}' in last message, got: {content[:200]}"
        )

    def reset(self) -> None:
        """Reset call history and index."""
        self.calls.clear()
        self._call_index = 0
