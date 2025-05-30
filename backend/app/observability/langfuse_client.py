"""
Langfuse LLM Observability Client

Wraps the official Langfuse SDK to provide:
- Trace-level observability for every pentest session
- Generation-level spans per LLM call (prompt, completion, latency, cost)
- Tool-call spans per MCP tool invocation
- Agent-role tagging for cost breakdown by agent
- trace_id propagation so one pentest session ↔ one Langfuse trace
- Self-hosted Langfuse support via LANGFUSE_HOST env var
- Graceful no-op when Langfuse is not configured (LANGFUSE_ENABLED=false)

Configuration
-------------
Set the following environment variables (or add to .env):
    LANGFUSE_PUBLIC_KEY   — Langfuse project public key
    LANGFUSE_SECRET_KEY   — Langfuse project secret key
    LANGFUSE_HOST         — Langfuse server URL (default: https://cloud.langfuse.com)
    LANGFUSE_ENABLED      — true / false (default: true when keys are present)
    LANGFUSE_DEBUG        — true / false (default: false)
    LANGFUSE_FLUSH_AT     — batch size before auto-flush (default: 15)
    LANGFUSE_FLUSH_INTERVAL — flush interval in seconds (default: 0.5)
    LANGFUSE_THREADS      — number of consumer threads (default: 1)
    LANGFUSE_SAMPLE_RATE  — 0.0–1.0 fraction of events to capture (default: 1.0)
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cost table (USD per 1 000 tokens) for common models
# Keep in sync with the ProviderRegistry model catalogue.
# ---------------------------------------------------------------------------
_COST_PER_1K: Dict[str, Dict[str, float]] = {
    # OpenAI
    "gpt-4o":                     {"input": 0.0025, "output": 0.010},
    "gpt-4o-mini":                {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo":                {"input": 0.010,  "output": 0.030},
    "gpt-4":                      {"input": 0.030,  "output": 0.060},
    "gpt-3.5-turbo":              {"input": 0.0005, "output": 0.0015},
    # Anthropic
    "claude-3-5-sonnet-20241022": {"input": 0.003,  "output": 0.015},
    "claude-3-5-haiku-20241022":  {"input": 0.001,  "output": 0.005},
    "claude-3-opus-20240229":     {"input": 0.015,  "output": 0.075},
    # Google
    "gemini-1.5-flash":           {"input": 0.000075, "output": 0.0003},
    "gemini-1.5-pro":             {"input": 0.00125,  "output": 0.005},
    # Groq (hosted on their cloud — billed by token)
    "llama-3.3-70b-versatile":    {"input": 0.00059, "output": 0.00079},
    "llama-3.1-8b-instant":       {"input": 0.00005, "output": 0.00008},
    # DeepSeek
    "deepseek-chat":              {"input": 0.00014, "output": 0.00028},
    "deepseek-coder":             {"input": 0.00014, "output": 0.00028},
}


def _calculate_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> Optional[float]:
    """Return the estimated cost in USD or ``None`` when the model is unknown."""
    costs = _COST_PER_1K.get(model)
    if costs is None:
        return None
    return (prompt_tokens / 1000) * costs["input"] + (completion_tokens / 1000) * costs["output"]


# ---------------------------------------------------------------------------
# Span / Generation data classes
# ---------------------------------------------------------------------------

@dataclass
class GenerationData:
    """Capture data for a single LLM call generation span."""

    name: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: Optional[float] = None
    input_messages: Optional[List[Dict[str, Any]]] = None
    output_text: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpanData:
    """Capture data for a tool or agent span."""

    name: str
    input: Optional[Any] = None
    output: Optional[Any] = None
    latency_ms: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# LangfuseClient
# ---------------------------------------------------------------------------

class LangfuseClient:
    """
    Thin async-friendly wrapper around the ``langfuse`` Python SDK.

    Designed to be instantiated once (singleton via ``get_langfuse()``) and
    shared across all agent runs.  All public methods are thread-safe and
    safe to call from async contexts.

    When Langfuse is not configured or ``LANGFUSE_ENABLED=false``, every
    method becomes a no-op so the rest of the codebase requires zero
    conditional logic.
    """

    def __init__(
        self,
        public_key: str = "",
        secret_key: str = "",
        host: str = "https://cloud.langfuse.com",
        enabled: bool = True,
        debug: bool = False,
        flush_at: int = 15,
        flush_interval: float = 0.5,
        threads: int = 1,
        sample_rate: float = 1.0,
    ) -> None:
        self._enabled = enabled and bool(public_key) and bool(secret_key)
        self._client: Optional[Any] = None
        self._sample_rate = max(0.0, min(1.0, sample_rate))

        if self._enabled:
            try:
                import langfuse  # noqa: PLC0415

                self._client = langfuse.Langfuse(
                    public_key=public_key,
                    secret_key=secret_key,
                    host=host,
                    debug=debug,
                    flush_at=flush_at,
                    flush_interval=flush_interval,
                    threads=threads,
                    sample_rate=sample_rate,
                )
                logger.info(
                    "LangfuseClient initialised — host=%s sample_rate=%.2f",
                    host,
                    sample_rate,
                )
            except ImportError:
                logger.warning(
                    "langfuse package not installed — LLM observability disabled. "
                    "Install it with: pip install langfuse"
                )
                self._enabled = False
            except Exception as exc:
                logger.warning("LangfuseClient init failed: %s", exc)
                self._enabled = False
        else:
            if not public_key or not secret_key:
                logger.debug(
                    "LangfuseClient: LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY "
                    "not set — observability disabled."
                )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # Trace management
    # ------------------------------------------------------------------

    def create_trace(
        self,
        name: str,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        input: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Create and return a Langfuse trace object.

        Args:
            name:       Human-readable trace name (e.g. ``"pentest:192.168.1.1"``).
            trace_id:   External trace ID to correlate with the UniVex session.
                        Auto-generated when ``None``.
            session_id: Browser / WebSocket session identifier.
            user_id:    Authenticated user performing the pentest.
            tags:       Free-form labels (e.g. ``["webapp", "CTF"]``).
            metadata:   Arbitrary JSON-serialisable metadata.
            input:      Top-level input for this trace (e.g. target spec).

        Returns:
            Langfuse ``StatefulTraceClient`` or ``None`` when disabled.
        """
        if not self._enabled or self._client is None:
            return None
        if self._sample_rate < 1.0 and random.random() > self._sample_rate:
            return None
        try:
            trace = self._client.trace(
                id=trace_id or str(uuid.uuid4()),
                name=name,
                session_id=session_id,
                user_id=user_id,
                tags=tags or [],
                metadata=metadata or {},
                input=input,
            )
            return trace
        except Exception as exc:
            logger.debug("Langfuse trace creation failed: %s", exc)
            return None

    def update_trace(
        self,
        trace: Any,
        output: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Update a trace with output data at the end of a pentest session."""
        if not self._enabled or trace is None:
            return
        try:
            trace.update(output=output, metadata=metadata, tags=tags)
        except Exception as exc:
            logger.debug("Langfuse trace update failed: %s", exc)

    # ------------------------------------------------------------------
    # Generation (LLM call) spans
    # ------------------------------------------------------------------

    def record_generation(
        self,
        trace: Optional[Any],
        data: GenerationData,
        parent_span: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Record a single LLM call as a Langfuse generation span.

        Automatically calculates cost when ``data.cost_usd`` is ``None``
        using the built-in cost table.

        Returns the created generation object (or ``None`` when disabled).
        """
        if not self._enabled or self._client is None:
            return None
        if trace is None and parent_span is None:
            return None

        cost = data.cost_usd
        if cost is None and data.prompt_tokens > 0:
            cost = _calculate_cost(data.model, data.prompt_tokens, data.completion_tokens)

        try:
            container = parent_span if parent_span is not None else trace
            gen = container.generation(
                name=data.name,
                model=data.model,
                model_parameters={},
                input=data.input_messages,
                output=data.output_text,
                usage={
                    "input": data.prompt_tokens,
                    "output": data.completion_tokens,
                    "total": data.total_tokens or (data.prompt_tokens + data.completion_tokens),
                    "unit": "TOKENS",
                },
                metadata={
                    "latency_ms": data.latency_ms,
                    **data.metadata,
                },
                level="ERROR" if data.error else "DEFAULT",
                status_message=data.error,
            )
            if cost is not None:
                try:
                    gen.update(usage={"cost": cost})
                except Exception:
                    pass
            return gen
        except Exception as exc:
            logger.debug("Langfuse generation recording failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Span (tool / agent sub-step) management
    # ------------------------------------------------------------------

    def start_span(
        self,
        trace: Optional[Any],
        name: str,
        input: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        parent_span: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Start a Langfuse span for a tool call or agent sub-step.

        Returns the span object so the caller can end it later with
        ``end_span()``.
        """
        if not self._enabled or self._client is None:
            return None
        if trace is None and parent_span is None:
            return None
        try:
            container = parent_span if parent_span is not None else trace
            span = container.span(
                name=name,
                input=input,
                metadata=metadata or {},
            )
            return span
        except Exception as exc:
            logger.debug("Langfuse span creation failed: %s", exc)
            return None

    def end_span(
        self,
        span: Optional[Any],
        output: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """End a span created with ``start_span()``."""
        if not self._enabled or span is None:
            return
        try:
            span.end(
                output=output,
                level="ERROR" if error else "DEFAULT",
                status_message=error,
                metadata=metadata,
            )
        except Exception as exc:
            logger.debug("Langfuse span end failed: %s", exc)

    # ------------------------------------------------------------------
    # High-level context managers
    # ------------------------------------------------------------------

    @contextmanager
    def agent_trace(
        self,
        agent_role: str,
        target: str,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        extra_tags: Optional[List[str]] = None,
    ) -> Iterator[Optional[Any]]:
        """
        Context manager that creates a trace for a full agent execution.

        Usage::

            with langfuse.agent_trace("recon", "192.168.1.1", session_id=sid) as trace:
                # do LLM calls, record_generation, etc.
                pass
        """
        trace = self.create_trace(
            name=f"agent:{agent_role}:{target}",
            trace_id=trace_id,
            session_id=session_id,
            user_id=user_id,
            tags=["univex", f"agent:{agent_role}", *(extra_tags or [])],
            metadata={"agent_role": agent_role, "target": target},
            input={"target": target},
        )
        try:
            yield trace
        except Exception as exc:
            self.update_trace(trace, metadata={"error": str(exc)})
            raise
        finally:
            self.flush()

    @asynccontextmanager
    async def async_agent_trace(
        self,
        agent_role: str,
        target: str,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        extra_tags: Optional[List[str]] = None,
    ) -> AsyncIterator[Optional[Any]]:
        """Async version of ``agent_trace()``."""
        trace = self.create_trace(
            name=f"agent:{agent_role}:{target}",
            trace_id=trace_id,
            session_id=session_id,
            user_id=user_id,
            tags=["univex", f"agent:{agent_role}", *(extra_tags or [])],
            metadata={"agent_role": agent_role, "target": target},
            input={"target": target},
        )
        try:
            yield trace
        except Exception as exc:
            self.update_trace(trace, metadata={"error": str(exc)})
            raise
        finally:
            await asyncio.to_thread(self.flush)

    @contextmanager
    def llm_call(
        self,
        trace: Optional[Any],
        agent_role: str,
        model: str,
        input_messages: Optional[List[Dict[str, Any]]] = None,
        parent_span: Optional[Any] = None,
    ) -> Iterator["_GenerationRecorder"]:
        """
        Context manager that times and records a single LLM call.

        Usage::

            with langfuse.llm_call(trace, "recon", "gpt-4o", messages) as gen:
                response = llm.invoke(messages)
                gen.set_output(response.content, response.usage)
        """
        recorder = _GenerationRecorder(
            client=self,
            trace=trace,
            agent_role=agent_role,
            model=model,
            input_messages=input_messages,
            parent_span=parent_span,
        )
        recorder._start()
        try:
            yield recorder
        except Exception as exc:
            recorder._error = str(exc)
            raise
        finally:
            recorder._finish()

    @contextmanager
    def tool_span(
        self,
        trace: Optional[Any],
        tool_name: str,
        input: Optional[Any] = None,
        parent_span: Optional[Any] = None,
    ) -> Iterator["_ToolSpanRecorder"]:
        """
        Context manager that times and records a tool invocation.

        Usage::

            with langfuse.tool_span(trace, "naabu", {"target": ip}) as sp:
                result = await naabu.execute(target=ip)
                sp.set_output(result)
        """
        recorder = _ToolSpanRecorder(
            client=self,
            trace=trace,
            tool_name=tool_name,
            input=input,
            parent_span=parent_span,
        )
        recorder._start()
        try:
            yield recorder
        except Exception as exc:
            recorder._error = str(exc)
            raise
        finally:
            recorder._finish()

    # ------------------------------------------------------------------
    # Score / event helpers
    # ------------------------------------------------------------------

    def score_trace(
        self,
        trace: Optional[Any],
        name: str,
        value: float,
        comment: Optional[str] = None,
    ) -> None:
        """Attach a numeric score to a trace (e.g. exploit success rate)."""
        if not self._enabled or trace is None:
            return
        try:
            trace.score(name=name, value=value, comment=comment)
        except Exception as exc:
            logger.debug("Langfuse score failed: %s", exc)

    def event(
        self,
        trace: Optional[Any],
        name: str,
        input: Optional[Any] = None,
        output: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a point-in-time event on the trace (e.g. phase transitions)."""
        if not self._enabled or trace is None:
            return
        try:
            trace.event(
                name=name,
                input=input,
                output=output,
                metadata=metadata or {},
            )
        except Exception as exc:
            logger.debug("Langfuse event failed: %s", exc)

    # ------------------------------------------------------------------
    # Flush / shutdown
    # ------------------------------------------------------------------

    def flush(self) -> None:
        """Force-flush any queued events to Langfuse. Call before process exit."""
        if not self._enabled or self._client is None:
            return
        try:
            self._client.flush()
        except Exception as exc:
            logger.debug("Langfuse flush failed: %s", exc)

    def shutdown(self) -> None:
        """Flush and shut down background threads."""
        if not self._enabled or self._client is None:
            return
        try:
            self._client.shutdown()
        except Exception as exc:
            logger.debug("Langfuse shutdown failed: %s", exc)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return a dict summarising the client's operational status."""
        return {
            "enabled": self._enabled,
            "client_ready": self._client is not None,
            "sample_rate": self._sample_rate,
        }


# ---------------------------------------------------------------------------
# Recorder helpers (returned by context managers)
# ---------------------------------------------------------------------------

class _GenerationRecorder:
    """Mutable state carrier returned by ``LangfuseClient.llm_call()``."""

    def __init__(
        self,
        client: LangfuseClient,
        trace: Optional[Any],
        agent_role: str,
        model: str,
        input_messages: Optional[List[Dict[str, Any]]],
        parent_span: Optional[Any],
    ) -> None:
        self._client = client
        self._trace = trace
        self._agent_role = agent_role
        self._model = model
        self._input_messages = input_messages
        self._parent_span = parent_span
        self._start_ts: float = 0.0
        self._output_text: Optional[str] = None
        self._prompt_tokens: int = 0
        self._completion_tokens: int = 0
        self._total_tokens: int = 0
        self._error: Optional[str] = None

    def set_output(
        self,
        text: Optional[str],
        usage: Optional[Any] = None,
    ) -> None:
        """Record the LLM response text and token usage."""
        self._output_text = text
        if usage is not None:
            if hasattr(usage, "prompt_tokens"):
                self._prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                self._completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                self._total_tokens = getattr(usage, "total_tokens", 0) or 0
            elif isinstance(usage, dict):
                self._prompt_tokens = usage.get("prompt_tokens", 0)
                self._completion_tokens = usage.get("completion_tokens", 0)
                self._total_tokens = usage.get("total_tokens", 0)

    def _start(self) -> None:
        self._start_ts = time.perf_counter()

    def _finish(self) -> None:
        latency_ms = (time.perf_counter() - self._start_ts) * 1000
        data = GenerationData(
            name=f"{self._agent_role}:llm_call",
            model=self._model,
            prompt_tokens=self._prompt_tokens,
            completion_tokens=self._completion_tokens,
            total_tokens=self._total_tokens,
            latency_ms=latency_ms,
            input_messages=self._input_messages,
            output_text=self._output_text,
            error=self._error,
            metadata={"agent_role": self._agent_role},
        )
        self._client.record_generation(
            trace=self._trace,
            data=data,
            parent_span=self._parent_span,
        )


class _ToolSpanRecorder:
    """Mutable state carrier returned by ``LangfuseClient.tool_span()``."""

    def __init__(
        self,
        client: LangfuseClient,
        trace: Optional[Any],
        tool_name: str,
        input: Optional[Any],
        parent_span: Optional[Any],
    ) -> None:
        self._client = client
        self._trace = trace
        self._tool_name = tool_name
        self._input = input
        self._parent_span = parent_span
        self._start_ts: float = 0.0
        self._output: Optional[Any] = None
        self._error: Optional[str] = None
        self._span: Optional[Any] = None

    def set_output(self, output: Any) -> None:
        self._output = output

    def _start(self) -> None:
        self._start_ts = time.perf_counter()
        self._span = self._client.start_span(
            trace=self._trace,
            name=f"tool:{self._tool_name}",
            input=self._input,
            metadata={"tool_name": self._tool_name},
            parent_span=self._parent_span,
        )

    def _finish(self) -> None:
        latency_ms = (time.perf_counter() - self._start_ts) * 1000
        self._client.end_span(
            span=self._span,
            output=self._output,
            error=self._error,
            metadata={"latency_ms": latency_ms},
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _build_langfuse_client() -> LangfuseClient:
    """Build the singleton ``LangfuseClient`` from application settings."""
    try:
        from app.core.config import settings  # noqa: PLC0415
        return LangfuseClient(
            public_key=getattr(settings, "LANGFUSE_PUBLIC_KEY", ""),
            secret_key=getattr(settings, "LANGFUSE_SECRET_KEY", ""),
            host=getattr(settings, "LANGFUSE_HOST", "https://cloud.langfuse.com"),
            enabled=getattr(settings, "LANGFUSE_ENABLED", True),
            debug=getattr(settings, "LANGFUSE_DEBUG", False),
            flush_at=getattr(settings, "LANGFUSE_FLUSH_AT", 15),
            flush_interval=getattr(settings, "LANGFUSE_FLUSH_INTERVAL", 0.5),
            threads=getattr(settings, "LANGFUSE_THREADS", 1),
            sample_rate=getattr(settings, "LANGFUSE_SAMPLE_RATE", 1.0),
        )
    except Exception as exc:
        logger.debug("Could not load settings for LangfuseClient: %s", exc)
        return LangfuseClient()  # no-op client


def get_langfuse() -> LangfuseClient:
    """
    Return the module-level singleton ``LangfuseClient``.

    Thread-safe and safe to call from async code.  Returns a no-op client
    when Langfuse is not configured so callers need zero conditional logic.
    """
    return _build_langfuse_client()


__all__ = [
    "LangfuseClient",
    "GenerationData",
    "SpanData",
    "get_langfuse",
]
