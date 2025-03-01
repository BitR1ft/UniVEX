"""
Multi-Agent Framework — Base Agent and Shared State

Defines MultiAgentState (extends AgentState) and the BaseAgent abstract class
that all specialised sub-agents inherit from.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from app.agent.state.agent_state import AgentState, Phase
from app.agent.tools.base_tool import BaseTool
from app.agent.tools.tool_registry import ToolRegistry

if TYPE_CHECKING:
    from app.agent.memory.episodic_memory import EpisodicMemoryStore as EpisodicMemoryStore, MemoryType
    from app.agent.memory.graphiti_client import GraphitiClient as GraphitiClient
    from app.agent.memory.flow_memory import FlowMemoryNamespace
    from app.agent.memory.auto_capture import AutoCaptureMiddleware
    from app.observability.langfuse_client import LangfuseClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------


class MultiAgentState(AgentState, total=False):
    """
    Extended agent state shared across all sub-agents in the orchestration
    framework.  Inherits all fields from AgentState and adds orchestration
    metadata.
    """

    # Names of sub-agents currently active in this run
    active_agents: List[str]

    # Accumulated results keyed by agent name
    agent_results: Dict[str, Any]

    # Ordered list of task dicts decomposed by the orchestrator
    orchestrator_plan: Optional[List[Dict[str, Any]]]

    # Metadata about the target (IP, domain, open ports, …)
    target_info: Optional[Dict[str, Any]]

    # Parallel execution workstreams (each is a WorkItem-like dict)
    workstreams: Optional[List[Dict[str, Any]]]


# ---------------------------------------------------------------------------
# BaseAgent
# ---------------------------------------------------------------------------


class BaseAgent(ABC):
    """
    Abstract parent class for all specialised sub-agents.

    Concrete sub-classes must implement:
      - ``AGENT_NAME`` class attribute
      - ``PREFERRED_TOOLS`` class attribute
      - ``get_phase()``
      - ``_build_system_prompt()``
      - ``run(state, task)``

    Memory / knowledge-graph integration:
      When ``auto_capture=True`` (the default), every agent response and tool
      output is automatically ingested into the ``EpisodicMemoryStore`` (and
      optionally Graphiti) associated with the current flow.  Pass a
      ``FlowMemoryNamespace`` via ``memory_ns`` to enable this behaviour.

    Observability integration:
      When Langfuse is configured (``LANGFUSE_PUBLIC_KEY`` / ``LANGFUSE_SECRET_KEY``
      env vars), every LLM call and tool invocation is traced automatically.
      Provide ``trace_id`` / ``session_id`` via the ``observability_ctx`` dict to
      correlate all agents in a single pentest session into one Langfuse trace.
    """

    AGENT_NAME: str = "base"
    PREFERRED_TOOLS: List[str] = []

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
        memory_ns: Optional["FlowMemoryNamespace"] = None,
        auto_capture: bool = True,
        observability_ctx: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.registry = registry
        self.llm = llm
        self.config = config or {}
        self._tools: List[BaseTool] = self._select_tools(registry)
        # Memory integration
        self._memory_ns: Optional["FlowMemoryNamespace"] = memory_ns
        self.auto_capture: bool = auto_capture
        # AutoCaptureMiddleware — optional vector-store ingestion
        self._auto_capture_middleware: Optional["AutoCaptureMiddleware"] = None
        # Context summariser — lazily initialised when LLM is set
        self._summarizer: Optional[Any] = None
        # Langfuse observability context — carries trace_id, session_id, user_id
        self._obs_ctx: Dict[str, Any] = observability_ctx or {}
        # Active Langfuse trace for this agent run (set in traced_run())
        self._lf_trace: Optional[Any] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_tool_names(self) -> List[str]:
        """Return the names of tools currently assigned to this agent."""
        return [t.name for t in self._tools]

    def set_memory_namespace(self, memory_ns: "FlowMemoryNamespace") -> None:
        """Attach a ``FlowMemoryNamespace`` for memory capture and retrieval."""
        self._memory_ns = memory_ns
        # Propagate to existing summarizer if already initialised
        if self._summarizer is not None:
            self._summarizer._memory_ns = memory_ns

    def set_auto_capture_middleware(
        self, middleware: "AutoCaptureMiddleware"
    ) -> None:
        """Attach an :class:`AutoCaptureMiddleware` for automatic vector-store ingestion."""
        self._auto_capture_middleware = middleware

    def set_observability_ctx(self, ctx: Dict[str, Any]) -> None:
        """
        Set the Langfuse observability context for this agent.

        The context dict may contain:
        - ``trace_id``   — external trace ID to correlate all agents in a session
        - ``session_id`` — browser / WebSocket session identifier
        - ``user_id``    — authenticated user identifier
        - ``target``     — pentest target for naming the trace
        """
        self._obs_ctx = ctx

    # ------------------------------------------------------------------
    # Langfuse observability helpers
    # ------------------------------------------------------------------

    def _get_langfuse(self) -> Optional["LangfuseClient"]:
        """Return the singleton LangfuseClient, or ``None`` when not available."""
        try:
            from app.observability.langfuse_client import get_langfuse  # noqa: PLC0415
            lf = get_langfuse()
            return lf if lf.enabled else None
        except Exception:  # noqa: BLE001
            return None

    def start_langfuse_trace(
        self,
        target: str,
        extra_tags: Optional[List[str]] = None,
    ) -> Optional[Any]:
        """
        Create a Langfuse trace for this agent's execution.

        Stores the trace on ``self._lf_trace`` and returns it.  Call this at
        the start of ``run()`` if you want per-agent tracing.  The orchestrator
        can set ``trace_id`` in ``observability_ctx`` so all agents in a session
        appear under one parent trace.
        """
        lf = self._get_langfuse()
        if lf is None:
            return None
        trace = lf.create_trace(
            name=f"agent:{self.AGENT_NAME}:{target}",
            trace_id=self._obs_ctx.get("trace_id"),
            session_id=self._obs_ctx.get("session_id"),
            user_id=self._obs_ctx.get("user_id"),
            tags=["univex", f"agent:{self.AGENT_NAME}", *(extra_tags or [])],
            metadata={
                "agent_role": self.AGENT_NAME,
                "target": target,
                **{k: v for k, v in self._obs_ctx.items() if k not in ("trace_id", "session_id", "user_id")},
            },
            input={"target": target},
        )
        self._lf_trace = trace
        return trace

    def record_llm_generation(
        self,
        model: str,
        input_messages: Optional[List[Dict[str, Any]]] = None,
        output_text: Optional[str] = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record an LLM call generation in Langfuse.

        Call this after each ``llm.invoke()`` / ``llm.ainvoke()`` to capture
        the prompt, response, token usage, latency, and estimated cost.
        """
        lf = self._get_langfuse()
        if lf is None or self._lf_trace is None:
            return
        from app.observability.langfuse_client import GenerationData  # noqa: PLC0415
        data = GenerationData(
            name=f"{self.AGENT_NAME}:llm",
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_ms=latency_ms,
            input_messages=input_messages,
            output_text=output_text,
            error=error,
            metadata={"agent_role": self.AGENT_NAME, **(metadata or {})},
        )
        lf.record_generation(trace=self._lf_trace, data=data)

    def record_tool_call(
        self,
        tool_name: str,
        input: Optional[Any] = None,
        output: Optional[Any] = None,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        """Record a tool invocation as a Langfuse span."""
        lf = self._get_langfuse()
        if lf is None or self._lf_trace is None:
            return
        span = lf.start_span(
            trace=self._lf_trace,
            name=f"tool:{tool_name}",
            input=input,
            metadata={"tool_name": tool_name, "agent_role": self.AGENT_NAME},
        )
        lf.end_span(
            span=span,
            output=output,
            error=error,
            metadata={"latency_ms": latency_ms},
        )

    def finalize_langfuse_trace(
        self,
        output: Optional[Any] = None,
        error: Optional[str] = None,
    ) -> None:
        """Finalise the active Langfuse trace and flush events."""
        lf = self._get_langfuse()
        if lf is None or self._lf_trace is None:
            return
        lf.update_trace(
            trace=self._lf_trace,
            output=output,
            metadata={"error": error} if error else None,
        )
        lf.flush()
        self._lf_trace = None

    def get_summarizer(self) -> Optional[Any]:
        """
        Return (or lazily initialise) the ``ContextSummarizer`` for this agent.

        Requires ``self.llm`` to be set.  Returns ``None`` when no LLM is
        configured — summarisation is silently skipped.
        """
        if self._summarizer is not None:
            return self._summarizer
        if self.llm is None:
            return None
        try:
            from app.agent.memory.context_summarizer import ContextSummarizer
            self._summarizer = ContextSummarizer(
                llm=self.llm,
                memory_ns=self._memory_ns,
            )
        except ImportError:
            logger.debug("ContextSummarizer not available — skipping")
        return self._summarizer

    async def compress_messages(
        self,
        messages: List[Any],
        model_name: str = "gpt-4o",
        flow_id: str = "default",
        session_id: str = "default",
    ) -> List[Any]:
        """
        Compress the message history using context summarisation.

        Thin wrapper around ``ContextSummarizer.maybe_summarize()`` that
        silently returns the original messages when no LLM or summarizer is
        available.
        """
        summarizer = self.get_summarizer()
        if summarizer is None:
            return messages
        return await summarizer.maybe_summarize(
            messages=messages,
            model_name=model_name,
            flow_id=flow_id,
            session_id=session_id,
            agent_role=self.AGENT_NAME,
        )

    @abstractmethod
    def get_phase(self) -> Phase:
        """Return the primary phase for this agent."""

    @abstractmethod
    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Execute the agent's main workstream.

        Args:
            state: Shared multi-agent state.
            task:  Natural language task description.

        Returns:
            Result dict that the orchestrator merges into ``agent_results``.
        """

    # ------------------------------------------------------------------
    # Memory helpers — called by sub-classes or the orchestrator
    # ------------------------------------------------------------------

    async def capture_memory(
        self,
        content: str,
        memory_type: "MemoryType",
        session_id: str = "default",
        flow_id: str = "default",
        **kwargs: Any,
    ) -> None:
        """
        Capture a memory entry for the current agent.

        Writes to the ``FlowMemoryNamespace`` (episodic + Graphiti) and
        optionally to the vector store via ``AutoCaptureMiddleware``.

        No-op when ``auto_capture=False`` or no memory namespace is attached.
        """
        if not self.auto_capture:
            return
        if self._memory_ns is not None:
            try:
                await self._memory_ns.capture(
                    session_id=session_id,
                    agent_role=self.AGENT_NAME,
                    memory_type=memory_type,
                    content=content,
                    **kwargs,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Memory capture failed for agent %s: %s", self.AGENT_NAME, exc
                )
        if self._auto_capture_middleware is not None:
            try:
                await self._auto_capture_middleware.capture_response(
                    flow_id=flow_id,
                    agent_role=self.AGENT_NAME,
                    memory_type=memory_type,
                    content=content,
                    session_id=session_id,
                    **kwargs,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "AutoCapture middleware failed for agent %s: %s",
                    self.AGENT_NAME,
                    exc,
                )

    async def capture_tool_output(
        self,
        tool_name: str,
        output: str,
        flow_id: str = "default",
        session_id: str = "default",
    ) -> None:
        """
        Capture the output of a tool invocation.

        Writes to both the episodic memory namespace and the vector store
        via ``AutoCaptureMiddleware`` when available.
        """
        if not self.auto_capture:
            return
        from app.agent.memory.episodic_memory import MemoryType  # noqa: PLC0415

        if self._memory_ns is not None:
            try:
                await self._memory_ns.capture(
                    session_id=session_id,
                    agent_role=self.AGENT_NAME,
                    memory_type=MemoryType.ANSWER,
                    content=output,
                    tool_name=tool_name,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Tool output capture failed for agent %s tool %s: %s",
                    self.AGENT_NAME,
                    tool_name,
                    exc,
                )
        if self._auto_capture_middleware is not None:
            try:
                await self._auto_capture_middleware.capture_tool_output(
                    flow_id=flow_id,
                    agent_role=self.AGENT_NAME,
                    tool_name=tool_name,
                    output=output,
                    session_id=session_id,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "AutoCapture tool output failed for agent %s tool %s: %s",
                    self.AGENT_NAME,
                    tool_name,
                    exc,
                )

    async def query_past_knowledge(
        self,
        query: str,
        memory_type: Optional["MemoryType"] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Search the Graphiti knowledge graph for relevant past findings.

        Returns an empty list when no memory namespace is configured.
        """
        if self._memory_ns is None:
            return []
        try:
            results = await self._memory_ns.search(
                query=query,
                memory_type=memory_type,
                limit=limit,
            )
            return [
                {"node_id": r.node_id, "name": r.name, "score": r.score}
                for r in results
            ]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Knowledge query failed for agent %s: %s", self.AGENT_NAME, exc)
            return []

    # ------------------------------------------------------------------
    # Overridable helpers
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        """Return a specialised system prompt for this agent."""
        phase = self.get_phase()
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            f"You are the {self.AGENT_NAME} agent operating in the "
            f"{phase.value} phase.\n"
            f"Available tools: {tool_names}.\n"
            "Perform your specialised security assessment tasks and return "
            "structured findings."
        )

    def _select_tools(self, registry: ToolRegistry) -> List[BaseTool]:
        """
        Filter tools from *registry* that match ``PREFERRED_TOOLS``.

        Falls back to all tools available for this agent's phase when
        ``PREFERRED_TOOLS`` is empty or none of the preferred tools are
        registered.
        """
        selected: List[BaseTool] = []

        for name in self.PREFERRED_TOOLS:
            tool = registry.get_tool(name)
            if tool is not None:
                selected.append(tool)

        if not selected:
            phase_tools = registry.get_tools_for_phase(self.get_phase())
            selected = list(phase_tools.values())

        return selected


__all__ = ["MultiAgentState", "BaseAgent"]