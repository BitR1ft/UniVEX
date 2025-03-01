"""
ContextSummarizer — LangChain Chain Summarization Middleware

Compresses growing conversation history when the token count exceeds
``AGENT_SUMMARY_THRESHOLD`` (default: 75%) of the model's context window.

This prevents context overflow during long-running pentests and keeps LLM
costs manageable.

Architecture:
  - ``ContextSummarizer.maybe_summarize(messages, model_name)`` is the main
    entry point.  It is a no-op when the history is within the threshold.
  - When summarisation is triggered, all messages except the last N are
    replaced with a single summary AIMessage.
  - The summary is also captured into the agent's episodic memory as a
    ``MemoryType.MEMORY`` entry.

Integration:
  Each agent class calls ``ContextSummarizer.maybe_summarize()`` at the
  start of ``run()`` before building its LLM prompt.

Usage::

    summarizer = ContextSummarizer(llm=my_llm)
    messages = await summarizer.maybe_summarize(
        messages=state["messages"],
        model_name="gpt-4o",
        flow_id="flow-abc",
        session_id="sess-001",
        agent_role="recon",
    )
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional, Sequence, TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from app.agent.memory.flow_memory import FlowMemoryNamespace

# ---------------------------------------------------------------------------
# Model context window sizes (tokens) — used to compute threshold
# ---------------------------------------------------------------------------

#: Best-effort mapping of model identifiers to context window sizes.
#: Falls back to ``_DEFAULT_CONTEXT_WINDOW`` for unknown models.
_MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    # OpenAI
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4": 8_192,
    "gpt-3.5-turbo": 16_385,
    # Anthropic
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    "claude-3-opus-20240229": 200_000,
    "claude-3-sonnet-20240229": 200_000,
    # Google
    "gemini-1.5-pro": 2_097_152,
    "gemini-1.5-flash": 1_048_576,
    # Groq
    "llama-3.3-70b-versatile": 128_000,
    "mixtral-8x7b-32768": 32_768,
    # DeepSeek
    "deepseek-chat": 64_000,
    "deepseek-coder": 64_000,
}

_DEFAULT_CONTEXT_WINDOW: int = 8_000
_DEFAULT_SUMMARY_THRESHOLD: float = 0.75
# Minimum number of recent messages to keep intact (not summarised)
_MIN_KEEP_RECENT: int = 4
# Average tokens per character estimate used when a tokenizer is not available
_CHARS_PER_TOKEN: float = 4.0


def _estimate_tokens(messages: Sequence[Any]) -> int:
    """Fast token count estimate based on character length."""
    total_chars = sum(
        len(str(getattr(m, "content", m))) for m in messages
    )
    return int(total_chars / _CHARS_PER_TOKEN)


def _context_window_for(model_name: str) -> int:
    """Return the context window size for a model identifier."""
    for key, size in _MODEL_CONTEXT_WINDOWS.items():
        if key in model_name.lower():
            return size
    return _DEFAULT_CONTEXT_WINDOW


# ---------------------------------------------------------------------------
# ContextSummarizer
# ---------------------------------------------------------------------------


class ContextSummarizer:
    """
    Middleware that compresses long conversation histories via LLM summarisation.

    Attributes:
        llm               – LangChain LLM instance used for summarisation.
        threshold         – Token fraction threshold (default: from env or 0.75).
        min_keep_recent   – Number of recent messages to always preserve.
        memory_ns         – Optional flow namespace for capturing summaries.
    """

    def __init__(
        self,
        llm: Any,
        threshold: Optional[float] = None,
        min_keep_recent: int = _MIN_KEEP_RECENT,
        memory_ns: Optional["FlowMemoryNamespace"] = None,
    ) -> None:
        self.llm = llm
        self.threshold = threshold if threshold is not None else self._load_threshold()
        self.min_keep_recent = min_keep_recent
        self._memory_ns = memory_ns

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def maybe_summarize(
        self,
        messages: List[Any],
        model_name: str = "gpt-4o",
        flow_id: str = "default",
        session_id: str = "default",
        agent_role: str = "agent",
    ) -> List[Any]:
        """
        Return the (potentially summarised) message list.

        Summarisation is triggered when the estimated token count of
        ``messages`` exceeds ``self.threshold * context_window``.

        Args:
            messages    – Current conversation history (list of BaseMessage).
            model_name  – Active model name (used to look up context window).
            flow_id     – Flow identifier for memory capture.
            session_id  – Session identifier for memory capture.
            agent_role  – Agent role for memory tagging.

        Returns:
            The original list if below threshold, otherwise a compressed list
            starting with an AIMessage summary of the older messages.
        """
        if not messages or len(messages) <= self.min_keep_recent:
            return messages

        context_window = _context_window_for(model_name)
        max_tokens = int(context_window * self.threshold)
        current_tokens = _estimate_tokens(messages)

        if current_tokens <= max_tokens:
            logger.debug(
                "Context OK: %d est. tokens ≤ threshold %d — no summarisation",
                current_tokens, max_tokens,
            )
            return messages

        logger.info(
            "Context overflow: est. %d tokens > threshold %d — summarising history",
            current_tokens, max_tokens,
        )

        # Split: summarise all but the last N messages
        to_summarise = messages[: -self.min_keep_recent]
        keep_recent = messages[-self.min_keep_recent :]

        summary_text = await self._summarise(to_summarise, agent_role, model_name)
        summary_message = self._make_summary_message(summary_text)

        # Optionally store the summary in episodic memory
        if self._memory_ns is not None:
            await self._capture_summary(summary_text, flow_id, session_id, agent_role)

        compressed = [summary_message] + list(keep_recent)
        logger.info(
            "Context compressed: %d → %d messages (est. %d → %d tokens)",
            len(messages), len(compressed),
            current_tokens, _estimate_tokens(compressed),
        )
        return compressed

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _summarise(
        self,
        messages: List[Any],
        agent_role: str,
        model_name: str,
    ) -> str:
        """
        Call the LLM to produce a concise summary of the given messages.

        Falls back to a heuristic text concatenation when the LLM call fails.
        """
        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            prompt_text = (
                "You are a professional summarisation assistant for a penetration "
                "testing AI agent.\n\n"
                "Below is a conversation history from the "
                f"'{agent_role}' agent performing a security assessment. "
                "Produce a concise, structured summary that preserves all:\n"
                "  • Discovered vulnerabilities and their CVEs\n"
                "  • Tool execution results (ports, services, hashes)\n"
                "  • Exploits attempted and whether they succeeded\n"
                "  • Key decisions made and their rationale\n"
                "  • Next steps that were planned\n\n"
                "Be technical and specific. Omit pleasantries and meta-commentary.\n\n"
                "--- CONVERSATION HISTORY ---\n"
            )
            for msg in messages:
                role = getattr(msg, "type", "unknown")
                content = getattr(msg, "content", str(msg))
                prompt_text += f"[{role}]: {content}\n"

            prompt_text += "\n--- END HISTORY ---\n\nProvide the summary now:"

            summary_messages = [
                SystemMessage(content="You are a concise, technical summarisation assistant."),
                HumanMessage(content=prompt_text),
            ]

            response = await self.llm.ainvoke(summary_messages)
            return getattr(response, "content", str(response))

        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM summarisation failed (%s) — using text fallback", exc)
            return self._fallback_summary(messages)

    def _fallback_summary(self, messages: List[Any]) -> str:
        """Produce a simple text-based summary when LLM call fails."""
        parts = []
        for msg in messages:
            role = getattr(msg, "type", "msg")
            content = str(getattr(msg, "content", msg))[:500]
            parts.append(f"[{role}]: {content}")
        return "Previous conversation summary:\n" + "\n".join(parts)

    def _make_summary_message(self, summary_text: str) -> Any:
        """Wrap the summary in an AIMessage (or a plain dict if LangChain unavailable)."""
        try:
            from langchain_core.messages import AIMessage
            return AIMessage(content=f"[CONTEXT SUMMARY]\n{summary_text}")
        except ImportError:
            return {"type": "ai", "content": f"[CONTEXT SUMMARY]\n{summary_text}"}

    async def _capture_summary(
        self,
        summary_text: str,
        flow_id: str,
        session_id: str,
        agent_role: str,
    ) -> None:
        """Persist the summary as a MEMORY-type entry in the flow namespace."""
        try:
            from app.agent.memory.episodic_memory import MemoryType
            await self._memory_ns.capture(  # type: ignore[union-attr]
                session_id=session_id,
                agent_role=agent_role,
                memory_type=MemoryType.MEMORY,
                content=summary_text,
                tags=["context_summary"],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to store context summary in memory: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_threshold() -> float:
        raw = os.getenv("AGENT_SUMMARY_THRESHOLD", str(_DEFAULT_SUMMARY_THRESHOLD))
        try:
            val = float(raw)
            return max(0.1, min(1.0, val))
        except ValueError:
            return _DEFAULT_SUMMARY_THRESHOLD

    def estimate_tokens(self, messages: Sequence[Any]) -> int:
        """Public wrapper around the token estimator (useful in tests)."""
        return _estimate_tokens(messages)

    def would_summarize(self, messages: Sequence[Any], model_name: str = "gpt-4o") -> bool:
        """Return True if the current messages would trigger summarisation."""
        if len(messages) <= self.min_keep_recent:
            return False
        context_window = _context_window_for(model_name)
        max_tokens = int(context_window * self.threshold)
        return _estimate_tokens(messages) > max_tokens
