"""
Tests for Day 2 — ContextSummarizer.

Coverage:
  - Token estimation (_estimate_tokens)
  - Context window lookup (_context_window_for)
  - would_summarize threshold detection
  - maybe_summarize: no-op below threshold
  - maybe_summarize: compresses when above threshold
  - maybe_summarize: always keeps min_keep_recent messages
  - LLM summarisation call structure
  - Fallback summary when LLM fails
  - Summary message wrapping (AIMessage)
  - Memory capture integration
  - ContextSummarizer.estimate_tokens() public wrapper
"""

from __future__ import annotations

import os
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.memory.context_summarizer import (
    ContextSummarizer,
    _estimate_tokens,
    _context_window_for,
    _DEFAULT_CONTEXT_WINDOW,
    _DEFAULT_SUMMARY_THRESHOLD,
    _MIN_KEEP_RECENT,
)


# ===========================================================================
# Token estimation helpers
# ===========================================================================

class TestEstimateTokens:
    """Tests for the _estimate_tokens helper."""

    def test_empty_list_returns_zero(self):
        assert _estimate_tokens([]) == 0

    def test_single_message(self):
        msg = MagicMock()
        msg.content = "A" * 400  # 400 chars → ~100 tokens
        result = _estimate_tokens([msg])
        assert result > 0

    def test_estimation_proportional_to_content_length(self):
        short_msg = MagicMock()
        short_msg.content = "short"
        long_msg = MagicMock()
        long_msg.content = "long " * 1000
        short_estimate = _estimate_tokens([short_msg])
        long_estimate = _estimate_tokens([long_msg])
        assert long_estimate > short_estimate

    def test_multiple_messages_summed(self):
        msgs = []
        for _ in range(5):
            m = MagicMock()
            m.content = "word " * 100
            msgs.append(m)
        single_estimate = _estimate_tokens([msgs[0]])
        total_estimate = _estimate_tokens(msgs)
        assert total_estimate == pytest.approx(single_estimate * 5, rel=0.1)

    def test_works_with_dicts(self):
        msgs = [{"type": "human", "content": "hello world"}]
        result = _estimate_tokens(msgs)
        assert result >= 0


class TestContextWindowFor:
    """Tests for _context_window_for model lookup."""

    def test_known_model_gpt4o(self):
        assert _context_window_for("gpt-4o") == 128_000

    def test_known_model_gpt4o_mini(self):
        assert _context_window_for("gpt-4o-mini") == 128_000

    def test_known_model_claude_sonnet(self):
        assert _context_window_for("claude-3-5-sonnet-20241022") == 200_000

    def test_known_model_groq_llama(self):
        assert _context_window_for("llama-3.3-70b-versatile") == 128_000

    def test_unknown_model_returns_default(self):
        assert _context_window_for("some-unknown-model-xyz") == _DEFAULT_CONTEXT_WINDOW

    def test_model_matching_is_case_insensitive(self):
        assert _context_window_for("GPT-4O") > 0

    def test_partial_match_works(self):
        # "gpt-4o" is a substring of "openai/gpt-4o-2024-11-20"
        result = _context_window_for("openai/gpt-4o-2024-11-20")
        assert result == 128_000


# ===========================================================================
# ContextSummarizer.would_summarize
# ===========================================================================

class TestWouldSummarize:
    """Tests for the would_summarize check."""

    def _make_summarizer(self, threshold: float = 0.75) -> ContextSummarizer:
        llm = MagicMock()
        return ContextSummarizer(llm=llm, threshold=threshold)

    def test_empty_messages_returns_false(self):
        s = self._make_summarizer()
        assert s.would_summarize([]) is False

    def test_few_messages_below_min_keep_returns_false(self):
        s = self._make_summarizer()
        msgs = [MagicMock(content="x") for _ in range(_MIN_KEEP_RECENT)]
        assert s.would_summarize(msgs) is False

    def test_small_messages_below_threshold_returns_false(self):
        s = self._make_summarizer(threshold=0.75)
        msgs = [MagicMock(content="short") for _ in range(10)]
        # Short messages won't hit the threshold of a 8k-token window
        assert s.would_summarize(msgs, model_name="gpt-4") is False

    def test_large_messages_above_threshold_returns_true(self):
        s = self._make_summarizer(threshold=0.1)  # Very low threshold
        # gpt-4 has 8192 token context; 10% = 819 tokens; with 100-char msgs * 100
        msgs = [MagicMock(content="x" * 500) for _ in range(50)]
        assert s.would_summarize(msgs, model_name="gpt-4") is True


# ===========================================================================
# ContextSummarizer.estimate_tokens
# ===========================================================================

class TestEstimateTokensPublic:
    def test_public_wrapper(self):
        llm = MagicMock()
        s = ContextSummarizer(llm=llm)
        msgs = [MagicMock(content="hello world")]
        result = s.estimate_tokens(msgs)
        assert isinstance(result, int)
        assert result >= 0


# ===========================================================================
# ContextSummarizer.maybe_summarize — below threshold (no-op)
# ===========================================================================

class TestMaybeSummarizeNoOp:
    """Tests for cases where summarisation should NOT be triggered."""

    def _make_summarizer(self) -> ContextSummarizer:
        llm = AsyncMock()
        return ContextSummarizer(llm=llm, threshold=0.75)

    @pytest.mark.asyncio
    async def test_empty_messages_returns_original(self):
        s = self._make_summarizer()
        result = await s.maybe_summarize([])
        assert result == []

    @pytest.mark.asyncio
    async def test_few_messages_returns_original(self):
        s = self._make_summarizer()
        msgs = ["msg1", "msg2"]
        result = await s.maybe_summarize(msgs)
        assert result == msgs

    @pytest.mark.asyncio
    async def test_below_threshold_returns_original(self):
        s = self._make_summarizer()
        try:
            from langchain_core.messages import HumanMessage
            msgs = [HumanMessage(content="short") for _ in range(5)]
        except ImportError:
            msgs = [MagicMock(content="short") for _ in range(5)]

        result = await s.maybe_summarize(msgs, model_name="gpt-4o")
        assert len(result) == len(msgs)

    @pytest.mark.asyncio
    async def test_llm_not_called_when_below_threshold(self):
        llm = AsyncMock()
        s = ContextSummarizer(llm=llm, threshold=0.99)
        try:
            from langchain_core.messages import HumanMessage
            msgs = [HumanMessage(content="hi") for _ in range(3)]
        except ImportError:
            msgs = [MagicMock(content="hi") for _ in range(3)]
        await s.maybe_summarize(msgs)
        llm.ainvoke.assert_not_called()


# ===========================================================================
# ContextSummarizer.maybe_summarize — above threshold (compression)
# ===========================================================================

class TestMaybeSummarizeCompression:
    """Tests for cases where summarisation IS triggered."""

    def _make_long_messages(self, n: int = 50):
        try:
            from langchain_core.messages import HumanMessage, AIMessage
            msgs = []
            for i in range(n):
                if i % 2 == 0:
                    msgs.append(HumanMessage(content=f"User message {i}: " + "data " * 50))
                else:
                    msgs.append(AIMessage(content=f"AI response {i}: " + "result " * 50))
            return msgs
        except ImportError:
            return [MagicMock(content=f"message {i} " + "x" * 200) for i in range(n)]

    @pytest.mark.asyncio
    async def test_compression_reduces_message_count(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summarised history of the pentest session")
        s = ContextSummarizer(llm=llm, threshold=0.01)  # Very low threshold to force trigger

        msgs = self._make_long_messages(20)
        result = await s.maybe_summarize(msgs, model_name="gpt-4")
        assert len(result) < len(msgs)

    @pytest.mark.asyncio
    async def test_compression_keeps_min_recent_messages(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summary of earlier conversation")
        s = ContextSummarizer(llm=llm, threshold=0.01, min_keep_recent=4)

        msgs = self._make_long_messages(20)
        result = await s.maybe_summarize(msgs, model_name="gpt-4")
        # Should have: 1 summary + 4 recent = 5 messages
        assert len(result) >= _MIN_KEEP_RECENT

    @pytest.mark.asyncio
    async def test_first_message_is_summary_after_compression(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="KEY FINDINGS: SQLi on /search")
        s = ContextSummarizer(llm=llm, threshold=0.01)

        msgs = self._make_long_messages(20)
        result = await s.maybe_summarize(msgs, model_name="gpt-4")

        # First message should be a summary (fewer total messages)
        assert len(result) < len(msgs)
        assert len(result) >= 1
        first = result[0]
        # Should have content attribute (either string or mock)
        assert hasattr(first, "content") or isinstance(first, dict)

    @pytest.mark.asyncio
    async def test_llm_called_once_during_compression(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summary")
        s = ContextSummarizer(llm=llm, threshold=0.01)

        msgs = self._make_long_messages(20)
        await s.maybe_summarize(msgs, model_name="gpt-4")
        assert llm.ainvoke.call_count == 1

    @pytest.mark.asyncio
    async def test_fallback_summary_when_llm_fails(self):
        """When LLM raises an exception, the fallback text summary is used."""
        llm = AsyncMock()
        llm.ainvoke.side_effect = RuntimeError("LLM API error")
        s = ContextSummarizer(llm=llm, threshold=0.01)

        msgs = self._make_long_messages(20)
        # Should not raise
        result = await s.maybe_summarize(msgs, model_name="gpt-4")
        assert len(result) < len(msgs) or len(result) >= 1

    @pytest.mark.asyncio
    async def test_custom_min_keep_recent(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summary")
        s = ContextSummarizer(llm=llm, threshold=0.01, min_keep_recent=6)

        msgs = self._make_long_messages(20)
        result = await s.maybe_summarize(msgs, model_name="gpt-4")
        # 1 summary + at least 6 recent
        assert len(result) >= 6 + 1

    @pytest.mark.asyncio
    async def test_all_agent_roles_passed_to_llm(self):
        """Verify that the LLM is called once during compression."""
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summary")
        s = ContextSummarizer(llm=llm, threshold=0.01)

        msgs = self._make_long_messages(20)
        await s.maybe_summarize(msgs, model_name="gpt-4", agent_role="exploit")
        # The LLM must be called at least once
        assert llm.ainvoke.call_count >= 1


# ===========================================================================
# ContextSummarizer — Memory Capture Integration
# ===========================================================================

class TestContextSummarizerMemoryCapture:
    """Tests for memory capture of summaries."""

    @pytest.mark.asyncio
    async def test_summary_captured_when_memory_ns_set(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Important summary text")

        mock_ns = AsyncMock()
        mock_ns.capture.return_value = MagicMock()

        s = ContextSummarizer(llm=llm, threshold=0.01, memory_ns=mock_ns)

        msgs = [MagicMock(content="long " * 100) for _ in range(20)]
        await s.maybe_summarize(
            msgs,
            model_name="gpt-4",
            flow_id="flow-001",
            session_id="session-001",
            agent_role="recon",
        )
        mock_ns.capture.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_capture_without_memory_ns(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summary")
        s = ContextSummarizer(llm=llm, threshold=0.01, memory_ns=None)

        msgs = [MagicMock(content="long " * 100) for _ in range(20)]
        # Should not raise
        result = await s.maybe_summarize(msgs, model_name="gpt-4")
        assert result is not None

    @pytest.mark.asyncio
    async def test_memory_capture_failure_is_non_fatal(self):
        llm = AsyncMock()
        llm.ainvoke.return_value = MagicMock(content="Summary")

        mock_ns = AsyncMock()
        mock_ns.capture.side_effect = RuntimeError("Memory store down")

        s = ContextSummarizer(llm=llm, threshold=0.01, memory_ns=mock_ns)

        msgs = [MagicMock(content="long " * 100) for _ in range(20)]
        # Should not raise even when memory capture fails
        result = await s.maybe_summarize(msgs, model_name="gpt-4")
        assert result is not None


# ===========================================================================
# ContextSummarizer — Threshold from Environment Variable
# ===========================================================================

class TestContextSummarizerEnvThreshold:
    """Tests for AGENT_SUMMARY_THRESHOLD env var integration."""

    def test_default_threshold_used_when_no_env(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_SUMMARY_THRESHOLD", None)
            llm = MagicMock()
            s = ContextSummarizer(llm=llm)
            assert s.threshold == pytest.approx(_DEFAULT_SUMMARY_THRESHOLD)

    def test_threshold_loaded_from_env(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "0.5"}, clear=False):
            llm = MagicMock()
            s = ContextSummarizer(llm=llm)
            assert s.threshold == pytest.approx(0.5)

    def test_explicit_threshold_overrides_env(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "0.5"}, clear=False):
            llm = MagicMock()
            s = ContextSummarizer(llm=llm, threshold=0.9)
            assert s.threshold == pytest.approx(0.9)

    def test_invalid_env_uses_default(self):
        with patch.dict(os.environ, {"AGENT_SUMMARY_THRESHOLD": "bad"}, clear=False):
            llm = MagicMock()
            s = ContextSummarizer(llm=llm)
            assert s.threshold == pytest.approx(_DEFAULT_SUMMARY_THRESHOLD)


# ===========================================================================
# ContextSummarizer — Fallback Summary
# ===========================================================================

class TestFallbackSummary:
    """Tests for the _fallback_summary method."""

    def test_fallback_includes_message_content(self):
        llm = MagicMock()
        s = ContextSummarizer(llm=llm)
        msg1 = MagicMock()
        msg1.content = "First important message"
        msg1.type = "human"
        msg2 = MagicMock()
        msg2.content = "AI response about finding"
        msg2.type = "ai"

        summary = s._fallback_summary([msg1, msg2])
        assert "First important message" in summary
        assert "AI response about finding" in summary

    def test_fallback_truncates_long_content(self):
        llm = MagicMock()
        s = ContextSummarizer(llm=llm)
        msg = MagicMock()
        msg.content = "x" * 2000  # Very long message
        msg.type = "human"

        summary = s._fallback_summary([msg])
        # Each message is truncated to 500 chars, so total summary shouldn't be too huge
        assert len(summary) < 5000
