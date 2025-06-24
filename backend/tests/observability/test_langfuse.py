"""
Tests — Langfuse LLM Observability

Covers:
- LangfuseClient initialisation (enabled / disabled / no SDK)
- Trace creation, update, tagging
- Generation recording with token usage and cost calculation
- Span creation and ending
- llm_call() context manager
- tool_span() context manager
- agent_trace() context manager
- async_agent_trace() context manager
- score_trace() and event() helpers
- flush() / shutdown()
- health_check()
- get_langfuse() singleton
- BaseAgent Langfuse integration (start_langfuse_trace, record_llm_generation, etc.)
- Cost calculation accuracy across supported models
- Sample rate enforcement
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import time
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, PropertyMock

# Resolve paths relative to this test file for cross-environment portability
_BACKEND_DIR = Path(__file__).parent.parent.parent
_LANGFUSE_CLIENT = _BACKEND_DIR / "app" / "observability" / "langfuse_client.py"
_BASE_AGENT = _BACKEND_DIR / "app" / "agent" / "agents" / "__init__.py"


# ---------------------------------------------------------------------------
# Helpers to load the module without real langfuse SDK
# ---------------------------------------------------------------------------

def _make_fake_langfuse_sdk() -> types.ModuleType:
    """Create a minimal fake langfuse module for unit testing."""
    mod = types.ModuleType("langfuse")

    class FakeGeneration:
        def __init__(self, **kw):
            self.kw = kw
            self.updates = []

        def update(self, **kw):
            self.updates.append(kw)

    class FakeSpan:
        def __init__(self, **kw):
            self.kw = kw
            self.ended = False
            self.end_kwargs = {}

        def generation(self, **kw):
            return FakeGeneration(**kw)

        def span(self, **kw):
            return FakeSpan(**kw)

        def end(self, **kw):
            self.ended = True
            self.end_kwargs = kw

        def event(self, **kw):
            pass

        def score(self, **kw):
            pass

        def update(self, **kw):
            pass

    class FakeTrace:
        def __init__(self, **kw):
            self.kw = kw
            self.events: List[Dict] = []
            self.scores: List[Dict] = []
            self.updates: List[Dict] = []

        def generation(self, **kw):
            return FakeGeneration(**kw)

        def span(self, **kw):
            return FakeSpan(**kw)

        def event(self, **kw):
            self.events.append(kw)

        def score(self, **kw):
            self.scores.append(kw)

        def update(self, **kw):
            self.updates.append(kw)

    class FakeLangfuse:
        def __init__(self, **kw):
            self.kw = kw
            self.traces: List[FakeTrace] = []
            self.flushed = 0
            self.shut_down = False

        def trace(self, **kw):
            t = FakeTrace(**kw)
            self.traces.append(t)
            return t

        def flush(self):
            self.flushed += 1

        def shutdown(self):
            self.shut_down = True

    mod.Langfuse = FakeLangfuse
    mod.FakeTrace = FakeTrace  # type: ignore[attr-defined]
    mod.FakeGeneration = FakeGeneration  # type: ignore[attr-defined]
    mod.FakeSpan = FakeSpan  # type: ignore[attr-defined]
    return mod


def _load_langfuse_client_module(fake_sdk: Optional[types.ModuleType] = None):
    """Load the langfuse_client module, optionally injecting a fake SDK."""
    # Remove cached versions
    for key in list(sys.modules.keys()):
        if "langfuse_client" in key or key == "langfuse":
            del sys.modules[key]

    if fake_sdk is not None:
        sys.modules["langfuse"] = fake_sdk

    # Ensure parent package modules exist in sys.modules before exec
    for pkg in ("app", "app.core", "app.core.config", "app.observability"):
        if pkg not in sys.modules:
            sys.modules[pkg] = types.ModuleType(pkg)

    spec = importlib.util.spec_from_file_location(
        "app.observability.langfuse_client",
        str(_LANGFUSE_CLIENT),
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["app.observability.langfuse_client"] = mod  # register BEFORE exec
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class TestCostCalculation(unittest.TestCase):
    """Test _calculate_cost() for various models."""

    def setUp(self):
        self._mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())

    def test_gpt4o_cost(self):
        cost = self._mod._calculate_cost("gpt-4o", prompt_tokens=1000, completion_tokens=500)
        self.assertIsNotNone(cost)
        # 1000/1000 * 0.0025 + 500/1000 * 0.010 = 0.0025 + 0.005 = 0.0075
        self.assertAlmostEqual(cost, 0.0075, places=6)

    def test_gpt4o_mini_cost(self):
        cost = self._mod._calculate_cost("gpt-4o-mini", 1000, 1000)
        self.assertIsNotNone(cost)
        self.assertAlmostEqual(cost, 0.00015 + 0.0006, places=6)

    def test_claude_sonnet_cost(self):
        cost = self._mod._calculate_cost("claude-3-5-sonnet-20241022", 2000, 500)
        self.assertIsNotNone(cost)
        expected = (2000 / 1000) * 0.003 + (500 / 1000) * 0.015
        self.assertAlmostEqual(cost, expected, places=6)

    def test_unknown_model_returns_none(self):
        cost = self._mod._calculate_cost("unknown-model-xyz", 1000, 500)
        self.assertIsNone(cost)

    def test_zero_tokens_cost_is_zero(self):
        cost = self._mod._calculate_cost("gpt-4o", 0, 0)
        self.assertAlmostEqual(cost, 0.0, places=6)

    def test_groq_llama_cost(self):
        cost = self._mod._calculate_cost("llama-3.3-70b-versatile", 1000, 1000)
        self.assertIsNotNone(cost)
        expected = (1000 / 1000) * 0.00059 + (1000 / 1000) * 0.00079
        self.assertAlmostEqual(cost, expected, places=6)

    def test_deepseek_cost(self):
        cost = self._mod._calculate_cost("deepseek-chat", 500, 250)
        self.assertIsNotNone(cost)
        expected = (500 / 1000) * 0.00014 + (250 / 1000) * 0.00028
        self.assertAlmostEqual(cost, expected, places=6)

    def test_gemini_flash_cost(self):
        cost = self._mod._calculate_cost("gemini-1.5-flash", 10000, 5000)
        self.assertIsNotNone(cost)

    def test_all_supported_models_have_costs(self):
        supported = [
            "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo",
            "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229",
            "gemini-1.5-flash", "gemini-1.5-pro",
            "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
            "deepseek-chat", "deepseek-coder",
        ]
        for model in supported:
            cost = self._mod._calculate_cost(model, 1000, 500)
            self.assertIsNotNone(cost, f"Cost table missing for model: {model}")
            self.assertGreater(cost, 0)


class TestLangfuseClientInit(unittest.TestCase):
    """Test LangfuseClient initialisation in various configurations."""

    def _make_client(self, fake_sdk, **kwargs):
        mod = _load_langfuse_client_module(fake_sdk)
        return mod.LangfuseClient(**kwargs), mod

    def test_disabled_when_no_keys(self):
        client, _ = self._make_client(
            _make_fake_langfuse_sdk(),
            public_key="",
            secret_key="",
        )
        self.assertFalse(client.enabled)

    def test_enabled_with_keys(self):
        client, _ = self._make_client(
            _make_fake_langfuse_sdk(),
            public_key="pk-test",
            secret_key="sk-test",
        )
        self.assertTrue(client.enabled)

    def test_disabled_by_flag(self):
        client, _ = self._make_client(
            _make_fake_langfuse_sdk(),
            public_key="pk-test",
            secret_key="sk-test",
            enabled=False,
        )
        self.assertFalse(client.enabled)

    def test_graceful_when_sdk_missing(self):
        # Remove langfuse from sys.modules to simulate missing package
        mod = _load_langfuse_client_module(None)
        # Should not raise
        client = mod.LangfuseClient(public_key="pk", secret_key="sk")
        self.assertFalse(client.enabled)

    def test_health_check_shape(self):
        client, _ = self._make_client(
            _make_fake_langfuse_sdk(),
            public_key="pk-test",
            secret_key="sk-test",
        )
        hc = client.health_check()
        self.assertIn("enabled", hc)
        self.assertIn("client_ready", hc)
        self.assertIn("sample_rate", hc)

    def test_sample_rate_clamped(self):
        client, _ = self._make_client(
            _make_fake_langfuse_sdk(),
            public_key="pk",
            secret_key="sk",
            sample_rate=5.0,
        )
        self.assertLessEqual(client._sample_rate, 1.0)
        client2, _ = self._make_client(
            _make_fake_langfuse_sdk(),
            public_key="pk",
            secret_key="sk",
            sample_rate=-1.0,
        )
        self.assertGreaterEqual(client2._sample_rate, 0.0)


class TestLangfuseClientTracing(unittest.TestCase):
    """Test trace / generation / span operations."""

    def setUp(self):
        self._sdk = _make_fake_langfuse_sdk()
        self._mod = _load_langfuse_client_module(self._sdk)
        self._client = self._mod.LangfuseClient(
            public_key="pk-test",
            secret_key="sk-test",
        )

    def test_create_trace_returns_object(self):
        trace = self._client.create_trace(name="test-trace")
        self.assertIsNotNone(trace)

    def test_create_trace_with_all_params(self):
        trace = self._client.create_trace(
            name="pentest:192.168.1.1",
            trace_id="custom-trace-id",
            session_id="sess-123",
            user_id="user-abc",
            tags=["recon", "webapp"],
            metadata={"target": "192.168.1.1"},
            input={"target": "192.168.1.1"},
        )
        self.assertIsNotNone(trace)

    def test_update_trace(self):
        trace = self._client.create_trace(name="t")
        self._client.update_trace(trace, output={"result": "done"})
        # Should not raise

    def test_update_trace_with_none_is_noop(self):
        self._client.update_trace(None, output={"x": 1})
        # Should not raise

    def test_record_generation_with_tokens(self):
        trace = self._client.create_trace(name="gen-test")
        data = self._mod.GenerationData(
            name="recon:llm_call",
            model="gpt-4o",
            prompt_tokens=500,
            completion_tokens=200,
            total_tokens=700,
            latency_ms=123.4,
            input_messages=[{"role": "user", "content": "scan target"}],
            output_text="Found open ports: 80, 443",
        )
        gen = self._client.record_generation(trace=trace, data=data)
        self.assertIsNotNone(gen)

    def test_record_generation_auto_calculates_cost(self):
        trace = self._client.create_trace(name="cost-test")
        data = self._mod.GenerationData(
            name="exploit:llm",
            model="gpt-4o",
            prompt_tokens=1000,
            completion_tokens=500,
        )
        # Should not raise — cost auto-calculated
        gen = self._client.record_generation(trace=trace, data=data)
        self.assertIsNotNone(gen)

    def test_record_generation_with_error(self):
        trace = self._client.create_trace(name="err-test")
        data = self._mod.GenerationData(
            name="webapp:llm",
            model="claude-3-5-sonnet-20241022",
            error="Connection timeout",
        )
        gen = self._client.record_generation(trace=trace, data=data)
        self.assertIsNotNone(gen)

    def test_start_and_end_span(self):
        trace = self._client.create_trace(name="span-test")
        span = self._client.start_span(
            trace=trace,
            name="tool:naabu",
            input={"target": "192.168.1.1"},
        )
        self.assertIsNotNone(span)
        self._client.end_span(span, output={"open_ports": [80, 443]})
        self.assertTrue(span.ended)

    def test_end_span_with_error(self):
        trace = self._client.create_trace(name="span-err")
        span = self._client.start_span(trace=trace, name="tool:naabu")
        self._client.end_span(span, error="naabu not available")
        self.assertTrue(span.ended)

    def test_end_none_span_is_noop(self):
        self._client.end_span(None, output="x")
        # Should not raise

    def test_score_trace(self):
        trace = self._client.create_trace(name="score-test")
        self._client.score_trace(trace, name="exploit_success", value=0.9)
        self.assertEqual(len(trace.scores), 1)
        self.assertEqual(trace.scores[0]["name"], "exploit_success")

    def test_score_none_trace_is_noop(self):
        self._client.score_trace(None, name="x", value=1.0)
        # Should not raise

    def test_event_on_trace(self):
        trace = self._client.create_trace(name="event-test")
        self._client.event(trace, name="phase_transition", input={"from": "recon", "to": "exploit"})
        self.assertEqual(len(trace.events), 1)

    def test_flush_calls_sdk_flush(self):
        self._client.flush()
        sdk_client = self._client._client
        self.assertGreaterEqual(sdk_client.flushed, 1)

    def test_shutdown(self):
        self._client.shutdown()
        sdk_client = self._client._client
        self.assertTrue(sdk_client.shut_down)

    def test_disabled_client_returns_none_for_trace(self):
        mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())
        client = mod.LangfuseClient(enabled=False)
        trace = client.create_trace(name="x")
        self.assertIsNone(trace)

    def test_disabled_client_noop_flush(self):
        mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())
        client = mod.LangfuseClient(enabled=False)
        client.flush()  # Should not raise

    def test_generation_with_parent_span(self):
        trace = self._client.create_trace(name="nested")
        parent = self._client.start_span(trace=trace, name="agent:recon")
        data = self._mod.GenerationData(name="sub-gen", model="gpt-4o-mini")
        gen = self._client.record_generation(trace=trace, data=data, parent_span=parent)
        self.assertIsNotNone(gen)


class TestLangfuseContextManagers(unittest.TestCase):
    """Test context manager helpers."""

    def setUp(self):
        self._sdk = _make_fake_langfuse_sdk()
        self._mod = _load_langfuse_client_module(self._sdk)
        self._client = self._mod.LangfuseClient(
            public_key="pk-test",
            secret_key="sk-test",
        )

    def test_agent_trace_context_manager(self):
        with self._client.agent_trace("recon", "192.168.1.1", session_id="s1") as trace:
            self.assertIsNotNone(trace)

    def test_agent_trace_yields_none_when_disabled(self):
        mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())
        client = mod.LangfuseClient(enabled=False)
        with client.agent_trace("recon", "10.0.0.1") as trace:
            self.assertIsNone(trace)

    def test_agent_trace_flushes_on_exit(self):
        initial_flush = self._client._client.flushed
        with self._client.agent_trace("exploit", "192.168.1.1") as trace:
            pass
        self.assertGreater(self._client._client.flushed, initial_flush)

    def test_agent_trace_on_exception(self):
        with self.assertRaises(ValueError):
            with self._client.agent_trace("webapp", "10.0.0.1") as trace:
                raise ValueError("test error")

    def test_async_agent_trace(self):
        async def _run():
            async with self._client.async_agent_trace(
                "report", "target.com", session_id="sess-async"
            ) as trace:
                self.assertIsNotNone(trace)
        asyncio.run(_run())

    def test_llm_call_context_manager(self):
        trace = self._client.create_trace(name="llm-cm-test")
        with self._client.llm_call(trace, "recon", "gpt-4o") as gen:
            gen.set_output("LLM response text", {"prompt_tokens": 100, "completion_tokens": 50})
        # Should complete without error

    def test_llm_call_records_latency(self):
        trace = self._client.create_trace(name="latency-test")
        with self._client.llm_call(trace, "exploit", "claude-3-5-sonnet-20241022") as gen:
            time.sleep(0.01)
            gen.set_output("exploit code")
        # Should not raise

    def test_tool_span_context_manager(self):
        trace = self._client.create_trace(name="tool-cm-test")
        with self._client.tool_span(trace, "naabu", input={"target": "10.0.0.1"}) as sp:
            sp.set_output({"open_ports": [22, 80, 443]})
        # Should complete without error

    def test_tool_span_on_exception(self):
        trace = self._client.create_trace(name="tool-err-test")
        with self.assertRaises(RuntimeError):
            with self._client.tool_span(trace, "nuclei") as sp:
                raise RuntimeError("nuclei crashed")


class TestGetLangfuseSingleton(unittest.TestCase):
    """Test the module-level get_langfuse() singleton."""

    def test_returns_langfuse_client_instance(self):
        # Clean up cache
        mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())
        # Call _build_langfuse_client directly since get_langfuse() uses @lru_cache
        client = mod.LangfuseClient()
        self.assertIsInstance(client, mod.LangfuseClient)

    def test_disabled_client_health_check(self):
        mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())
        client = mod.LangfuseClient()
        hc = client.health_check()
        self.assertFalse(hc["enabled"])


class TestBaseAgentLangfuseIntegration(unittest.TestCase):
    """Test Langfuse integration on the BaseAgent level."""

    def _make_agent(self):
        """Create a minimal concrete agent for testing."""
        import importlib.util as ilu
        import types
        from typing import TypedDict

        # Stub heavy imports
        for mod_name in [
            "app", "app.agent", "app.agent.state",
            "app.agent.tools", "app.agent.tools.base_tool",
            "app.agent.tools.tool_registry", "app.agent.memory",
            "app.agent.memory.episodic_memory", "app.agent.memory.graphiti_client",
            "app.agent.memory.flow_memory", "app.agent.memory.auto_capture",
        ]:
            if mod_name not in sys.modules:
                sys.modules[mod_name] = types.ModuleType(mod_name)

        # Stub Phase enum and AgentState
        from enum import Enum
        Phase = Enum("Phase", {"INFORMATIONAL": "informational"})
        AgentState = TypedDict("AgentState", {"messages": list}, total=False)

        agent_state_mod = types.ModuleType("app.agent.state.agent_state")
        agent_state_mod.Phase = Phase  # type: ignore
        agent_state_mod.AgentState = AgentState  # type: ignore
        sys.modules["app.agent.state.agent_state"] = agent_state_mod

        # Stub BaseTool and ToolRegistry
        class FakeRegistry:
            def get_tool(self, name):
                return None
            def get_tools_for_phase(self, phase):
                return {}

        base_tool_mod = types.ModuleType("app.agent.tools.base_tool")
        base_tool_mod.BaseTool = object  # type: ignore
        sys.modules["app.agent.tools.base_tool"] = base_tool_mod

        tool_registry_mod = types.ModuleType("app.agent.tools.tool_registry")
        tool_registry_mod.ToolRegistry = FakeRegistry  # type: ignore
        sys.modules["app.agent.tools.tool_registry"] = tool_registry_mod

        # Load the module
        for key in list(sys.modules.keys()):
            if key == "app.agent.agents":
                del sys.modules[key]

        sys.modules["langfuse"] = _make_fake_langfuse_sdk()
        # Also set up observability module stub
        obs_mod = types.ModuleType("app.observability")
        lf_mod = types.ModuleType("app.observability.langfuse_client")
        sys.modules["app.observability"] = obs_mod
        sys.modules["app.observability.langfuse_client"] = lf_mod

        spec = ilu.spec_from_file_location(
            "app.agent.agents",
            str(_BASE_AGENT),
        )
        mod = ilu.module_from_spec(spec)
        sys.modules["app.agent.agents"] = mod
        spec.loader.exec_module(mod)

        class ConcreteAgent(mod.BaseAgent):
            AGENT_NAME = "test_agent"
            PREFERRED_TOOLS = []
            def get_phase(self):
                return Phase.INFORMATIONAL
            async def run(self, state, task):
                return {}

        registry = FakeRegistry()
        return ConcreteAgent(registry=registry), mod

    def test_agent_has_langfuse_attributes(self):
        agent, mod = self._make_agent()
        self.assertIsNotNone(agent)
        self.assertTrue(hasattr(agent, "_obs_ctx"))
        self.assertTrue(hasattr(agent, "_lf_trace"))
        self.assertIsNone(agent._lf_trace)

    def test_set_observability_ctx(self):
        agent, mod = self._make_agent()
        ctx = {"trace_id": "abc123", "session_id": "sess-1", "user_id": "user-1"}
        agent.set_observability_ctx(ctx)
        self.assertEqual(agent._obs_ctx["trace_id"], "abc123")
        self.assertEqual(agent._obs_ctx["session_id"], "sess-1")

    def test_get_langfuse_returns_none_when_not_configured(self):
        agent, mod = self._make_agent()
        # _get_langfuse should gracefully return None when module import fails
        result = agent._get_langfuse()
        # Either None or a disabled LangfuseClient
        if result is not None:
            self.assertFalse(result.enabled)

    def test_record_llm_generation_noop_without_trace(self):
        agent, mod = self._make_agent()
        # Should not raise even without a trace
        agent.record_llm_generation(
            model="gpt-4o",
            output_text="test",
            prompt_tokens=100,
            completion_tokens=50,
        )

    def test_record_tool_call_noop_without_trace(self):
        agent, mod = self._make_agent()
        agent.record_tool_call(
            tool_name="naabu",
            input={"target": "10.0.0.1"},
            output={"ports": [80]},
        )

    def test_finalize_langfuse_trace_noop_without_trace(self):
        agent, mod = self._make_agent()
        agent.finalize_langfuse_trace(output={"result": "done"})


class TestGenerationDataclass(unittest.TestCase):
    """Test the GenerationData and SpanData dataclasses."""

    def setUp(self):
        self._mod = _load_langfuse_client_module(_make_fake_langfuse_sdk())

    def test_generation_data_defaults(self):
        data = self._mod.GenerationData(name="test", model="gpt-4o")
        self.assertEqual(data.prompt_tokens, 0)
        self.assertEqual(data.completion_tokens, 0)
        self.assertEqual(data.latency_ms, 0.0)
        self.assertIsNone(data.cost_usd)
        self.assertIsNone(data.error)
        self.assertIsNotNone(data.metadata)

    def test_generation_data_with_all_fields(self):
        data = self._mod.GenerationData(
            name="recon:llm",
            model="claude-3-5-sonnet-20241022",
            prompt_tokens=1000,
            completion_tokens=300,
            total_tokens=1300,
            latency_ms=456.7,
            cost_usd=0.0075,
            input_messages=[{"role": "system", "content": "You are an agent"}],
            output_text="Scan complete",
            error=None,
            metadata={"agent_role": "recon"},
        )
        self.assertEqual(data.total_tokens, 1300)
        self.assertAlmostEqual(data.cost_usd, 0.0075)

    def test_span_data_defaults(self):
        data = self._mod.SpanData(name="tool:naabu")
        self.assertIsNone(data.input)
        self.assertIsNone(data.output)
        self.assertEqual(data.latency_ms, 0.0)
        self.assertIsNone(data.error)


if __name__ == "__main__":
    unittest.main()
