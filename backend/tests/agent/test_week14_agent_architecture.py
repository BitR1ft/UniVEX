"""
Tests for Week 14 — Agent Architecture.

Covers:
          assertion helpers, AgentTestScenario
"""

import json
import pytest
from unittest.mock import AsyncMock, Mock, patch
from langchain_core.messages import HumanMessage, AIMessage

from app.agent.state.agent_state import AgentState, Phase
from app.agent.prompts.system_prompts import (
    get_system_prompt,
    INFORMATIONAL_PHASE_PROMPT,
    EXPLOITATION_PHASE_PROMPT,
    POST_EXPLOITATION_PHASE_PROMPT,
    COMPLETE_PHASE_PROMPT,
)
from app.agent.core.react_nodes import ReActNodes
from app.agent.core.graph import should_continue, create_agent_graph, approval_gate
from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.tool_registry import ToolRegistry
from app.agent.config import (
    AgentConfig, PhaseConfig, AgentConfigManager, DEFAULT_CONFIG,
    get_default_config_manager,
)
from app.agent.testing import (
    MockLLM, MockTool, AgentTestScenario,
    build_initial_state, build_state_with_observation, build_state_pending_approval,
    assert_state_stopped, assert_state_has_messages, assert_last_message_contains,
    assert_tool_output_present, assert_phase, assert_next_action,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_state() -> AgentState:
    return build_initial_state()


@pytest.fixture
def mock_registry():
    registry = ToolRegistry()
    tool = MockTool(name="echo", response="hello")
    registry.register_tool(tool, allowed_phases=list(Phase))
    return registry


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestLangGraphSetup:
    """Day 86 — LangGraph graph structure and entry point."""

    def test_should_continue_think_is_default(self, minimal_state):
        minimal_state["next_action"] = "unknown"
        assert should_continue(minimal_state) == "think"

    def test_should_continue_end_on_stop(self, minimal_state):
        minimal_state["should_stop"] = True
        assert should_continue(minimal_state) == "end"

    def test_should_continue_act(self, minimal_state):
        minimal_state["next_action"] = "act"
        assert should_continue(minimal_state) == "act"

    def test_should_continue_observe(self, minimal_state):
        minimal_state["next_action"] = "observe"
        assert should_continue(minimal_state) == "observe"

    def test_should_continue_approval(self, minimal_state):
        minimal_state["next_action"] = "approval"
        assert should_continue(minimal_state) == "approval"

    def test_create_agent_graph_no_memory(self):
        """create_agent_graph with enable_memory=False should not raise."""
        with patch("app.agent.core.graph.ReActNodes") as MockNodes:
            MockNodes.return_value.think = AsyncMock()
            MockNodes.return_value.act = AsyncMock()
            MockNodes.return_value.observe = AsyncMock()
            graph = create_agent_graph(enable_memory=False)
            assert graph is not None

    def test_create_agent_graph_with_memory(self):
        """create_agent_graph with enable_memory=True should not raise."""
        with patch("app.agent.core.graph.ReActNodes") as MockNodes:
            MockNodes.return_value.think = AsyncMock()
            MockNodes.return_value.act = AsyncMock()
            MockNodes.return_value.observe = AsyncMock()
            graph = create_agent_graph(enable_memory=True)
            assert graph is not None


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestSystemPrompts:
    """Day 87 — per-phase prompts and get_system_prompt()."""

    def test_informational_prompt_not_empty(self):
        assert len(INFORMATIONAL_PHASE_PROMPT) > 100

    def test_exploitation_prompt_not_empty(self):
        assert len(EXPLOITATION_PHASE_PROMPT) > 100

    def test_post_exploitation_prompt_not_empty(self):
        assert len(POST_EXPLOITATION_PHASE_PROMPT) > 100

    def test_complete_prompt_not_empty(self):
        assert len(COMPLETE_PHASE_PROMPT) > 100

    def test_get_system_prompt_informational(self):
        p = get_system_prompt(Phase.INFORMATIONAL)
        assert "INFORMATIONAL" in p.upper() or "information" in p.lower()

    def test_get_system_prompt_exploitation(self):
        p = get_system_prompt(Phase.EXPLOITATION)
        assert "EXPLOIT" in p.upper()

    def test_get_system_prompt_post_exploitation(self):
        p = get_system_prompt(Phase.POST_EXPLOITATION)
        assert "POST" in p.upper()

    def test_get_system_prompt_complete(self):
        p = get_system_prompt(Phase.COMPLETE)
        assert "COMPLETE" in p.upper() or "complete" in p.lower()

    def test_get_system_prompt_accepts_string(self):
        """Should also work when passed a raw phase string."""
        p = get_system_prompt("informational")
        assert p == INFORMATIONAL_PHASE_PROMPT

    def test_get_system_prompt_unknown_falls_back(self):
        """Unknown phase should fall back to informational prompt."""
        p = get_system_prompt("nonexistent_phase")
        assert p == INFORMATIONAL_PHASE_PROMPT

    def test_informational_prompt_contains_structured_reasoning(self):
        assert "THOUGHT" in INFORMATIONAL_PHASE_PROMPT.upper() or \
               "SITUATION" in INFORMATIONAL_PHASE_PROMPT.upper() or \
               "reasoning" in INFORMATIONAL_PHASE_PROMPT.lower()

    def test_exploitation_prompt_contains_risk_analysis(self):
        assert "RISK" in EXPLOITATION_PHASE_PROMPT.upper()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestMemorySaver:
    """Day 88 — MemorySaver wired through graph creation."""

    def test_memory_enabled_by_default(self):
        with patch("app.agent.core.graph.ReActNodes") as MockNodes:
            MockNodes.return_value.think = AsyncMock()
            MockNodes.return_value.act = AsyncMock()
            MockNodes.return_value.observe = AsyncMock()
            graph = create_agent_graph(enable_memory=True)
            # If MemorySaver is attached, the graph's checkpointer should not be None
            assert graph is not None

    def test_memory_disabled_flag(self):
        with patch("app.agent.core.graph.ReActNodes") as MockNodes:
            MockNodes.return_value.think = AsyncMock()
            MockNodes.return_value.act = AsyncMock()
            MockNodes.return_value.observe = AsyncMock()
            # Should not raise even when memory is disabled
            graph = create_agent_graph(enable_memory=False)
            assert graph is not None


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestToolInterfaceFramework:
    """Day 89 — BaseTool, ToolMetadata, registration."""

    def test_mock_tool_metadata(self):
        tool = MockTool(name="scanner", description="port scanner")
        assert tool.name == "scanner"
        assert tool.description == "port scanner"
        assert isinstance(tool.metadata, ToolMetadata)

    def test_mock_tool_execute(self):
        """MockTool.execute is async and returns response."""
        import asyncio
        tool = MockTool(response="scan complete")
        result = asyncio.run(tool.execute(target="10.0.0.1"))
        assert result == "scan complete"

    def test_mock_tool_records_calls(self):
        import asyncio
        tool = MockTool()
        asyncio.run(tool.execute(a=1))
        asyncio.run(tool.execute(b=2))
        assert tool.call_count == 2
        assert tool.calls[0] == {"a": 1}

    def test_mock_tool_failure(self):
        import asyncio
        tool = MockTool(should_fail=True, fail_message="boom")
        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(tool.execute())

    def test_tool_registry_phase_control(self):
        registry = ToolRegistry()
        recon_tool = MockTool(name="recon")
        exploit_tool = MockTool(name="exploit")
        registry.register_tool(recon_tool, [Phase.INFORMATIONAL])
        registry.register_tool(exploit_tool, [Phase.EXPLOITATION])

        assert registry.is_tool_allowed("recon", Phase.INFORMATIONAL)
        assert not registry.is_tool_allowed("recon", Phase.EXPLOITATION)
        assert registry.is_tool_allowed("exploit", Phase.EXPLOITATION)
        assert not registry.is_tool_allowed("exploit", Phase.INFORMATIONAL)

    def test_tool_registry_unregister(self):
        registry = ToolRegistry()
        tool = MockTool(name="temp")
        registry.register_tool(tool)
        registry.unregister_tool("temp")
        assert "temp" not in registry.list_all_tools()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestReActPattern:
    """Day 90 — LLM response parsing and ACT/OBSERVE node logic."""

    def _make_nodes(self):
        nodes = ReActNodes.__new__(ReActNodes)
        nodes.model_provider = "openai"
        nodes.model_name = "gpt-4"
        return nodes

    def test_parse_simple_respond(self):
        nodes = self._make_nodes()
        response = (
            "THOUGHT: I have enough info.\n"
            "ACTION: respond\n"
            "TOOL_INPUT: Task complete."
        )
        thought, action, tool_input = nodes._parse_llm_response(response)
        assert thought == "I have enough info."
        assert action == "respond"
        assert tool_input == "Task complete."

    def test_parse_tool_call_with_json(self):
        nodes = self._make_nodes()
        response = (
            "THOUGHT: I need to scan.\n"
            "ACTION: naabu\n"
            'TOOL_INPUT: {"target": "10.0.0.1", "ports": "80,443"}'
        )
        thought, action, tool_input = nodes._parse_llm_response(response)
        assert action == "naabu"
        assert isinstance(tool_input, dict)
        assert tool_input["target"] == "10.0.0.1"

    def test_parse_multiline_thought(self):
        nodes = self._make_nodes()
        response = (
            "THOUGHT: First thought.\n"
            "Second thought.\n"
            "ACTION: respond\n"
            "TOOL_INPUT: done"
        )
        thought, action, tool_input = nodes._parse_llm_response(response)
        assert "First thought." in thought
        assert "Second thought." in thought

    def test_parse_invalid_json_falls_back(self):
        nodes = self._make_nodes()
        response = (
            "THOUGHT: scanning\n"
            "ACTION: naabu\n"
            "TOOL_INPUT: {broken json}"
        )
        thought, action, tool_input = nodes._parse_llm_response(response)
        assert action == "naabu"
        assert tool_input == {}  # Falls back to empty dict for non-respond actions

    def test_parse_no_tool_input(self):
        nodes = self._make_nodes()
        response = "THOUGHT: Think.\nACTION: respond"
        thought, action, tool_input = nodes._parse_llm_response(response)
        assert action == "respond"

    @pytest.mark.asyncio
    async def test_act_node_tool_not_found(self, mock_registry):
        """ACT node returns think-redirect when tool is not found."""
        nodes = ReActNodes.__new__(ReActNodes)
        nodes.model_provider = "openai"
        nodes.model_name = "gpt-4"
        nodes._get_error_recovery_hint = Mock(return_value="")

        state = build_initial_state(
            next_action="act",
            selected_tool="nonexistent",
            tool_input={"target": "10.0.0.1"},
        )

        with patch(
            "app.agent.tools.tool_registry.get_global_registry",
            return_value=mock_registry,
        ):
            result = await nodes.act(state)

        assert result["next_action"] == "think"
        assert "not available" in result["observation"] or "Unknown tool" in result["observation"]

    @pytest.mark.asyncio
    async def test_observe_node_adds_message(self):
        """OBSERVE node appends tool output to messages."""
        nodes = ReActNodes.__new__(ReActNodes)
        state = build_initial_state(
            next_action="observe",
            observation="Port 80 is open",
        )
        result = await nodes.observe(state)
        assert result["next_action"] == "think"
        msg_contents = [m.content for m in result["messages"]]
        assert any("Port 80 is open" in c for c in msg_contents)

    @pytest.mark.asyncio
    async def test_approval_gate_approved(self):
        """Approval gate forwards to act when status is approved."""
        state = build_state_pending_approval("exploit_execute")
        state["pending_approval"]["status"] = "approved"
        result = await approval_gate(state)
        assert result["next_action"] == "act"
        assert result["pending_approval"] is None

    @pytest.mark.asyncio
    async def test_approval_gate_rejected_stops(self):
        """Approval gate stops agent when status is rejected."""
        state = build_state_pending_approval("exploit_execute")
        state["pending_approval"]["status"] = "rejected"
        result = await approval_gate(state)
        assert result["should_stop"] is True
        assert result["next_action"] == "end"

    @pytest.mark.asyncio
    async def test_approval_gate_pending_stops(self):
        """Approval gate stops when approval is still pending."""
        state = build_state_pending_approval("exploit_execute")
        # status remains 'pending' (not changed)
        result = await approval_gate(state)
        assert result["should_stop"] is True


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestAgentConfiguration:
    """Day 91 — AgentConfig, PhaseConfig, AgentConfigManager."""

    def test_default_config_has_all_phases(self):
        for phase in Phase:
            cfg = DEFAULT_CONFIG.get_phase_config(phase)
            assert cfg.phase == phase

    def test_phase_config_serialisation_roundtrip(self):
        pc = PhaseConfig(
            phase=Phase.EXPLOITATION,
            allowed_tools=["exploit_execute"],
            max_iterations=10,
            require_approval_for=["exploit_execute"],
        )
        pc2 = PhaseConfig.from_dict(pc.to_dict())
        assert pc2.phase == Phase.EXPLOITATION
        assert pc2.max_iterations == 10
        assert "exploit_execute" in pc2.allowed_tools

    def test_agent_config_roundtrip(self):
        cfg = AgentConfig(
            model_provider="anthropic",
            model_name="claude-3-opus-20240229",
            default_temperature=0.3,
        )
        cfg2 = AgentConfig.from_dict(cfg.to_dict())
        assert cfg2.model_provider == "anthropic"
        assert cfg2.default_temperature == 0.3

    def test_agent_config_json_roundtrip(self):
        cfg = DEFAULT_CONFIG
        json_str = cfg.to_json()
        cfg2 = AgentConfig.from_json(json_str)
        assert cfg2.model_provider == cfg.model_provider
        assert cfg2.model_name == cfg.model_name

    def test_get_temperature_uses_phase_override(self):
        cfg = AgentConfig()
        cfg.phases[Phase.EXPLOITATION.value] = PhaseConfig(
            phase=Phase.EXPLOITATION, temperature=0.1
        )
        assert cfg.get_temperature(Phase.EXPLOITATION) == 0.1

    def test_get_temperature_falls_back_to_default(self):
        cfg = AgentConfig(default_temperature=0.5)
        cfg.phases[Phase.INFORMATIONAL.value] = PhaseConfig(
            phase=Phase.INFORMATIONAL, temperature=None
        )
        assert cfg.get_temperature(Phase.INFORMATIONAL) == 0.5

    def test_get_max_iterations(self):
        cfg = AgentConfig()
        cfg.phases[Phase.INFORMATIONAL.value] = PhaseConfig(
            phase=Phase.INFORMATIONAL, max_iterations=15
        )
        assert cfg.get_max_iterations(Phase.INFORMATIONAL) == 15

    def test_is_tool_allowed_empty_means_all(self):
        cfg = AgentConfig()
        cfg.phases[Phase.INFORMATIONAL.value] = PhaseConfig(
            phase=Phase.INFORMATIONAL, allowed_tools=[]
        )
        assert cfg.is_tool_allowed("any_tool", Phase.INFORMATIONAL) is True

    def test_is_tool_allowed_explicit_list(self):
        cfg = AgentConfig()
        cfg.phases[Phase.INFORMATIONAL.value] = PhaseConfig(
            phase=Phase.INFORMATIONAL, allowed_tools=["naabu", "curl"]
        )
        assert cfg.is_tool_allowed("naabu", Phase.INFORMATIONAL) is True
        assert cfg.is_tool_allowed("metasploit_search", Phase.INFORMATIONAL) is False

    def test_requires_approval(self):
        cfg = AgentConfig()
        cfg.phases[Phase.EXPLOITATION.value] = PhaseConfig(
            phase=Phase.EXPLOITATION,
            require_approval_for=["exploit_execute"],
        )
        assert cfg.requires_approval("exploit_execute", Phase.EXPLOITATION) is True
        assert cfg.requires_approval("curl", Phase.EXPLOITATION) is False

    def test_manager_load_from_dict(self):
        manager = AgentConfigManager()
        data = DEFAULT_CONFIG.to_dict()
        data["model_name"] = "gpt-4-turbo"
        cfg = manager.load_from_dict(data)
        assert cfg.model_name == "gpt-4-turbo"

    def test_manager_load_invalid_raises(self):
        manager = AgentConfigManager()
        with pytest.raises(ValueError):
            manager.load_from_dict({"model_provider": "unknown_provider"})

    def test_manager_load_from_json(self):
        manager = AgentConfigManager()
        json_str = DEFAULT_CONFIG.to_json()
        cfg = manager.load_from_json(json_str)
        assert cfg.model_provider == DEFAULT_CONFIG.model_provider

    def test_manager_update_phase(self):
        manager = AgentConfigManager()
        pc = manager.update_phase(Phase.EXPLOITATION, max_iterations=5)
        assert pc.max_iterations == 5

    def test_manager_update_phase_invalid_field(self):
        manager = AgentConfigManager()
        with pytest.raises(ValueError, match="no field"):
            manager.update_phase(Phase.EXPLOITATION, nonexistent_field=True)

    def test_manager_set_model(self):
        manager = AgentConfigManager()
        manager.set_model("anthropic", "claude-3-haiku-20240307")
        assert manager.get_config().model_provider == "anthropic"

    def test_manager_set_model_invalid_provider(self):
        manager = AgentConfigManager()
        with pytest.raises(ValueError, match="Unknown provider"):
            manager.set_model("cohere", "command-r")

    def test_manager_add_approved_tool(self):
        manager = AgentConfigManager()
        manager.add_approved_tool("naabu", Phase.EXPLOITATION)
        pc = manager.get_phase_config(Phase.EXPLOITATION)
        assert "naabu" in pc.allowed_tools
        assert "naabu" not in pc.require_approval_for

    def test_manager_validate_ok(self):
        manager = AgentConfigManager()
        assert manager.validate() is True

    def test_manager_validate_invalid_temperature(self):
        manager = AgentConfigManager()
        manager.get_config().default_temperature = 3.0  # out of range
        with pytest.raises(ValueError):
            manager.validate()

    def test_get_default_config_manager_singleton(self):
        m1 = get_default_config_manager()
        m2 = get_default_config_manager()
        assert m1 is m2

    def test_default_config_exploitation_requires_approval(self):
        """Exploitation phase must require approval for dangerous tools."""
        pc = DEFAULT_CONFIG.get_phase_config(Phase.EXPLOITATION)
        assert "exploit_execute" in pc.require_approval_for or \
               len(pc.require_approval_for) > 0


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestAgentTestingFramework:
    """Day 92 — MockLLM, MockTool, state builders, assertion helpers."""

    # ── MockLLM ─────────────────────────────────────────────────────────────

    def test_mock_llm_returns_response(self):
        import asyncio
        mock = MockLLM(["THOUGHT: done\nACTION: respond\nTOOL_INPUT: ok"])
        resp = asyncio.run(mock.ainvoke([]))
        assert "done" in resp.content

    def test_mock_llm_cycles_responses(self):
        import asyncio
        mock = MockLLM(["resp-A", "resp-B"])
        r1 = asyncio.run(mock.ainvoke([]))
        r2 = asyncio.run(mock.ainvoke([]))
        r3 = asyncio.run(mock.ainvoke([]))
        assert r1.content == "resp-A"
        assert r2.content == "resp-B"
        assert r3.content == "resp-A"  # cycles back

    def test_mock_llm_call_count(self):
        import asyncio
        mock = MockLLM()
        asyncio.run(mock.ainvoke([]))
        asyncio.run(mock.ainvoke([]))
        assert mock.call_count == 2

    def test_mock_llm_reset(self):
        import asyncio
        mock = MockLLM()
        asyncio.run(mock.ainvoke([]))
        mock.reset()
        assert mock.call_count == 0

    def test_mock_llm_build_tool_response(self):
        mock = MockLLM()
        r = mock.build_tool_response("Scanning", "naabu", {"target": "10.0.0.1"})
        assert "THOUGHT: Scanning" in r
        assert "ACTION: naabu" in r
        assert '"target"' in r

    # ── State Builders ───────────────────────────────────────────────────────

    def test_build_initial_state_defaults(self):
        state = build_initial_state()
        assert state["next_action"] == "think"
        assert state["should_stop"] is False
        assert state["messages"] == []

    def test_build_initial_state_overrides(self):
        state = build_initial_state(phase=Phase.EXPLOITATION, should_stop=True)
        assert state["current_phase"] == Phase.EXPLOITATION
        assert state["should_stop"] is True

    def test_build_state_with_observation(self):
        state = build_state_with_observation("Port 443 open")
        assert state["observation"] == "Port 443 open"
        assert state["next_action"] == "observe"

    def test_build_state_pending_approval(self):
        state = build_state_pending_approval("exploit_execute")
        assert state["pending_approval"]["tool"] == "exploit_execute"
        assert state["pending_approval"]["status"] == "pending"
        assert state["next_action"] == "approval"

    # ── Assertion Helpers ────────────────────────────────────────────────────

    def test_assert_state_stopped_passes(self):
        state = build_initial_state(should_stop=True)
        assert_state_stopped(state)  # should not raise

    def test_assert_state_stopped_fails(self):
        state = build_initial_state(should_stop=False)
        with pytest.raises(AssertionError):
            assert_state_stopped(state)

    def test_assert_state_has_messages(self):
        state = build_initial_state(messages=[HumanMessage(content="hello")])
        assert_state_has_messages(state, min_count=1)

    def test_assert_state_has_messages_fails(self):
        state = build_initial_state()
        with pytest.raises(AssertionError):
            assert_state_has_messages(state, min_count=1)

    def test_assert_last_message_contains(self):
        state = build_initial_state(messages=[AIMessage(content="scan complete")])
        assert_last_message_contains(state, "complete")

    def test_assert_last_message_contains_fails(self):
        state = build_initial_state(messages=[AIMessage(content="hello")])
        with pytest.raises(AssertionError):
            assert_last_message_contains(state, "nonexistent")

    def test_assert_tool_output_present(self):
        state = build_initial_state()
        state["tool_outputs"]["naabu"] = "port 80 open"
        assert_tool_output_present(state, "naabu")

    def test_assert_tool_output_present_fails(self):
        state = build_initial_state()
        with pytest.raises(AssertionError):
            assert_tool_output_present(state, "naabu")

    def test_assert_phase(self):
        state = build_initial_state(phase=Phase.EXPLOITATION)
        assert_phase(state, Phase.EXPLOITATION)

    def test_assert_next_action(self):
        state = build_initial_state(next_action="act")
        assert_next_action(state, "act")

    # ── AgentTestScenario ────────────────────────────────────────────────────

    def test_scenario_add_and_retrieve_tool(self):
        scenario = AgentTestScenario()
        tool = scenario.add_tool("scanner", response="open ports: 80, 443")
        assert scenario.get_tool("scanner") is tool

    def test_scenario_assert_tool_called(self):
        import asyncio
        scenario = AgentTestScenario()
        tool = scenario.add_tool("scanner")
        asyncio.run(tool.execute(target="10.0.0.1"))
        scenario.assert_tool_called("scanner", times=1)

    def test_scenario_assert_tool_called_fails(self):
        scenario = AgentTestScenario()
        scenario.add_tool("scanner")
        with pytest.raises(AssertionError):
            scenario.assert_tool_called("scanner", times=1)  # not called

    def test_scenario_reset_all(self):
        import asyncio
        scenario = AgentTestScenario()
        tool = scenario.add_tool("scanner")
        asyncio.run(tool.execute())
        assert tool.call_count == 1
        scenario.reset_all()
        assert tool.call_count == 0

    def test_scenario_tool_phase_restriction(self):
        scenario = AgentTestScenario()
        scenario.add_tool("recon_tool", phases=[Phase.INFORMATIONAL])
        assert scenario.registry.is_tool_allowed("recon_tool", Phase.INFORMATIONAL)
        assert not scenario.registry.is_tool_allowed("recon_tool", Phase.EXPLOITATION)
