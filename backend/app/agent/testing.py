"""
Agent Testing Framework.

Provides utilities, mock LLM, and scenario helpers for testing the AI agent
without live LLM API calls.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from langchain_core.messages import BaseMessage

from app.agent.state.agent_state import AgentState, Phase
from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Mock LLM
# ---------------------------------------------------------------------------


class MockLLM:
    """
    Deterministic mock LLM for agent unit tests.

    Accepts a list of *responses* (strings in THOUGHT/ACTION/TOOL_INPUT format
    or plain text) and returns them in order, cycling through when exhausted.

    Usage::

        mock = MockLLM(["THOUGHT: scan\\nACTION: respond\\nTOOL_INPUT: done"])
        response = await mock.ainvoke(messages)
        assert response.content == "..."
    """

    class FakeResponse:
        """Mimics a LangChain AIMessage returned by a real LLM."""
        def __init__(self, content: str):
            self.content = content

    def __init__(self, responses: Optional[List[str]] = None):
        self.responses = responses or [
            "THOUGHT: I have enough information.\nACTION: respond\nTOOL_INPUT: Analysis complete."
        ]
        self._call_count = 0

    async def ainvoke(self, messages: Any, **kwargs: Any) -> "MockLLM.FakeResponse":
        """Return the next pre-canned response (cycling if needed)."""
        idx = self._call_count % len(self.responses)
        self._call_count += 1
        return self.FakeResponse(self.responses[idx])

    def reset(self) -> None:
        """Reset call counter."""
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def build_tool_response(
        self,
        thought: str,
        tool_name: str,
        tool_input: Dict[str, Any],
    ) -> str:
        """Helper to build a well-formed THOUGHT/ACTION/TOOL_INPUT string."""
        return (
            f"THOUGHT: {thought}\n"
            f"ACTION: {tool_name}\n"
            f"TOOL_INPUT: {json.dumps(tool_input)}"
        )


# ---------------------------------------------------------------------------
# Mock Tool
# ---------------------------------------------------------------------------


class MockTool(BaseTool):
    """
    Configurable mock tool for testing.

    Returns a preset *response* and records every call.
    """

    def __init__(
        self,
        name: str = "mock_tool",
        description: str = "A mock tool for testing",
        response: str = "mock tool output",
        should_fail: bool = False,
        fail_message: str = "mock tool error",
    ):
        self._name = name
        self._description = description
        self.response = response
        self.should_fail = should_fail
        self.fail_message = fail_message
        self.calls: List[Dict[str, Any]] = []
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self._name,
            description=self._description,
            parameters={"input": {"type": "string", "description": "Input value"}},
        )

    async def execute(self, **kwargs: Any) -> str:
        self.calls.append(kwargs)
        if self.should_fail:
            raise RuntimeError(self.fail_message)
        return self.response

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def reset(self) -> None:
        self.calls.clear()


# ---------------------------------------------------------------------------
# State builder helpers
# ---------------------------------------------------------------------------


def build_initial_state(
    thread_id: str = "test-thread",
    project_id: Optional[str] = "test-project",
    phase: Phase = Phase.INFORMATIONAL,
    messages: Optional[List[BaseMessage]] = None,
    **overrides: Any,
) -> AgentState:
    """
    Build a minimal but valid AgentState for testing.

    Args:
        thread_id: Conversation thread identifier
        project_id: Optional project context
        phase: Starting operational phase
        messages: Pre-populated messages (empty list by default)
        **overrides: Any AgentState fields to override

    Returns:
        AgentState TypedDict
    """
    base: AgentState = {
        "messages": messages or [],
        "current_phase": phase,
        "tool_outputs": {},
        "project_id": project_id,
        "thread_id": thread_id,
        "next_action": "think",
        "selected_tool": None,
        "tool_input": None,
        "observation": None,
        "should_stop": False,
        "pending_approval": None,
        "guidance": None,
        "progress": None,
        "checkpoint": None,
    }
    base.update(overrides)
    return base


def build_state_with_observation(
    observation: str,
    thread_id: str = "test-thread",
    phase: Phase = Phase.INFORMATIONAL,
) -> AgentState:
    """Build a state where a previous tool has produced *observation*."""
    return build_initial_state(
        thread_id=thread_id,
        phase=phase,
        next_action="observe",
        observation=observation,
    )


def build_state_pending_approval(
    tool_name: str,
    thread_id: str = "test-thread",
) -> AgentState:
    """Build a state where an operation is awaiting human approval."""
    return build_initial_state(
        thread_id=thread_id,
        next_action="approval",
        pending_approval={
            "tool": tool_name,
            "reason": f"Approval required for {tool_name}",
            "status": "pending",
        },
    )


# ---------------------------------------------------------------------------
# Test scenario helpers
# ---------------------------------------------------------------------------


class AgentTestScenario:
    """
    Helper for setting up a repeatable agent test scenario.

    Manages a mock tool registry and provides factory methods for
    common test situations.
    """

    def __init__(self):
        self.registry = ToolRegistry()
        self._tools: Dict[str, MockTool] = {}

    def add_tool(
        self,
        name: str = "mock_tool",
        description: str = "Test tool",
        response: str = "tool output",
        phases: Optional[List[Phase]] = None,
        should_fail: bool = False,
    ) -> MockTool:
        """Register a mock tool and return it for assertions."""
        tool = MockTool(
            name=name,
            description=description,
            response=response,
            should_fail=should_fail,
        )
        self.registry.register_tool(
            tool, allowed_phases=phases or list(Phase)
        )
        self._tools[name] = tool
        return tool

    def get_tool(self, name: str) -> Optional[MockTool]:
        """Retrieve a previously added MockTool by name."""
        return self._tools.get(name)

    def assert_tool_called(self, tool_name: str, times: int = 1) -> None:
        """Assert that *tool_name* was called exactly *times* times."""
        tool = self._tools.get(tool_name)
        assert tool is not None, f"Tool '{tool_name}' not found in scenario"
        assert tool.call_count == times, (
            f"Expected tool '{tool_name}' to be called {times} times, "
            f"but it was called {tool.call_count} times"
        )

    def reset_all(self) -> None:
        """Reset call counters on all mock tools."""
        for tool in self._tools.values():
            tool.reset()


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def assert_state_stopped(state: AgentState) -> None:
    """Assert the agent has set should_stop = True."""
    assert state.get("should_stop") is True, (
        f"Expected should_stop=True, got {state.get('should_stop')}"
    )


def assert_state_has_messages(state: AgentState, min_count: int = 1) -> None:
    """Assert the state contains at least *min_count* messages."""
    count = len(state.get("messages", []))
    assert count >= min_count, (
        f"Expected at least {min_count} message(s), found {count}"
    )


def assert_last_message_contains(state: AgentState, text: str) -> None:
    """Assert the last message's content contains *text*."""
    messages = state.get("messages", [])
    assert messages, "State has no messages"
    last = messages[-1]
    content = last.content if hasattr(last, "content") else str(last)
    assert text in content, (
        f"Expected last message to contain '{text}', got: {content!r}"
    )


def assert_tool_output_present(state: AgentState, tool_name: str) -> None:
    """Assert that *tool_name* output exists in state.tool_outputs."""
    outputs = state.get("tool_outputs", {})
    assert tool_name in outputs, (
        f"Expected tool_outputs to contain '{tool_name}', "
        f"found keys: {list(outputs.keys())}"
    )


def assert_phase(state: AgentState, expected_phase: Phase) -> None:
    """Assert the current phase matches *expected_phase*."""
    actual = state.get("current_phase")
    assert actual == expected_phase, (
        f"Expected phase {expected_phase.value}, got {actual}"
    )


def assert_next_action(state: AgentState, expected_action: str) -> None:
    """Assert next_action equals *expected_action*."""
    actual = state.get("next_action")
    assert actual == expected_action, (
        f"Expected next_action='{expected_action}', got '{actual}'"
    )
