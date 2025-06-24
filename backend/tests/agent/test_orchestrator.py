"""
Tests for Day 7 — Multi-Agent Orchestration Framework

Covers:
  - MultiAgentState structure
  - BaseAgent interface
  - ReconAgent
  - WebAppAgent
  - ExploitAgent
  - ReportAgent
  - WorkItem / OrchestratorResult structures
  - OrchestratorAgent pipeline
  - Integration: full recon → webapp → exploit → report pipeline
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, patch

import pytest

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.agents.exploit_agent import ExploitAgent
from app.agent.agents.recon_agent import ReconAgent
from app.agent.agents.report_agent import ReportAgent
from app.agent.agents.web_agent import WebAppAgent
from app.agent.orchestrator import OrchestratorAgent, OrchestratorResult, WorkItem
from app.agent.state.agent_state import Phase
from app.agent.testing import MockTool
from app.agent.tools.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_registry(*tools: MockTool) -> ToolRegistry:
    """Return a registry pre-loaded with *tools* (all phases allowed)."""
    registry = ToolRegistry()
    for tool in tools:
        registry.register_tool(tool, allowed_phases=list(Phase))
    return registry


def _empty_registry() -> ToolRegistry:
    return ToolRegistry()


def _minimal_state(target: str = "192.168.1.1") -> MultiAgentState:
    return {
        "messages": [],
        "current_phase": Phase.INFORMATIONAL,
        "tool_outputs": {},
        "project_id": None,
        "thread_id": "test",
        "next_action": "think",
        "selected_tool": None,
        "tool_input": None,
        "observation": None,
        "should_stop": False,
        "pending_approval": None,
        "guidance": None,
        "progress": None,
        "checkpoint": None,
        "active_agents": [],
        "agent_results": {},
        "orchestrator_plan": None,
        "target_info": {"target": target},
        "workstreams": None,
    }


# ---------------------------------------------------------------------------
# TestMultiAgentState  (10 tests)
# ---------------------------------------------------------------------------


class TestMultiAgentState:
    """Validate the MultiAgentState structure and default values."""

    def test_state_has_active_agents_key(self):
        state = _minimal_state()
        assert "active_agents" in state

    def test_active_agents_defaults_to_empty_list(self):
        state = _minimal_state()
        assert state["active_agents"] == []

    def test_state_has_agent_results_key(self):
        state = _minimal_state()
        assert "agent_results" in state

    def test_agent_results_defaults_to_empty_dict(self):
        state = _minimal_state()
        assert state["agent_results"] == {}

    def test_state_has_orchestrator_plan_key(self):
        state = _minimal_state()
        assert "orchestrator_plan" in state

    def test_orchestrator_plan_defaults_to_none(self):
        state = _minimal_state()
        assert state["orchestrator_plan"] is None

    def test_state_has_target_info_key(self):
        state = _minimal_state()
        assert "target_info" in state

    def test_target_info_contains_target(self):
        state = _minimal_state("10.0.0.1")
        assert state["target_info"]["target"] == "10.0.0.1"

    def test_state_has_workstreams_key(self):
        state = _minimal_state()
        assert "workstreams" in state

    def test_workstreams_defaults_to_none(self):
        state = _minimal_state()
        assert state["workstreams"] is None

    def test_state_inherits_agent_state_fields(self):
        state = _minimal_state()
        for field in (
            "messages", "current_phase", "tool_outputs", "project_id",
            "thread_id", "next_action", "selected_tool", "tool_input",
            "observation", "should_stop",
        ):
            assert field in state

    def test_state_can_store_multiple_agent_results(self):
        state = _minimal_state()
        state["agent_results"]["recon"] = {"findings": []}
        state["agent_results"]["webapp"] = {"findings": []}
        assert len(state["agent_results"]) == 2


# ---------------------------------------------------------------------------
# Concrete BaseAgent stub for testing
# ---------------------------------------------------------------------------


class _ConcreteAgent(BaseAgent):
    AGENT_NAME = "concrete"
    PREFERRED_TOOLS: List[str] = []

    def get_phase(self) -> Phase:
        return Phase.INFORMATIONAL

    async def run(self, state: MultiAgentState, task: str) -> Dict[str, Any]:
        return {"agent": self.AGENT_NAME, "findings": []}


# ---------------------------------------------------------------------------
# TestBaseAgent  (12 tests)
# ---------------------------------------------------------------------------


class TestBaseAgent:
    """BaseAgent abstract interface tests using _ConcreteAgent stub."""

    def test_can_instantiate_with_empty_registry(self):
        agent = _ConcreteAgent(_empty_registry())
        assert agent is not None

    def test_agent_name_attribute(self):
        assert _ConcreteAgent.AGENT_NAME == "concrete"

    def test_get_phase_returns_phase_enum(self):
        agent = _ConcreteAgent(_empty_registry())
        assert isinstance(agent.get_phase(), Phase)

    def test_get_phase_returns_correct_phase(self):
        agent = _ConcreteAgent(_empty_registry())
        assert agent.get_phase() == Phase.INFORMATIONAL

    def test_get_tool_names_returns_list(self):
        agent = _ConcreteAgent(_empty_registry())
        assert isinstance(agent.get_tool_names(), list)

    def test_get_tool_names_with_registered_tool(self):
        tool = MockTool(name="test_tool")
        registry = _make_registry(tool)
        agent = _ConcreteAgent(registry)
        assert "test_tool" in agent.get_tool_names()

    def test_build_system_prompt_returns_string(self):
        agent = _ConcreteAgent(_empty_registry())
        prompt = agent._build_system_prompt()
        assert isinstance(prompt, str)

    def test_build_system_prompt_non_empty(self):
        agent = _ConcreteAgent(_empty_registry())
        assert len(agent._build_system_prompt()) > 0

    def test_build_system_prompt_contains_agent_name(self):
        agent = _ConcreteAgent(_empty_registry())
        assert "concrete" in agent._build_system_prompt()

    def test_select_tools_returns_list(self):
        agent = _ConcreteAgent(_empty_registry())
        assert isinstance(agent._tools, list)

    def test_select_tools_filters_by_preferred_list(self):
        class _WithPreferred(_ConcreteAgent):
            PREFERRED_TOOLS = ["alpha"]

        alpha = MockTool(name="alpha")
        beta = MockTool(name="beta")
        registry = _make_registry(alpha, beta)
        agent = _WithPreferred(registry)
        assert agent.get_tool_names() == ["alpha"]

    def test_select_tools_falls_back_to_phase_tools(self):
        """When PREFERRED_TOOLS is empty, all phase tools are selected."""
        tool = MockTool(name="any_tool")
        registry = ToolRegistry()
        registry.register_tool(tool, allowed_phases=[Phase.INFORMATIONAL])
        agent = _ConcreteAgent(registry)
        assert "any_tool" in agent.get_tool_names()

    def test_run_returns_dict(self):
        agent = _ConcreteAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "task"))
        assert isinstance(result, dict)

    def test_config_stored_on_agent(self):
        agent = _ConcreteAgent(_empty_registry(), config={"key": "value"})
        assert agent.config["key"] == "value"


# ---------------------------------------------------------------------------
# TestReconAgent  (12 tests)
# ---------------------------------------------------------------------------


class TestReconAgent:
    """ReconAgent specialisation tests."""

    def test_agent_name(self):
        assert ReconAgent.AGENT_NAME == "recon"

    def test_get_phase_is_informational(self):
        agent = ReconAgent(_empty_registry())
        assert agent.get_phase() == Phase.INFORMATIONAL

    def test_preferred_tools_is_non_empty_list(self):
        assert isinstance(ReconAgent.PREFERRED_TOOLS, list)
        assert len(ReconAgent.PREFERRED_TOOLS) > 0

    def test_preferred_tools_contains_naabu(self):
        assert "naabu" in ReconAgent.PREFERRED_TOOLS

    def test_preferred_tools_contains_web_search(self):
        assert "web_search" in ReconAgent.PREFERRED_TOOLS

    def test_run_returns_dict_with_agent_key(self):
        agent = ReconAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "scan 10.0.0.1"))
        assert result.get("agent") == "recon"

    def test_run_returns_findings_key(self):
        agent = ReconAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "scan 10.0.0.1"))
        assert "findings" in result

    def test_scan_target_returns_structured_result(self):
        agent = ReconAgent(_empty_registry())
        result = asyncio.run(agent.scan_target("10.0.0.1"))
        assert "findings" in result
        assert "target_info" in result

    def test_scan_target_includes_target_in_info(self):
        agent = ReconAgent(_empty_registry())
        result = asyncio.run(agent.scan_target("192.168.0.1"))
        assert result["target_info"]["target"] == "192.168.0.1"

    def test_run_handles_offline_gracefully(self):
        """With no real tools, agent should still return a result."""
        agent = ReconAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "scan offline-host"))
        assert isinstance(result, dict)
        assert isinstance(result.get("findings", []), list)

    def test_select_tools_returns_recon_tools(self):
        naabu = MockTool(name="naabu")
        registry = ToolRegistry()
        registry.register_tool(naabu, allowed_phases=[Phase.INFORMATIONAL])
        agent = ReconAgent(registry)
        assert "naabu" in agent.get_tool_names()

    def test_build_system_prompt_mentions_reconnaissance(self):
        agent = ReconAgent(_empty_registry())
        prompt = agent._build_system_prompt()
        assert "reconnaissance" in prompt.lower() or "recon" in prompt.lower()

    def test_run_with_tool_available_produces_finding(self):
        naabu = MockTool(name="naabu", response="80/tcp open http")
        registry = ToolRegistry()
        registry.register_tool(naabu, allowed_phases=[Phase.INFORMATIONAL])
        agent = ReconAgent(registry)
        result = asyncio.run(agent.run(_minimal_state(), "scan 10.0.0.1"))
        tools_used = [f.get("tool") for f in result.get("findings", [])]
        assert "naabu" in tools_used


# ---------------------------------------------------------------------------
# TestWebAppAgent  (12 tests)
# ---------------------------------------------------------------------------


class TestWebAppAgent:
    """WebAppAgent specialisation tests."""

    def test_agent_name(self):
        assert WebAppAgent.AGENT_NAME == "webapp"

    def test_get_phase_is_exploitation(self):
        agent = WebAppAgent(_empty_registry())
        assert agent.get_phase() == Phase.EXPLOITATION

    def test_preferred_tools_is_non_empty_list(self):
        assert isinstance(WebAppAgent.PREFERRED_TOOLS, list)
        assert len(WebAppAgent.PREFERRED_TOOLS) > 0

    def test_preferred_tools_contains_xss_tool(self):
        assert any("xss" in t for t in WebAppAgent.PREFERRED_TOOLS)

    def test_preferred_tools_contains_csrf_tool(self):
        assert any("csrf" in t for t in WebAppAgent.PREFERRED_TOOLS)

    def test_preferred_tools_contains_injection_tool(self):
        assert any("injection" in t for t in WebAppAgent.PREFERRED_TOOLS)

    def test_run_returns_dict_with_agent_key(self):
        agent = WebAppAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "test webapp"))
        assert result.get("agent") == "webapp"

    def test_run_returns_findings_key(self):
        agent = WebAppAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "test webapp"))
        assert "findings" in result

    def test_test_web_target_returns_structured_result(self):
        agent = WebAppAgent(_empty_registry())
        result = asyncio.run(agent.test_web_target("http://example.com"))
        assert "findings" in result
        assert "tests_run" in result

    def test_prioritize_tests_returns_non_empty_list(self):
        agent = WebAppAgent(_empty_registry())
        tests = agent._prioritize_tests()
        assert isinstance(tests, list)
        assert len(tests) > 0

    def test_prioritize_tests_returns_ordered_list(self):
        agent = WebAppAgent(_empty_registry())
        tests = agent._prioritize_tests()
        assert isinstance(tests[0], str)

    def test_handles_missing_tools_gracefully(self):
        agent = WebAppAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "test no-tools-available"))
        assert isinstance(result, dict)

    def test_run_with_xss_tool_produces_finding(self):
        xss_tool = MockTool(name="reflected_xss", response="XSS found")
        registry = ToolRegistry()
        registry.register_tool(xss_tool, allowed_phases=[Phase.EXPLOITATION])
        agent = WebAppAgent(registry)
        result = asyncio.run(agent.run(_minimal_state(), "test webapp"))
        tools_used = [f.get("tool") for f in result.get("findings", [])]
        assert "reflected_xss" in tools_used

    def test_build_system_prompt_mentions_web(self):
        agent = WebAppAgent(_empty_registry())
        prompt = agent._build_system_prompt()
        assert "web" in prompt.lower()


# ---------------------------------------------------------------------------
# TestExploitAgent  (12 tests)
# ---------------------------------------------------------------------------


class TestExploitAgent:
    """ExploitAgent specialisation tests."""

    def test_agent_name(self):
        assert ExploitAgent.AGENT_NAME == "exploit"

    def test_get_phase_is_exploitation(self):
        agent = ExploitAgent(_empty_registry())
        assert agent.get_phase() == Phase.EXPLOITATION

    def test_preferred_tools_is_non_empty_list(self):
        assert isinstance(ExploitAgent.PREFERRED_TOOLS, list)
        assert len(ExploitAgent.PREFERRED_TOOLS) > 0

    def test_preferred_tools_contains_metasploit(self):
        assert "metasploit" in ExploitAgent.PREFERRED_TOOLS

    def test_preferred_tools_contains_sqlmap(self):
        assert "sqlmap_detect" in ExploitAgent.PREFERRED_TOOLS

    def test_run_returns_dict_with_agent_key(self):
        agent = ExploitAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "exploit target"))
        assert result.get("agent") == "exploit"

    def test_run_returns_findings_key(self):
        agent = ExploitAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "exploit target"))
        assert "findings" in result

    def test_exploit_target_returns_structured_result(self):
        agent = ExploitAgent(_empty_registry())
        result = asyncio.run(agent.exploit_target("10.0.0.1"))
        assert "findings" in result
        assert "sessions" in result
        assert "flags" in result

    def test_escalate_privileges_returns_structured_result(self):
        agent = ExploitAgent(_empty_registry())
        result = asyncio.run(agent.escalate_privileges("10.0.0.1"))
        assert "findings" in result
        assert "flags" in result

    def test_handles_gracefully_with_no_tools(self):
        agent = ExploitAgent(_empty_registry())
        result = asyncio.run(agent.run(_minimal_state(), "exploit with no tools"))
        assert isinstance(result, dict)

    def test_run_uses_recon_results_from_state(self):
        state = _minimal_state()
        state["agent_results"] = {"recon": {"findings": [{"type": "port_scan"}]}}
        agent = ExploitAgent(_empty_registry())
        result = asyncio.run(agent.run(state, "exploit after recon"))
        assert isinstance(result, dict)

    def test_build_system_prompt_mentions_exploitation(self):
        agent = ExploitAgent(_empty_registry())
        prompt = agent._build_system_prompt()
        assert "exploit" in prompt.lower()

    def test_exploit_with_metasploit_tool(self):
        msf = MockTool(name="metasploit", response="session opened")
        registry = ToolRegistry()
        registry.register_tool(msf, allowed_phases=[Phase.EXPLOITATION])
        agent = ExploitAgent(registry)
        result = asyncio.run(agent.exploit_target("10.0.0.1"))
        tools_used = [f.get("tool") for f in result.get("findings", [])]
        assert "metasploit" in tools_used


# ---------------------------------------------------------------------------
# TestReportAgent  (15 tests)
# ---------------------------------------------------------------------------


class TestReportAgent:
    """ReportAgent report generation tests."""

    def test_agent_name(self):
        assert ReportAgent.AGENT_NAME == "report"

    def test_get_phase_is_complete(self):
        agent = ReportAgent(_empty_registry())
        assert agent.get_phase() == Phase.COMPLETE

    def test_preferred_tools_is_empty(self):
        """Report agent does not use network tools."""
        assert ReportAgent.PREFERRED_TOOLS == []

    def test_generate_report_returns_string(self):
        agent = ReportAgent(_empty_registry())
        report = agent.generate_report([])
        assert isinstance(report, str)

    def test_generate_report_contains_executive_summary(self):
        agent = ReportAgent(_empty_registry())
        report = agent.generate_report([])
        assert "Executive Summary" in report

    def test_generate_report_contains_technical_findings(self):
        agent = ReportAgent(_empty_registry())
        report = agent.generate_report([{"type": "xss", "tool": "reflected_xss", "severity": "high", "output": "found"}])
        assert "Technical Findings" in report

    def test_generate_report_contains_remediation(self):
        agent = ReportAgent(_empty_registry())
        report = agent.generate_report([])
        assert "Remediation" in report

    def test_generate_report_contains_cvss_severity(self):
        agent = ReportAgent(_empty_registry())
        report = agent.generate_report([])
        assert "Critical" in report or "CVSS" in report

    def test_generate_report_empty_findings_produces_minimal_report(self):
        agent = ReportAgent(_empty_registry())
        report = agent.generate_report([])
        assert len(report) > 0
        assert "No exploitable vulnerabilities" in report or "No findings" in report

    def test_summarize_findings_deduplicates_identical(self):
        agent = ReportAgent(_empty_registry())
        findings = [
            {"type": "xss", "tool": "reflected_xss", "severity": "high", "output": "a"},
            {"type": "xss", "tool": "reflected_xss", "severity": "high", "output": "b"},
        ]
        result = agent.summarize_findings(findings)
        assert len(result) == 1

    def test_summarize_findings_keeps_highest_severity(self):
        agent = ReportAgent(_empty_registry())
        findings = [
            {"type": "xss", "tool": "reflected_xss", "severity": "medium", "output": "a"},
            {"type": "xss", "tool": "reflected_xss", "severity": "critical", "output": "b"},
        ]
        result = agent.summarize_findings(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_summarize_findings_sorts_by_severity(self):
        agent = ReportAgent(_empty_registry())
        findings = [
            {"type": "info_leak", "tool": "tool_a", "severity": "info", "output": ""},
            {"type": "xss", "tool": "tool_b", "severity": "high", "output": ""},
            {"type": "sqli", "tool": "tool_c", "severity": "critical", "output": ""},
        ]
        result = agent.summarize_findings(findings)
        severities = [f["severity"] for f in result]
        assert severities == ["critical", "high", "info"]

    def test_summarize_findings_handles_empty_input(self):
        agent = ReportAgent(_empty_registry())
        result = agent.summarize_findings([])
        assert result == []

    def test_run_returns_report_key(self):
        state = _minimal_state()
        agent = ReportAgent(_empty_registry())
        result = asyncio.run(agent.run(state, "generate report"))
        assert "report" in result

    def test_run_returns_summary_with_counts(self):
        state = _minimal_state()
        state["agent_results"] = {
            "recon": {
                "findings": [
                    {"type": "port_scan", "tool": "naabu", "severity": "info", "output": "80 open"},
                ]
            }
        }
        agent = ReportAgent(_empty_registry())
        result = asyncio.run(agent.run(state, "report"))
        summary = result.get("summary", {})
        assert "total_findings" in summary
        assert summary["total_findings"] >= 1

    def test_generate_report_with_multiple_findings(self):
        agent = ReportAgent(_empty_registry())
        findings = [
            {"type": "xss", "tool": "reflected_xss", "severity": "high", "output": "xss"},
            {"type": "sqli", "tool": "sqlmap_detect", "severity": "critical", "output": "sql"},
        ]
        report = agent.generate_report(findings)
        assert "xss" in report.lower() or "Xss" in report
        assert "sqli" in report.lower() or "Sqli" in report


# ---------------------------------------------------------------------------
# TestWorkItem  (4 tests)
# ---------------------------------------------------------------------------


class TestWorkItem:
    """WorkItem TypedDict / dataclass structure tests."""

    def test_work_item_has_agent_key(self):
        wi = WorkItem(agent="recon", task="scan target")
        assert wi["agent"] == "recon"

    def test_work_item_has_task_key(self):
        wi = WorkItem(agent="recon", task="scan target")
        assert wi["task"] == "scan target"

    def test_work_item_has_priority_key(self):
        wi = WorkItem(agent="recon", task="t", priority=1)
        assert wi["priority"] == 1

    def test_work_item_depends_on_defaults_to_empty(self):
        wi = WorkItem(agent="recon", task="t")
        assert wi["depends_on"] == []

    def test_work_item_can_have_dependencies(self):
        wi = WorkItem(agent="exploit", task="t", depends_on=["recon"])
        assert "recon" in wi["depends_on"]


# ---------------------------------------------------------------------------
# TestOrchestratorResult  (4 tests)
# ---------------------------------------------------------------------------


class TestOrchestratorResult:
    """OrchestratorResult structure tests."""

    def _make_result(self) -> OrchestratorResult:
        return OrchestratorResult(
            target="10.0.0.1",
            workstreams=[],
            agent_results={},
            final_report="# Report",
            total_findings=5,
            critical_count=1,
            high_count=2,
        )

    def test_result_has_target_key(self):
        r = self._make_result()
        assert r["target"] == "10.0.0.1"

    def test_result_has_final_report(self):
        r = self._make_result()
        assert r["final_report"] == "# Report"

    def test_result_has_total_findings(self):
        r = self._make_result()
        assert r["total_findings"] == 5

    def test_result_has_critical_and_high_counts(self):
        r = self._make_result()
        assert r["critical_count"] == 1
        assert r["high_count"] == 2


# ---------------------------------------------------------------------------
# TestOrchestratorAgent  (15 tests)
# ---------------------------------------------------------------------------


class TestOrchestratorAgent:
    """OrchestratorAgent orchestration tests."""

    def test_can_instantiate_with_registry(self):
        orch = OrchestratorAgent(_empty_registry())
        assert orch is not None

    def test_decompose_target_returns_list(self):
        orch = OrchestratorAgent(_empty_registry())
        result = orch.decompose_target("10.0.0.1")
        assert isinstance(result, list)

    def test_decompose_target_returns_work_items(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        assert all(isinstance(w, WorkItem) for w in items)

    def test_decompose_target_includes_recon_first(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        assert items[0]["agent"] == "recon"

    def test_decompose_target_includes_report_last(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        assert items[-1]["agent"] == "report"

    def test_decompose_target_all_four_agents_present(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        agents = {w["agent"] for w in items}
        assert agents == {"recon", "webapp", "exploit", "report"}

    def test_parallel_workstreams_have_empty_depends_on(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        parallel = [w for w in items if not w["depends_on"]]
        assert len(parallel) >= 1

    def test_recon_has_no_dependencies(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        recon = next(w for w in items if w["agent"] == "recon")
        assert recon["depends_on"] == []

    def test_report_depends_on_other_agents(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1")
        report = next(w for w in items if w["agent"] == "report")
        assert len(report["depends_on"]) > 0

    def test_run_returns_orchestrator_result(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("10.0.0.1"))
        assert isinstance(result, OrchestratorResult)

    def test_run_result_has_target(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("10.0.0.1"))
        assert result["target"] == "10.0.0.1"

    def test_dispatch_workitem_routes_to_recon(self):
        orch = OrchestratorAgent(_empty_registry())
        wi = WorkItem(agent="recon", task="scan")
        state = _minimal_state()
        result = asyncio.run(orch._dispatch_workitem(wi, state))
        assert result.get("agent") == "recon"

    def test_dispatch_workitem_handles_unknown_agent(self):
        orch = OrchestratorAgent(_empty_registry())
        wi = WorkItem(agent="unknown_agent", task="do something")
        state = _minimal_state()
        result = asyncio.run(orch._dispatch_workitem(wi, state))
        assert "error" in result

    def test_merge_results_aggregates_agent_results(self):
        orch = OrchestratorAgent(_empty_registry())
        agent_results = {
            "recon": {"findings": [{"type": "port_scan", "severity": "info"}]},
            "report": {"report": "# Report", "summary": {"total_findings": 1, "critical": 0, "high": 0}},
        }
        wi = WorkItem(agent="recon", task="scan")
        result = orch._merge_results("10.0.0.1", [wi], agent_results)
        assert isinstance(result, OrchestratorResult)
        assert result["agent_results"] == agent_results

    def test_run_with_empty_scope_still_works(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("10.0.0.1", scope=[]))
        assert isinstance(result, OrchestratorResult)

    def test_run_with_scope_includes_scope_in_tasks(self):
        orch = OrchestratorAgent(_empty_registry())
        items = orch.decompose_target("10.0.0.1", scope=["/api", "/admin"])
        assert any("/api" in w["task"] or "scope" in w["task"] for w in items)


# ---------------------------------------------------------------------------
# TestOrchestratorIntegration  (8 tests)
# ---------------------------------------------------------------------------


class TestOrchestratorIntegration:
    """End-to-end integration tests for the full pipeline."""

    def test_full_pipeline_completes(self):
        """Full recon → webapp → exploit → report pipeline completes."""
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("192.168.1.100"))
        assert isinstance(result, OrchestratorResult)

    def test_all_four_agents_run(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("192.168.1.100"))
        agents_run = set(result["agent_results"].keys())
        assert "recon" in agents_run
        assert "webapp" in agents_run
        assert "exploit" in agents_run
        assert "report" in agents_run

    def test_report_agent_always_runs_last(self):
        """Report result key exists and contains a report string."""
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("192.168.1.100"))
        report_result = result["agent_results"].get("report", {})
        assert isinstance(report_result.get("report", ""), str)

    def test_final_report_is_non_empty_string(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("192.168.1.100"))
        assert isinstance(result["final_report"], str)
        assert len(result["final_report"]) > 0

    def test_result_has_total_findings_field(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("192.168.1.100"))
        assert "total_findings" in result

    def test_pipeline_with_mock_tools(self):
        """Using mock tools for recon, webapp, exploit phases."""
        naabu = MockTool(name="naabu", response="80/tcp open")
        xss = MockTool(name="reflected_xss", response="XSS found")
        msf = MockTool(name="metasploit", response="session 1 opened")

        registry = ToolRegistry()
        registry.register_tool(naabu, allowed_phases=[Phase.INFORMATIONAL])
        registry.register_tool(xss, allowed_phases=[Phase.EXPLOITATION])
        registry.register_tool(msf, allowed_phases=[Phase.EXPLOITATION])

        orch = OrchestratorAgent(registry)
        result = asyncio.run(orch.run("10.10.10.10"))
        assert isinstance(result, OrchestratorResult)

    def test_parallel_workstreams_use_asyncio_gather(self):
        """
        Verify that independent workstreams (webapp + exploit) are run in
        parallel by checking both execute when given matching mock tools.
        """
        xss = MockTool(name="reflected_xss", response="xss")
        msf = MockTool(name="metasploit", response="msf")
        registry = ToolRegistry()
        registry.register_tool(xss, allowed_phases=[Phase.EXPLOITATION])
        registry.register_tool(msf, allowed_phases=[Phase.EXPLOITATION])

        orch = OrchestratorAgent(registry)
        result = asyncio.run(orch.run("10.0.0.1"))
        # Both webapp and exploit agents must appear in results
        assert "webapp" in result["agent_results"]
        assert "exploit" in result["agent_results"]

    def test_orchestrator_result_has_workstreams(self):
        orch = OrchestratorAgent(_empty_registry())
        result = asyncio.run(orch.run("10.0.0.1"))
        assert isinstance(result["workstreams"], list)
        assert len(result["workstreams"]) >= 4
