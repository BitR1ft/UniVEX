"""
Tests for Day 3 GAP_COVERAGE_PLAN — 8 New Specialised Agent Roles

Covers all 8 new agents:
  - RefinerAgent
  - GeneratorAgent
  - AdviserAgent
  - ReflectorAgent
  - EnricherAgent
  - CoderAgent
  - InstallerAgent
  - SimpleJSONAgent

And orchestrator helper methods:
  - enrich_findings()
  - reflect_on_session()
  - generate_payload()
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.agents.adviser_agent import AdviserAgent, ConsultationType
from app.agent.agents.coder_agent import CoderAgent, CodeType, Language
from app.agent.agents.enricher_agent import EnricherAgent
from app.agent.agents.generator_agent import GeneratorAgent, GenerationType
from app.agent.agents.installer_agent import InstallerAgent, OSType, ToolStatus
from app.agent.agents.refiner_agent import RefinerAgent
from app.agent.agents.reflector_agent import ReflectorAgent
from app.agent.agents.simple_json_agent import SchemaType, SimpleJSONAgent
from app.agent.orchestrator import OrchestratorAgent
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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


def _state_with_findings(findings: List[Dict[str, Any]]) -> MultiAgentState:
    state = _minimal_state()
    state["agent_results"] = {"recon": {"findings": findings}}
    return state


SAMPLE_FINDINGS = [
    {"type": "sqli", "severity": "critical", "tool": "sqlmap", "output": "SQL injection found"},
    {"type": "xss", "severity": "high", "tool": "nuclei", "output": "Reflected XSS"},
    {"type": "port_scan", "severity": "info", "tool": "nmap", "output": "Port 22 open"},
]


# ===========================================================================
# TestRefinerAgent  (12 tests)
# ===========================================================================


class TestRefinerAgent:
    """Tests for RefinerAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = RefinerAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert RefinerAgent.AGENT_NAME == "refiner"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.COMPLETE

    def test_preferred_tools(self):
        assert "web_search" in RefinerAgent.PREFERRED_TOOLS
        assert "query_graph" in RefinerAgent.PREFERRED_TOOLS

    def test_quality_threshold(self):
        assert RefinerAgent.quality_threshold == 0.8

    def test_build_system_prompt_contains_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "refin" in prompt.lower() or "quality" in prompt.lower()
        assert "penetration" in prompt.lower() or "security" in prompt.lower()

    def test_score_quality_empty_string(self):
        score = self.agent._score_quality("")
        assert score == 0.0

    def test_score_quality_short_text(self):
        score = self.agent._score_quality("hello world")
        assert 0.0 <= score < 0.5

    def test_score_quality_rich_text(self):
        rich = (
            "## Findings\n\n"
            "- **SQL Injection** (Critical): vulnerability found in login form.\n"
            "  - Recommendation: use parameterised queries.\n"
            "  - Impact: data exfiltration risk.\n"
            "  - CVE: CVE-2021-44228\n"
            "  - Severity: critical\n"
            "  - remediation: patch the application\n"
            "  - exploit: confirmed via sqlmap\n"
            "  - finding: confirmed\n"
            "  - target: 10.0.0.1\n\n"
            "```sql\nSELECT * FROM users WHERE id=1 OR 1=1\n```\n\n"
            "1. Apply patch immediately\n"
            "2. Review all input handling\n"
        )
        score = self.agent._score_quality(rich)
        assert score >= 0.4

    def test_identify_issues_short_text(self):
        issues = self.agent._identify_issues("too short")
        assert any("short" in i.lower() or "detail" in i.lower() for i in issues)

    def test_refine_once_adds_header(self):
        text = "Some findings were identified during testing."
        issues = ["Missing section headings; add structured headers."]
        refined = self.agent._refine_once(text, issues)
        assert "#" in refined

    def test_run_returns_expected_keys(self):
        state = _minimal_state()
        result = asyncio.run(self.agent.run(state, "Sample output to refine."))
        assert result["agent"] == "refiner"
        assert "refined_output" in result
        assert "quality_score" in result
        assert "iterations" in result
        assert "issues" in result
        assert isinstance(result["quality_score"], float)


# ===========================================================================
# TestGeneratorAgent  (14 tests)
# ===========================================================================


class TestGeneratorAgent:
    """Tests for GeneratorAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = GeneratorAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert GeneratorAgent.AGENT_NAME == "generator"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.EXPLOITATION

    def test_preferred_tools(self):
        assert "web_search" in GeneratorAgent.PREFERRED_TOOLS
        assert "searchsploit" in GeneratorAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "generat" in prompt.lower()
        assert "payload" in prompt.lower() or "exploit" in prompt.lower()

    def test_generation_type_enum_values(self):
        assert GenerationType.PAYLOAD.value == "payload"
        assert GenerationType.WORDLIST.value == "wordlist"
        assert GenerationType.REVERSE_SHELL.value == "reverse_shell"
        assert GenerationType.POC_CODE.value == "poc_code"

    def test_generate_payload_xss(self):
        result = self.agent.generate_payload("xss", {"url": "http://target.com"})
        assert "payload" in result
        assert result["type"] == "xss"
        assert "<script" in result["payload"] or "onerror" in result["payload"]

    def test_generate_payload_sqli(self):
        result = self.agent.generate_payload("sqli", {})
        assert "OR" in result["payload"] or "UNION" in result["payload"] or "DROP" in result["payload"]

    def test_generate_payload_unknown_type(self):
        result = self.agent.generate_payload("unknown_type", {})
        assert "payload" in result

    def test_generate_wordlist_returns_list(self):
        wordlist = self.agent.generate_wordlist("dirs", 20, [])
        assert isinstance(wordlist, list)
        assert len(wordlist) <= 20
        assert "admin" in wordlist

    def test_generate_wordlist_with_custom_patterns(self):
        wordlist = self.agent.generate_wordlist("general", 50, ["custom_entry"])
        assert "custom_entry" in wordlist

    def test_generate_poc_returns_python_code(self):
        poc = self.agent.generate_poc("CVE-2021-44228", "rce", {"target": "192.168.1.1"})
        assert "python" in poc.lower() or "import" in poc or "def " in poc
        assert "CVE-2021-44228" in poc

    def test_generate_reverse_shell_bash(self):
        shell = self.agent.generate_reverse_shell("linux", "10.10.10.10", 4444, "bash")
        assert "10.10.10.10" in shell
        assert "4444" in shell

    def test_run_returns_expected_keys(self):
        state = _minimal_state()
        result = asyncio.run(self.agent.run(state, "Generate XSS payload"))
        assert result["agent"] == "generator"
        assert "generation_type" in result
        assert "content" in result
        assert "usage" in result


# ===========================================================================
# TestAdviserAgent  (12 tests)
# ===========================================================================


class TestAdviserAgent:
    """Tests for AdviserAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = AdviserAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert AdviserAgent.AGENT_NAME == "adviser"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.COMPLETE

    def test_preferred_tools(self):
        assert "web_search" in AdviserAgent.PREFERRED_TOOLS
        assert "query_graph" in AdviserAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "advis" in prompt.lower() or "consult" in prompt.lower() or "expert" in prompt.lower()

    def test_consultation_type_enum_values(self):
        assert ConsultationType.RISK_ASSESSMENT.value == "risk_assessment"
        assert ConsultationType.REMEDIATION.value == "remediation"
        assert ConsultationType.EXPLOIT_SELECTION.value == "exploit_selection"

    def test_assess_risk_with_findings(self):
        result = self.agent.assess_risk({"findings": SAMPLE_FINDINGS})
        assert "risk_score" in result
        assert "likelihood" in result
        assert "impact" in result
        assert "recommendations" in result
        assert isinstance(result["risk_score"], float)
        assert result["risk_score"] >= 0.0

    def test_assess_risk_empty_findings(self):
        result = self.agent.assess_risk({"findings": []})
        assert result["risk_score"] == 0.0

    def test_suggest_remediation_sqli(self):
        result = self.agent.suggest_remediation("sqli", {})
        assert "steps" in result
        assert len(result["steps"]) > 0
        assert result["priority"] == "Critical"

    def test_suggest_remediation_unknown(self):
        result = self.agent.suggest_remediation("unknown_vuln", {})
        assert "steps" in result
        assert "priority" in result

    def test_select_exploit_no_exploits(self):
        result = self.agent.select_exploit({}, [])
        assert result["selected"] is None

    def test_run_returns_expected_keys(self):
        state = _state_with_findings(SAMPLE_FINDINGS)
        result = asyncio.run(self.agent.run(state, "Assess risk"))
        assert result["agent"] == "adviser"
        assert "consultation_type" in result
        assert "advice" in result


# ===========================================================================
# TestReflectorAgent  (12 tests)
# ===========================================================================


class TestReflectorAgent:
    """Tests for ReflectorAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = ReflectorAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert ReflectorAgent.AGENT_NAME == "reflector"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.COMPLETE

    def test_preferred_tools(self):
        assert "query_graph" in ReflectorAgent.PREFERRED_TOOLS
        assert "web_search" in ReflectorAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "reflect" in prompt.lower() or "coverage" in prompt.lower()

    def test_reflect_on_findings_with_data(self):
        result = self.agent.reflect_on_findings(SAMPLE_FINDINGS)
        assert result["total"] == len(SAMPLE_FINDINGS)
        assert "severity_breakdown" in result
        assert "attack_patterns" in result
        assert "key_observations" in result

    def test_reflect_on_findings_empty(self):
        result = self.agent.reflect_on_findings([])
        assert result["total"] == 0

    def test_identify_missed_surfaces_no_agents(self):
        missed = self.agent.identify_missed_surfaces({}, [])
        assert isinstance(missed, list)
        assert len(missed) > 0

    def test_identify_missed_surfaces_all_agents(self):
        completed = ["recon", "webapp", "exploit", "report"]
        missed = self.agent.identify_missed_surfaces({}, completed)
        assert isinstance(missed, list)

    def test_suggest_next_steps_returns_list(self):
        steps = self.agent.suggest_next_steps(
            {"findings": SAMPLE_FINDINGS, "completed": ["recon"], "target_info": {}}
        )
        assert isinstance(steps, list)
        assert len(steps) > 0
        assert "step" in steps[0]
        assert "priority" in steps[0]

    def test_analyze_coverage_empty(self):
        score = self.agent._analyze_coverage([], [])
        assert score == 1.0

    def test_run_returns_expected_keys(self):
        state = _state_with_findings(SAMPLE_FINDINGS)
        result = asyncio.run(self.agent.run(state, "Reflect on engagement"))
        assert result["agent"] == "reflector"
        assert "reflections" in result
        assert "coverage_score" in result
        assert "missed_surfaces" in result
        assert "next_steps" in result


# ===========================================================================
# TestEnricherAgent  (14 tests)
# ===========================================================================


class TestEnricherAgent:
    """Tests for EnricherAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = EnricherAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert EnricherAgent.AGENT_NAME == "enricher"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.COMPLETE

    def test_preferred_tools(self):
        assert "web_search" in EnricherAgent.PREFERRED_TOOLS
        assert "searchsploit" in EnricherAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "enrich" in prompt.lower() or "cve" in prompt.lower() or "owasp" in prompt.lower()

    def test_owasp_mapping_contains_sqli(self):
        assert "sqli" in EnricherAgent.OWASP_MAPPING
        assert "A03" in EnricherAgent.OWASP_MAPPING["sqli"]

    def test_cvss_base_scores_contain_critical(self):
        assert "critical" in EnricherAgent.CVSS_BASE_SCORES
        assert EnricherAgent.CVSS_BASE_SCORES["critical"] >= 9.0

    def test_enrich_finding_adds_fields(self):
        finding = {"type": "sqli", "severity": "critical", "tool": "sqlmap", "output": "found"}
        enriched = self.agent.enrich_finding(finding)
        assert "cve_references" in enriched
        assert "owasp_mapping" in enriched
        assert "cvss_score" in enriched
        assert "cwe_id" in enriched
        assert "remediation" in enriched

    def test_map_to_owasp_sqli(self):
        result = self.agent._map_to_owasp("sqli")
        assert "A03" in result

    def test_map_to_owasp_xss(self):
        result = self.agent._map_to_owasp("xss")
        assert "A03" in result

    def test_map_to_owasp_unknown(self):
        result = self.agent._map_to_owasp("totally_unknown_vuln_type")
        assert "A05" in result  # Default

    def test_calculate_cvss_critical(self):
        score = self.agent._calculate_cvss("critical", "network", "none", "none")
        assert score >= 9.0

    def test_calculate_cvss_low(self):
        score = self.agent._calculate_cvss("low", "local", "high", "required")
        assert score >= 0.0

    def test_lookup_cve_log4j(self):
        cves = self.agent._lookup_cve("log4j", "log4j remote code execution")
        assert "CVE-2021-44228" in cves

    def test_run_returns_expected_keys(self):
        state = _state_with_findings(SAMPLE_FINDINGS)
        result = asyncio.run(self.agent.run(state, "Enrich findings"))
        assert result["agent"] == "enricher"
        assert "enriched_findings" in result
        assert "total_enriched" in result
        assert result["total_enriched"] == len(SAMPLE_FINDINGS)


# ===========================================================================
# TestCoderAgent  (14 tests)
# ===========================================================================


class TestCoderAgent:
    """Tests for CoderAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = CoderAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert CoderAgent.AGENT_NAME == "coder"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.EXPLOITATION

    def test_preferred_tools(self):
        assert "web_search" in CoderAgent.PREFERRED_TOOLS
        assert "searchsploit" in CoderAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "code" in prompt.lower() or "exploit" in prompt.lower() or "generat" in prompt.lower()

    def test_code_type_enum_values(self):
        assert CodeType.EXPLOIT.value == "exploit"
        assert CodeType.REVERSE_SHELL.value == "reverse_shell"
        assert CodeType.PAYLOAD.value == "payload"

    def test_language_enum_values(self):
        assert Language.PYTHON.value == "python"
        assert Language.BASH.value == "bash"
        assert Language.POWERSHELL.value == "powershell"

    def test_reverse_shell_templates_exist(self):
        assert "bash" in CoderAgent.REVERSE_SHELL_TEMPLATES
        assert "python" in CoderAgent.REVERSE_SHELL_TEMPLATES
        assert "powershell" in CoderAgent.REVERSE_SHELL_TEMPLATES

    def test_generate_exploit_python(self):
        result = self.agent.generate_exploit("sqli", {"target": "http://example.com"}, Language.PYTHON)
        assert "code" in result
        assert "language" in result
        assert result["language"] == "python"
        assert "def " in result["code"] or "import" in result["code"]

    def test_generate_reverse_shell_bash(self):
        result = self.agent.generate_reverse_shell("linux", "10.10.10.10", 4444, Language.BASH)
        assert "10.10.10.10" in result["code"]
        assert "4444" in result["code"]
        assert result["language"] == "bash"

    def test_analyze_code_detects_dangerous_python(self):
        code = "import os\nos.system('id')\neval('dangerous')"
        result = self.agent.analyze_code(code, Language.PYTHON)
        assert "vulnerabilities" in result
        assert result["risk_level"] in ("High", "Critical")

    def test_analyze_code_safe_code(self):
        code = "def hello():\n    print('hello world')\n"
        result = self.agent.analyze_code(code, Language.PYTHON)
        assert result["risk_level"] == "Low"

    def test_obfuscate_payload_base64(self):
        result = self.agent.obfuscate_payload("id", "base64")
        assert "base64" in result

    def test_run_returns_expected_keys(self):
        state = _minimal_state()
        result = asyncio.run(self.agent.run(state, "Generate reverse shell"))
        assert result["agent"] == "coder"
        assert "code_type" in result
        assert "code" in result
        assert "language" in result


# ===========================================================================
# TestInstallerAgent  (12 tests)
# ===========================================================================


class TestInstallerAgent:
    """Tests for InstallerAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = InstallerAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert InstallerAgent.AGENT_NAME == "installer"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.INFORMATIONAL

    def test_preferred_tools(self):
        assert "web_search" in InstallerAgent.PREFERRED_TOOLS
        assert "query_graph" in InstallerAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "install" in prompt.lower() or "tool" in prompt.lower()

    def test_os_type_enum_values(self):
        assert OSType.KALI.value == "kali"
        assert OSType.UBUNTU.value == "ubuntu"
        assert OSType.WINDOWS.value == "windows"

    def test_tool_status_enum_values(self):
        assert ToolStatus.INSTALLED.value == "installed"
        assert ToolStatus.NOT_INSTALLED.value == "not_installed"

    def test_tool_registry_contains_nmap(self):
        assert "nmap" in InstallerAgent.TOOL_REGISTRY

    def test_check_tool_returns_dict(self):
        result = self.agent.check_tool("nmap")
        assert "status" in result
        assert "path" in result
        assert "version" in result
        assert "tool" in result

    def test_get_installation_guide_nmap_kali(self):
        guide = self.agent.get_installation_guide("nmap", OSType.KALI)
        assert "tool" in guide
        assert guide["tool"] == "nmap"
        assert "commands" in guide
        assert "apt" in guide["commands"][0].lower()

    def test_resolve_dependencies_go_tools(self):
        result = self.agent.resolve_dependencies(["naabu", "nuclei"])
        assert "install_order" in result
        assert "go" in result["install_order"]

    def test_run_returns_expected_keys(self):
        state = _minimal_state()
        result = asyncio.run(self.agent.run(state, "Check nmap and sqlmap"))
        assert result["agent"] == "installer"
        assert "tool_statuses" in result
        assert "installation_guides" in result
        assert "recommendations" in result


# ===========================================================================
# TestSimpleJSONAgent  (12 tests)
# ===========================================================================


class TestSimpleJSONAgent:
    """Tests for SimpleJSONAgent."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.agent = SimpleJSONAgent(self.registry)

    def test_instantiation(self):
        assert self.agent is not None

    def test_agent_name(self):
        assert SimpleJSONAgent.AGENT_NAME == "simple_json"

    def test_get_phase(self):
        assert self.agent.get_phase() == Phase.INFORMATIONAL

    def test_preferred_tools(self):
        assert "web_search" in SimpleJSONAgent.PREFERRED_TOOLS
        assert "query_graph" in SimpleJSONAgent.PREFERRED_TOOLS

    def test_build_system_prompt_keywords(self):
        prompt = self.agent._build_system_prompt()
        assert "json" in prompt.lower() or "schema" in prompt.lower()

    def test_schema_type_enum_values(self):
        assert SchemaType.FINDING.value == "finding"
        assert SchemaType.TARGET_INFO.value == "target_info"
        assert SchemaType.SCAN_RESULT.value == "scan_result"

    def test_predefined_schemas_contain_finding(self):
        assert "finding" in SimpleJSONAgent.PREDEFINED_SCHEMAS
        schema = SimpleJSONAgent.PREDEFINED_SCHEMAS["finding"]
        assert "required" in schema
        assert "type" in schema["required"]

    def test_extract_json_from_raw_json(self):
        text = '{"type": "xss", "severity": "high"}'
        schema = SimpleJSONAgent.PREDEFINED_SCHEMAS["finding"]
        result = self.agent.extract_json(text, schema)
        assert result.get("type") == "xss"

    def test_extract_json_from_code_block(self):
        text = '```json\n{"type": "sqli", "severity": "critical"}\n```'
        schema = SimpleJSONAgent.PREDEFINED_SCHEMAS["finding"]
        result = self.agent.extract_json(text, schema)
        assert result.get("type") == "sqli"

    def test_validate_schema_valid(self):
        schema = SimpleJSONAgent.PREDEFINED_SCHEMAS["finding"]
        data = {"type": "xss", "severity": "high"}
        assert self.agent.validate_schema(data, schema) is True

    def test_validate_schema_missing_required(self):
        schema = SimpleJSONAgent.PREDEFINED_SCHEMAS["finding"]
        data = {"severity": "high"}  # Missing "type"
        assert self.agent.validate_schema(data, schema) is False

    def test_coerce_types_string_to_int(self):
        schema = {
            "properties": {
                "count": {"type": "integer"},
                "name": {"type": "string"},
            }
        }
        data = {"count": "42", "name": 123}
        result = self.agent._coerce_types(data, schema)
        assert result["count"] == 42
        assert result["name"] == "123"

    def test_run_returns_expected_keys(self):
        state = _minimal_state()
        result = asyncio.run(self.agent.run(state, "Extract finding from scan output"))
        assert result["agent"] == "simple_json"
        assert "result" in result
        assert "valid" in result
        assert "schema_type" in result


# ===========================================================================
# TestOrchestratorHelpers  (6 tests)
# ===========================================================================


class TestOrchestratorHelpers:
    """Tests for new orchestrator helper methods."""

    def setup_method(self):
        self.registry = _empty_registry()
        self.orchestrator = OrchestratorAgent(self.registry)

    def test_orchestrator_has_refiner(self):
        assert "refiner" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_generator(self):
        assert "generator" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_adviser(self):
        assert "adviser" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_reflector(self):
        assert "reflector" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_enricher(self):
        assert "enricher" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_coder(self):
        assert "coder" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_installer(self):
        assert "installer" in self.orchestrator.get_registered_agent_names()

    def test_orchestrator_has_simple_json(self):
        assert "simple_json" in self.orchestrator.get_registered_agent_names()

    def test_enrich_findings_returns_list(self):
        result = asyncio.run(self.orchestrator.enrich_findings(SAMPLE_FINDINGS))
        assert isinstance(result, list)
        assert len(result) == len(SAMPLE_FINDINGS)

    def test_reflect_on_session_returns_dict(self):
        state = _state_with_findings(SAMPLE_FINDINGS)
        result = asyncio.run(self.orchestrator.reflect_on_session(state))
        assert isinstance(result, dict)
        assert "agent" in result
        assert result["agent"] == "reflector"

    def test_generate_payload_returns_dict(self):
        result = asyncio.run(
            self.orchestrator.generate_payload("xss", {"target": "http://example.com"})
        )
        assert isinstance(result, dict)
        assert "agent" in result
        assert result["agent"] == "generator"

    def test_all_eight_agents_in_registry(self):
        expected = {
            "refiner", "generator", "adviser", "reflector",
            "enricher", "coder", "installer", "simple_json",
        }
        assert expected.issubset(set(self.orchestrator.get_registered_agent_names()))
