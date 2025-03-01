"""
Reflector Agent — Self-Reflection and Attack Surface Analysis

Reviews completed penetration test steps, identifies missed attack surfaces,
and suggests next moves to improve engagement coverage.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class ReflectorAgent(BaseAgent):
    """
    Sub-agent that performs self-reflection on completed penetration test steps.

    Analyses the coverage achieved, identifies gaps and missed attack surfaces,
    and recommends follow-up actions to maximise engagement value.
    """

    AGENT_NAME = "reflector"
    PREFERRED_TOOLS: List[str] = ["query_graph", "web_search"]

    # All known attack categories for coverage analysis
    _KNOWN_ATTACK_CATEGORIES: List[str] = [
        "port_scan",
        "service_enumeration",
        "web_application",
        "authentication",
        "authorisation",
        "injection",
        "xss",
        "ssrf",
        "xxe",
        "csrf",
        "file_inclusion",
        "deserialization",
        "active_directory",
        "privilege_escalation",
        "lateral_movement",
        "credential_dumping",
        "persistence",
        "data_exfiltration",
    ]

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(registry, llm, config)

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def get_phase(self) -> Phase:
        return Phase.COMPLETE

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the Reflector Agent, an expert in post-engagement "
            "analysis and attack surface coverage assessment.\n\n"
            "Your responsibilities:\n"
            "  1. Review all completed penetration test steps.\n"
            "  2. Identify missed attack surfaces and coverage gaps.\n"
            "  3. Suggest concrete next steps to improve coverage.\n"
            "  4. Analyse findings for logical follow-up attack paths.\n"
            "  5. Provide a coverage score for the engagement.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Return structured reflections with coverage metrics and "
            "prioritised next steps."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Review completed steps and return reflective analysis.

        Args:
            state: Shared multi-agent state with all agent results.
            task:  Description of what to reflect on.

        Returns:
            ``{"agent": "reflector", "reflections": dict, "coverage_score": float,
               "missed_surfaces": list, "next_steps": list}``
        """
        agent_results = state.get("agent_results") or {}
        target_info = state.get("target_info") or {}

        logger.info("ReflectorAgent reviewing %d agent results", len(agent_results))

        findings = self._collect_findings(agent_results)
        completed_tests = list(agent_results.keys())

        reflections = self.reflect_on_findings(findings)
        missed = self.identify_missed_surfaces(target_info, completed_tests)
        next_steps = self.suggest_next_steps(
            {"findings": findings, "target_info": target_info, "completed": completed_tests}
        )
        coverage = self._analyze_coverage(completed_tests, self._KNOWN_ATTACK_CATEGORIES)

        return {
            "agent": self.AGENT_NAME,
            "reflections": reflections,
            "coverage_score": coverage,
            "missed_surfaces": missed,
            "next_steps": next_steps,
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def reflect_on_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyse findings and produce reflection insights.

        Args:
            findings: List of finding dicts from all agents.

        Returns:
            Dict with ``total``, ``severity_breakdown``, ``attack_patterns``,
            ``key_observations``.
        """
        severity_breakdown: Dict[str, int] = {}
        attack_patterns: List[str] = []
        vuln_types: List[str] = []

        for finding in findings:
            sev = finding.get("severity", "info").lower()
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

            ftype = finding.get("type", "")
            if ftype and ftype not in vuln_types:
                vuln_types.append(ftype)

        # Identify attack patterns from finding types
        if any("sqli" in t or "injection" in t for t in vuln_types):
            attack_patterns.append("SQL injection attack path identified")
        if any("xss" in t for t in vuln_types):
            attack_patterns.append("XSS attack surface present")
        if any("port_scan" in t or "service" in t for t in vuln_types):
            attack_patterns.append("Network service attack surface enumerated")
        if any("auth" in t or "credential" in t for t in vuln_types):
            attack_patterns.append("Authentication weaknesses identified")

        key_observations: List[str] = []
        if severity_breakdown.get("critical", 0) > 0:
            key_observations.append(
                f"{severity_breakdown['critical']} critical finding(s) require immediate attention."
            )
        if not findings:
            key_observations.append("No findings recorded — consider expanding scope.")

        return {
            "total": len(findings),
            "severity_breakdown": severity_breakdown,
            "attack_patterns": attack_patterns,
            "vulnerability_types": vuln_types,
            "key_observations": key_observations,
        }

    def identify_missed_surfaces(
        self,
        target_info: Dict[str, Any],
        completed_tests: List[str],
    ) -> List[str]:
        """
        Identify attack surfaces that were not tested.

        Args:
            target_info:     Target metadata.
            completed_tests: List of agent names that have run.

        Returns:
            List of missed attack surface descriptions.
        """
        missed: List[str] = []

        if "recon" not in completed_tests:
            missed.append("Port scanning and service enumeration not performed.")
        if "webapp" not in completed_tests and "web" not in str(completed_tests):
            missed.append("Web application testing not performed.")
        if "exploit" not in completed_tests:
            missed.append("Exploit validation not performed.")

        # Check for specific attack types based on target info
        target_str = str(target_info)
        if "windows" in target_str.lower() and "active_directory" not in str(completed_tests):
            missed.append("Active Directory enumeration not performed on Windows target.")
        if "web" in target_str.lower():
            missed.append("Consider testing for SSRF, XXE, and deserialization vulnerabilities.")

        if not missed:
            missed.append("Coverage appears comprehensive for identified scope.")

        return missed

    def suggest_next_steps(self, current_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Suggest prioritised next steps based on current engagement state.

        Args:
            current_state: Dict with findings, target_info, and completed agents.

        Returns:
            List of next-step dicts with ``step``, ``priority``, ``rationale``.
        """
        findings = current_state.get("findings", [])
        completed = current_state.get("completed", [])
        current_state.get("target_info", {})

        next_steps: List[Dict[str, Any]] = []

        # Always recommend enrichment if findings exist
        if findings and "enricher" not in completed:
            next_steps.append({
                "step": "Run EnricherAgent on all findings",
                "priority": 1,
                "rationale": "Add CVE references, CVSS scores, and OWASP mapping.",
                "agent": "enricher",
            })

        # Recommend report generation if major agents have run
        if len(completed) >= 2 and "report" not in completed:
            next_steps.append({
                "step": "Generate final penetration test report",
                "priority": 2,
                "rationale": "Compile all findings into a deliverable report.",
                "agent": "report",
            })

        # Recommend exploit follow-up for high-severity findings
        high_sev = [
            f for f in findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        if high_sev and "exploit" not in completed:
            next_steps.append({
                "step": f"Attempt exploitation of {len(high_sev)} high-severity finding(s)",
                "priority": 1,
                "rationale": "Validate exploitability of critical/high findings.",
                "agent": "exploit",
            })

        if not next_steps:
            next_steps.append({
                "step": "Review and finalise the engagement report",
                "priority": 3,
                "rationale": "All major testing phases appear complete.",
                "agent": "report",
            })

        return sorted(next_steps, key=lambda x: x["priority"])

    def _analyze_coverage(
        self,
        completed: List[str],
        available_attacks: List[str],
    ) -> float:
        """
        Calculate coverage score based on completed vs available attack categories.

        Args:
            completed:         List of completed agent/test names.
            available_attacks: All known attack categories.

        Returns:
            Coverage float from 0.0 to 1.0.
        """
        if not available_attacks:
            return 1.0

        completed_str = " ".join(completed).lower()
        covered = sum(
            1 for attack in available_attacks if attack.lower() in completed_str
        )

        # Base coverage from agent presence
        agent_coverage = 0.0
        if "recon" in completed:
            agent_coverage += 0.25
        if any(w in completed for w in ("webapp", "web")):
            agent_coverage += 0.25
        if "exploit" in completed:
            agent_coverage += 0.25
        if "report" in completed:
            agent_coverage += 0.25

        category_coverage = covered / len(available_attacks)

        return round(min(1.0, (agent_coverage + category_coverage) / 2), 2)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_findings(self, agent_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten findings from all agent result dicts."""
        findings: List[Dict[str, Any]] = []
        for result in agent_results.values():
            if isinstance(result, dict):
                findings.extend(result.get("findings", []))
        return findings


__all__ = ["ReflectorAgent"]
