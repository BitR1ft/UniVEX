"""
Adviser Agent — Expert Consultation and Second-Opinion Role

Queried for second opinions on exploit selection, risk assessment,
remediation advice, and attack strategy recommendations.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class ConsultationType(str, Enum):
    """Types of consultation the AdviserAgent provides."""

    EXPLOIT_SELECTION = "exploit_selection"
    RISK_ASSESSMENT = "risk_assessment"
    REMEDIATION = "remediation"
    ATTACK_STRATEGY = "attack_strategy"
    COMPLIANCE = "compliance"


class AdviserAgent(BaseAgent):
    """
    Sub-agent providing expert consultation for penetration test decisions.

    Acts as a second opinion on exploit selection, risk rating, remediation
    guidance, and overall attack strategy.
    """

    AGENT_NAME = "adviser"
    PREFERRED_TOOLS: List[str] = ["web_search", "query_graph", "searchsploit"]

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
            "You are the Adviser Agent, a senior penetration testing expert "
            "providing authoritative consultation and second opinions.\n\n"
            "Your responsibilities:\n"
            "  1. Evaluate and rank available exploits for a given target.\n"
            "  2. Assess risk scores, likelihood, and impact of findings.\n"
            "  3. Recommend practical remediation strategies.\n"
            "  4. Advise on optimal attack strategy and sequencing.\n"
            "  5. Map findings to compliance frameworks (PCI-DSS, SOC2, ISO27001).\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Provide structured, actionable advice with clear reasoning."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Provide expert consultation based on the task and current state.

        Args:
            state: Shared multi-agent state with findings and target info.
            task:  Consultation request description.

        Returns:
            ``{"agent": "adviser", "consultation_type": str, "advice": dict}``
        """
        target_info = state.get("target_info") or {}
        agent_results = state.get("agent_results") or {}

        logger.info("AdviserAgent consultation: %s", task[:80])

        consultation_type = self._infer_consultation_type(task)

        # Gather findings from all agents for context
        findings = self._collect_findings(agent_results)

        if consultation_type == ConsultationType.RISK_ASSESSMENT:
            advice = self.assess_risk({"findings": findings, "target": target_info})
        elif consultation_type == ConsultationType.REMEDIATION:
            advice = self.suggest_remediation("general", {"findings": findings})
        elif consultation_type == ConsultationType.EXPLOIT_SELECTION:
            advice = self.select_exploit(target_info, findings)
        elif consultation_type == ConsultationType.ATTACK_STRATEGY:
            advice = self._advise_attack_strategy(target_info, findings)
        else:
            advice = self._advise_compliance(findings)

        return {
            "agent": self.AGENT_NAME,
            "consultation_type": consultation_type.value,
            "advice": advice,
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def assess_risk(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the risk level of a finding or set of findings.

        Args:
            finding: Finding dict or aggregate context with target and findings.

        Returns:
            Dict with ``risk_score``, ``likelihood``, ``impact``,
            ``recommendations``.
        """
        findings = finding.get("findings", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Compute a simple weighted risk score (0-10)
        risk_score = min(10.0, (
            severity_counts["critical"] * 4.0
            + severity_counts["high"] * 2.0
            + severity_counts["medium"] * 1.0
            + severity_counts["low"] * 0.25
        ))

        likelihood = "High" if risk_score >= 7 else ("Medium" if risk_score >= 4 else "Low")
        impact = "Severe" if severity_counts["critical"] > 0 else (
            "High" if severity_counts["high"] > 0 else "Moderate"
        )

        return {
            "risk_score": round(risk_score, 1),
            "likelihood": likelihood,
            "impact": impact,
            "severity_breakdown": severity_counts,
            "recommendations": [
                "Address all critical and high findings immediately.",
                "Implement a patch management programme.",
                "Perform follow-up testing after remediation.",
            ],
        }

    def suggest_remediation(
        self,
        vulnerability_type: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Suggest remediation steps for the given vulnerability type.

        Args:
            vulnerability_type: E.g. "sqli", "xss", "ssrf".
            context:            Additional context (target info, findings).

        Returns:
            Dict with ``steps``, ``priority``, ``estimated_effort``,
            ``references``.
        """
        remediation_map: Dict[str, Dict[str, Any]] = {
            "sqli": {
                "steps": [
                    "Use parameterised queries / prepared statements.",
                    "Apply input validation and allowlisting.",
                    "Restrict database account privileges.",
                    "Enable a Web Application Firewall (WAF).",
                ],
                "priority": "Critical",
                "estimated_effort": "2-5 days",
                "references": ["OWASP SQL Injection Prevention Cheat Sheet"],
            },
            "xss": {
                "steps": [
                    "Encode all output context-appropriately.",
                    "Implement Content Security Policy (CSP).",
                    "Sanitise user input server-side.",
                    "Use X-XSS-Protection header.",
                ],
                "priority": "High",
                "estimated_effort": "1-3 days",
                "references": ["OWASP XSS Prevention Cheat Sheet"],
            },
            "ssrf": {
                "steps": [
                    "Validate and sanitise all user-supplied URLs.",
                    "Use an allowlist for outbound connections.",
                    "Block access to internal metadata endpoints.",
                    "Segment internal networks from public-facing services.",
                ],
                "priority": "High",
                "estimated_effort": "3-7 days",
                "references": ["OWASP SSRF Prevention Cheat Sheet"],
            },
        }

        base = remediation_map.get(
            vulnerability_type.lower(),
            {
                "steps": [
                    "Apply vendor patches and security advisories.",
                    "Follow OWASP remediation guidelines.",
                    "Perform security code review.",
                    "Re-test after remediation.",
                ],
                "priority": "Medium",
                "estimated_effort": "1-5 days",
                "references": ["OWASP Top 10"],
            },
        )

        return {**base, "vulnerability_type": vulnerability_type, "context": context}

    def select_exploit(
        self,
        target_info: Dict[str, Any],
        available_exploits: List[Any],
    ) -> Dict[str, Any]:
        """
        Select the most appropriate exploit for the target.

        Args:
            target_info:       Target metadata (OS, services, versions).
            available_exploits: List of exploit dicts or finding dicts.

        Returns:
            Dict with ``selected``, ``rationale``, ``alternatives``,
            ``risk_level``.
        """
        if not available_exploits:
            return {
                "selected": None,
                "rationale": "No exploits available for evaluation.",
                "alternatives": [],
                "risk_level": "Unknown",
            }

        # Rank by severity (critical > high > medium > low)
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_exploits = sorted(
            available_exploits,
            key=lambda e: severity_rank.get(
                str(e.get("severity", "info")).lower(), 4
            ),
        )

        selected = sorted_exploits[0]
        return {
            "selected": selected,
            "rationale": (
                f"Selected based on highest severity: "
                f"{selected.get('severity', 'unknown')} — "
                f"{selected.get('type', 'unknown')}"
            ),
            "alternatives": sorted_exploits[1:3],
            "risk_level": selected.get("severity", "unknown"),
            "target_context": target_info,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _infer_consultation_type(self, task: str) -> ConsultationType:
        """Infer the consultation type from the task description."""
        task_lower = task.lower()
        if "risk" in task_lower or "assess" in task_lower:
            return ConsultationType.RISK_ASSESSMENT
        if "remediat" in task_lower or "fix" in task_lower or "patch" in task_lower:
            return ConsultationType.REMEDIATION
        if "exploit" in task_lower or "select" in task_lower:
            return ConsultationType.EXPLOIT_SELECTION
        if "strategy" in task_lower or "attack" in task_lower:
            return ConsultationType.ATTACK_STRATEGY
        if "compliance" in task_lower or "pci" in task_lower or "iso" in task_lower:
            return ConsultationType.COMPLIANCE
        return ConsultationType.RISK_ASSESSMENT

    def _collect_findings(self, agent_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten findings from all agent result dicts."""
        findings: List[Dict[str, Any]] = []
        for result in agent_results.values():
            if isinstance(result, dict):
                findings.extend(result.get("findings", []))
        return findings

    def _advise_attack_strategy(
        self, target_info: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Return attack strategy advice based on findings."""
        return {
            "recommended_sequence": [
                "1. Exploit highest-severity findings first.",
                "2. Attempt privilege escalation if low-privilege access is achieved.",
                "3. Pivot to internal network segments.",
                "4. Extract credentials and sensitive data.",
                "5. Maintain persistence for report evidence.",
            ],
            "target_context": target_info,
            "finding_count": len(findings),
        }

    def _advise_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Return compliance framework mapping advice."""
        return {
            "pci_dss": "Review findings against PCI-DSS v4.0 requirements 6.2 and 11.3.",
            "iso27001": "Map findings to ISO 27001 Annex A controls.",
            "soc2": "Review against SOC 2 Type II CC6 and CC7 criteria.",
            "finding_count": len(findings),
        }


__all__ = ["AdviserAgent", "ConsultationType"]
