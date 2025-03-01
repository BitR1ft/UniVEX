"""
Report Agent — Finding Summarisation and Report Generation

Purely data-transformational: reads accumulated ``agent_results`` from the
shared state and produces a structured Markdown penetration test report.

No network calls are made by this agent.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

# Severity ranking for deduplication and sorting (lower index = more severe)
_SEVERITY_RANK: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# CVSS-like severity labels
_CVSS_RANGES: List[tuple[str, str]] = [
    ("9.0-10.0", "Critical"),
    ("7.0-8.9", "High"),
    ("4.0-6.9", "Medium"),
    ("0.1-3.9", "Low"),
    ("0.0", "Informational"),
]


class ReportAgent(BaseAgent):
    """
    Sub-agent responsible for producing structured penetration test reports.

    Reads from ``state["agent_results"]``, deduplicates findings, assigns
    CVSS-like severity scores, and renders a Markdown report.

    This agent makes **no** network or tool calls — it is purely
    transformational.
    """

    AGENT_NAME = "report"
    PREFERRED_TOOLS: List[str] = []  # No tools needed

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
        return (
            "You are the Report Agent, an expert in penetration test report "
            "writing for professional security assessments.\n\n"
            "Your responsibilities:\n"
            "  1. Aggregate and deduplicate findings from all sub-agents.\n"
            "  2. Assign CVSS-like severity ratings to each finding.\n"
            "  3. Produce an executive summary suitable for management.\n"
            "  4. Provide detailed technical findings for engineers.\n"
            "  5. List actionable remediation recommendations.\n\n"
            "Output well-structured Markdown reports only."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Generate the final report from accumulated agent results.

        Args:
            state: Shared multi-agent state containing ``agent_results``.
            task:  Natural language task description (used as report title).

        Returns:
            ``{"agent": "report", "report": "<markdown>", "summary": {...}}``
        """
        agent_results = state.get("agent_results") or {}
        target_info = state.get("target_info") or {}
        target = target_info.get("target") or "Unknown Target"

        # Compress message history if it grew large during the engagement
        messages = state.get("messages", [])
        if messages:
            state["messages"] = await self.compress_messages(
                messages,
                flow_id=str(target_info.get("flow_id", "default")),
                session_id=str(target_info.get("session_id", "default")),
            )

        raw_findings = self._collect_findings(agent_results)
        summarised = self.summarize_findings(raw_findings)
        report_md = self.generate_report(summarised, target=target, task=task)

        critical = sum(1 for f in summarised if f.get("severity") == "critical")
        high = sum(1 for f in summarised if f.get("severity") == "high")
        medium = sum(1 for f in summarised if f.get("severity") == "medium")

        # Capture the report to episodic memory as a GUIDE entry
        try:
            from app.agent.memory.episodic_memory import MemoryType
            await self.capture_memory(
                content=report_md[:4096],  # Store first 4 KB of the report
                memory_type=MemoryType.GUIDE,
                session_id=str(target_info.get("session_id", "default")),
                target_type=str(target_info.get("type", "web")),
                score=1.0,
                tags=["final_report"],
            )
        except ImportError:
            pass

        return {
            "agent": self.AGENT_NAME,
            "report": report_md,
            "summary": {
                "total_findings": len(summarised),
                "critical": critical,
                "high": high,
                "medium": medium,
                "findings": summarised,
            },
        }

    # ------------------------------------------------------------------
    # Public report-generation methods
    # ------------------------------------------------------------------

    def generate_report(
        self,
        findings: List[Dict[str, Any]],
        target: str = "Target",
        task: str = "",
    ) -> str:
        """
        Render a structured Markdown penetration test report.

        Args:
            findings: Deduplicated, sorted finding dicts.
            target:   Name/IP of the target system.
            task:     Original engagement description.

        Returns:
            Multi-section Markdown string.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        medium = [f for f in findings if f.get("severity") == "medium"]
        low = [f for f in findings if f.get("severity") in ("low", "info")]

        lines: List[str] = []

        # ---- Title -------------------------------------------------------
        lines += [
            f"# Penetration Test Report — {target}",
            f"**Date:** {now}  ",
            f"**Engagement:** {task or 'Security Assessment'}",
            "",
        ]

        # ---- Executive Summary -------------------------------------------
        lines += [
            "## Executive Summary",
            "",
            f"This report presents the results of a penetration test conducted "
            f"against **{target}**.  The assessment identified a total of "
            f"**{len(findings)}** finding(s):",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {len(critical)} |",
            f"| High     | {len(high)} |",
            f"| Medium   | {len(medium)} |",
            f"| Low / Info | {len(low)} |",
            "",
        ]

        if not findings:
            lines += [
                "No exploitable vulnerabilities were identified during this "
                "assessment.  The target appears to be well-hardened.",
                "",
            ]
        else:
            risk_level = "Critical" if critical else ("High" if high else "Medium")
            lines += [
                f"The overall risk rating for this engagement is **{risk_level}**.",
                "",
            ]

        # ---- CVSS Severity Scale -----------------------------------------
        lines += [
            "## CVSS Severity Scale Reference",
            "",
            "| Score Range | Severity |",
            "|-------------|----------|",
        ]
        for score_range, label in _CVSS_RANGES:
            lines.append(f"| {score_range} | {label} |")
        lines.append("")

        # ---- Technical Findings ------------------------------------------
        lines += [
            "## Technical Findings",
            "",
        ]

        if not findings:
            lines += ["*No findings to report.*", ""]
        else:
            for idx, finding in enumerate(findings, start=1):
                severity = finding.get("severity", "info").capitalize()
                ftype = finding.get("type", "unknown")
                tool = finding.get("tool", "unknown")
                output = finding.get("output", "")
                lines += [
                    f"### Finding {idx}: {ftype.replace('_', ' ').title()} [{severity}]",
                    "",
                    f"**Type:** `{ftype}`  ",
                    f"**Tool:** `{tool}`  ",
                    f"**Severity:** {severity}  ",
                    "",
                    "**Details:**",
                    "",
                    "```",
                    str(output)[:1000],
                    "```",
                    "",
                ]

        # ---- Remediation Recommendations ---------------------------------
        lines += [
            "## Remediation Recommendations",
            "",
        ]

        recommendations = self._build_recommendations(findings)
        if not recommendations:
            lines += ["*No specific remediation actions required.*", ""]
        else:
            for rec in recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        # ---- Footer ------------------------------------------------------
        lines += [
            "---",
            "*Report generated by UniVex Multi-Agent Orchestration Framework.*",
        ]

        return "\n".join(lines)

    def summarize_findings(
        self, raw_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Deduplicate and sort findings by severity.

        Deduplication key: (type, tool).  When duplicates exist the entry
        with the highest severity is kept.

        Args:
            raw_findings: Unfiltered list of finding dicts from all agents.

        Returns:
            Deduplicated list sorted by severity (critical first).
        """
        if not raw_findings:
            return []

        seen: Dict[tuple, Dict[str, Any]] = {}

        for finding in raw_findings:
            ftype = finding.get("type", "unknown")
            tool = finding.get("tool", "unknown")
            key = (ftype, tool)

            if key not in seen:
                seen[key] = finding.copy()
            else:
                existing_rank = _SEVERITY_RANK.get(
                    seen[key].get("severity", "info"), 4
                )
                new_rank = _SEVERITY_RANK.get(
                    finding.get("severity", "info"), 4
                )
                if new_rank < existing_rank:
                    seen[key] = finding.copy()

        deduped = list(seen.values())
        deduped.sort(
            key=lambda f: _SEVERITY_RANK.get(f.get("severity", "info"), 4)
        )
        return deduped

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_findings(
        self, agent_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Flatten findings from all sub-agent result dicts."""
        all_findings: List[Dict[str, Any]] = []
        for agent_name, result in agent_results.items():
            if not isinstance(result, dict):
                continue
            findings = result.get("findings", [])
            for finding in findings:
                enriched = dict(finding)
                enriched.setdefault("source_agent", agent_name)
                all_findings.append(enriched)
        return all_findings

    def _build_recommendations(
        self, findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate remediation recommendations based on finding types."""
        type_recs: Dict[str, str] = {
            "xss": (
                "Implement Content Security Policy (CSP) headers and sanitise "
                "all user-supplied input before rendering."
            ),
            "csrf": (
                "Enforce anti-CSRF tokens on all state-changing requests and "
                "validate the Origin/Referer headers."
            ),
            "ssrf": (
                "Restrict outbound connections to allowlisted destinations and "
                "validate all user-supplied URLs server-side."
            ),
            "idor": (
                "Implement object-level authorisation checks on every resource "
                "access request."
            ),
            "injection": (
                "Use parameterised queries / prepared statements and validate "
                "all input against a strict schema."
            ),
            "sqli": (
                "Use parameterised SQL queries and apply the principle of least "
                "privilege to database accounts."
            ),
            "jwt": (
                "Rotate JWT signing keys regularly, enforce short expiry times, "
                "and validate algorithm and audience claims."
            ),
            "oauth": (
                "Follow RFC 6749 best practices: use PKCE, validate redirect URIs "
                "strictly, and bind tokens to client identifiers."
            ),
            "api": (
                "Apply rate limiting, authentication, and schema validation on "
                "all API endpoints."
            ),
            "graphql": (
                "Disable introspection in production, apply depth limits, and "
                "enforce per-field authorisation."
            ),
            "cors": (
                "Restrict CORS to trusted origins; never use wildcard origins "
                "with credentials."
            ),
            "service_exploit": (
                "Patch all software to the latest stable versions and disable "
                "unnecessary services."
            ),
            "privilege_escalation": (
                "Apply the principle of least privilege; audit SUID/SUDO "
                "configurations and scheduled tasks regularly."
            ),
            "credential_attack": (
                "Enforce strong password policies, multi-factor authentication, "
                "and account lockout thresholds."
            ),
            "port_scan": (
                "Restrict network access using firewall rules; expose only "
                "services required for business operations."
            ),
        }

        recs: List[str] = []
        seen_types: set = set()

        for finding in findings:
            ftype = finding.get("type", "")
            for key, rec in type_recs.items():
                if key in ftype and key not in seen_types:
                    recs.append(rec)
                    seen_types.add(key)

        return recs


__all__ = ["ReportAgent"]
