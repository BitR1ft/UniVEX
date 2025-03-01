"""
Enricher Agent — Finding Data Enrichment

Automatically enriches findings with CVE references, OWASP mapping, CVSS
scoring, CWE identifiers, and recommended remediation guidance.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class EnricherAgent(BaseAgent):
    """
    Sub-agent that enriches penetration test findings with security metadata.

    Adds CVE references, OWASP Top 10 mapping, CVSS scores, CWE identifiers,
    and prioritised remediation guidance to raw findings.
    """

    AGENT_NAME = "enricher"
    PREFERRED_TOOLS: List[str] = ["web_search", "query_graph", "searchsploit"]

    # OWASP Top 10 (2021) mapping from common vulnerability types
    OWASP_MAPPING: Dict[str, str] = {
        "sqli": "A03:2021 - Injection",
        "injection": "A03:2021 - Injection",
        "xss": "A03:2021 - Injection",
        "xxe": "A05:2021 - Security Misconfiguration",
        "ssrf": "A10:2021 - Server-Side Request Forgery",
        "idor": "A01:2021 - Broken Access Control",
        "bac": "A01:2021 - Broken Access Control",
        "auth": "A07:2021 - Identification and Authentication Failures",
        "credential": "A07:2021 - Identification and Authentication Failures",
        "csrf": "A01:2021 - Broken Access Control",
        "deserialization": "A08:2021 - Software and Data Integrity Failures",
        "lfi": "A05:2021 - Security Misconfiguration",
        "rfi": "A05:2021 - Security Misconfiguration",
        "redirect": "A01:2021 - Broken Access Control",
        "crypto": "A02:2021 - Cryptographic Failures",
        "tls": "A02:2021 - Cryptographic Failures",
        "jwt": "A02:2021 - Cryptographic Failures",
        "component": "A06:2021 - Vulnerable and Outdated Components",
        "dependency": "A06:2021 - Vulnerable and Outdated Components",
        "logging": "A09:2021 - Security Logging and Monitoring Failures",
        "ssti": "A03:2021 - Injection",
        "cors": "A05:2021 - Security Misconfiguration",
        "port_scan": "A05:2021 - Security Misconfiguration",
        "service_exploit": "A06:2021 - Vulnerable and Outdated Components",
    }

    # Base CVSS scores by severity label
    CVSS_BASE_SCORES: Dict[str, float] = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.0,
        "informational": 0.0,
    }

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
            "You are the Enricher Agent, an expert in security metadata "
            "enrichment for penetration test findings.\n\n"
            "Your responsibilities:\n"
            "  1. Identify relevant CVE identifiers for each finding.\n"
            "  2. Map vulnerabilities to OWASP Top 10 categories.\n"
            "  3. Calculate CVSS v3.1 scores based on attack characteristics.\n"
            "  4. Assign CWE identifiers to vulnerability types.\n"
            "  5. Provide prioritised remediation recommendations.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Return findings enriched with security metadata."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Enrich all findings in the current state.

        Args:
            state: Shared multi-agent state with agent results.
            task:  Task description (used if no findings in state).

        Returns:
            ``{"agent": "enricher", "enriched_findings": list,
               "total_enriched": int}``
        """
        agent_results = state.get("agent_results") or {}
        logger.info("EnricherAgent enriching findings from %d agents", len(agent_results))

        raw_findings = self._collect_findings(agent_results)
        enriched: List[Dict[str, Any]] = []

        for finding in raw_findings:
            try:
                enriched.append(self.enrich_finding(finding))
            except Exception as exc:
                logger.warning("Failed to enrich finding: %s", exc)
                enriched.append(finding)

        return {
            "agent": self.AGENT_NAME,
            "enriched_findings": enriched,
            "total_enriched": len(enriched),
            "findings": enriched,  # also expose under "findings" for compatibility
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single finding with security metadata.

        Args:
            finding: Raw finding dict with at minimum ``type`` and ``severity``.

        Returns:
            Enriched finding with ``cve_references``, ``owasp_mapping``,
            ``cvss_score``, ``remediation``, ``cwe_id``.
        """
        enriched = dict(finding)
        vuln_type = finding.get("type", "")
        severity = finding.get("severity", "info")
        description = finding.get("output", "")

        enriched["cve_references"] = self._lookup_cve(vuln_type, str(description))
        enriched["owasp_mapping"] = self._map_to_owasp(vuln_type)
        enriched["cvss_score"] = self._calculate_cvss(
            severity=severity,
            attack_vector="network",
            privileges="none",
            user_interaction="none",
        )
        enriched["cwe_id"] = self._map_to_cwe(vuln_type)
        enriched["remediation"] = self._get_remediation(vuln_type)

        return enriched

    def _lookup_cve(self, vulnerability_type: str, description: str) -> List[str]:
        """
        Return likely CVE references for the vulnerability type.

        Args:
            vulnerability_type: Type string (e.g. "sqli", "xss").
            description:        Finding description text.

        Returns:
            List of CVE ID strings.
        """
        cve_map: Dict[str, List[str]] = {
            "log4j": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
            "sqli": ["CVE-2012-1823"],
            "xss": [],
            "ssrf": [],
            "deserialization": ["CVE-2017-5638"],
            "heartbleed": ["CVE-2014-0160"],
            "shellshock": ["CVE-2014-6271"],
            "eternalblue": ["CVE-2017-0144"],
        }

        results: List[str] = []
        combined = f"{vulnerability_type} {description}".lower()

        for keyword, cves in cve_map.items():
            if keyword in combined:
                results.extend(cves)

        return list(set(results))

    def _map_to_owasp(self, vulnerability_type: str) -> str:
        """
        Map a vulnerability type to the OWASP Top 10 2021 category.

        Args:
            vulnerability_type: Vulnerability type string.

        Returns:
            OWASP category string.
        """
        vuln_lower = vulnerability_type.lower()
        for key, category in self.OWASP_MAPPING.items():
            if key in vuln_lower:
                return category
        return "A05:2021 - Security Misconfiguration"

    def _calculate_cvss(
        self,
        severity: str,
        attack_vector: str,
        privileges: str,
        user_interaction: str,
    ) -> float:
        """
        Calculate a CVSS v3.1-inspired score.

        Args:
            severity:         Base severity label.
            attack_vector:    "network", "adjacent", "local", or "physical".
            privileges:       "none", "low", or "high".
            user_interaction: "none" or "required".

        Returns:
            CVSS score float (0.0–10.0).
        """
        base = self.CVSS_BASE_SCORES.get(severity.lower(), 5.0)

        # Apply minor adjustments for vector and privilege requirements
        av_modifier = {"network": 0.0, "adjacent": -0.5, "local": -1.0, "physical": -1.5}
        pr_modifier = {"none": 0.0, "low": -0.5, "high": -1.0}
        ui_modifier = {"none": 0.0, "required": -0.5}

        score = (
            base
            + av_modifier.get(attack_vector.lower(), 0.0)
            + pr_modifier.get(privileges.lower(), 0.0)
            + ui_modifier.get(user_interaction.lower(), 0.0)
        )

        return round(max(0.0, min(10.0, score)), 1)

    def _map_to_cwe(self, vulnerability_type: str) -> str:
        """Map vulnerability type to CWE identifier."""
        cwe_map: Dict[str, str] = {
            "sqli": "CWE-89",
            "injection": "CWE-74",
            "xss": "CWE-79",
            "ssrf": "CWE-918",
            "idor": "CWE-639",
            "csrf": "CWE-352",
            "lfi": "CWE-22",
            "rfi": "CWE-98",
            "auth": "CWE-287",
            "deserialization": "CWE-502",
            "xxe": "CWE-611",
            "ssti": "CWE-94",
            "cors": "CWE-942",
            "redirect": "CWE-601",
            "crypto": "CWE-326",
            "tls": "CWE-295",
        }
        vuln_lower = vulnerability_type.lower()
        for key, cwe in cwe_map.items():
            if key in vuln_lower:
                return cwe
        return "CWE-693"

    def _get_remediation(self, vulnerability_type: str) -> str:
        """Return a brief remediation string for the vulnerability type."""
        remediation_map: Dict[str, str] = {
            "sqli": "Use parameterised queries and input validation.",
            "xss": "Encode output and implement Content Security Policy.",
            "ssrf": "Validate URLs and restrict outbound connections.",
            "idor": "Implement object-level authorisation checks.",
            "csrf": "Use anti-CSRF tokens on all state-changing requests.",
            "lfi": "Validate and sanitise file paths; use allowlists.",
            "deserialization": "Avoid deserialising untrusted data; use integrity checks.",
            "auth": "Enforce strong authentication and session management.",
            "xxe": "Disable external entity processing in XML parsers.",
            "cors": "Restrict CORS to trusted origins only.",
        }
        vuln_lower = vulnerability_type.lower()
        for key, remediation in remediation_map.items():
            if key in vuln_lower:
                return remediation
        return "Apply vendor patches and follow security best practices."

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


__all__ = ["EnricherAgent"]
