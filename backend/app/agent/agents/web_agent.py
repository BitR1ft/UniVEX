"""
Web Application Agent — Web Attack Specialisation

Performs web application security testing across multiple attack categories:
  - XSS (Reflected, Stored, DOM)
  - CSRF / SSRF / Open Redirect
  - IDOR & Access Control bypass
  - JWT, OAuth, API key leakage
  - API security (REST, GraphQL)
  - Advanced injection (NoSQL, SSTI, LDAP, XXE, Command, Header)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

# Priority order used by _prioritize_tests(): lower number = higher priority
_TEST_PRIORITY: Dict[str, int] = {
    "xss": 1,
    "csrf": 2,
    "ssrf": 3,
    "idor": 4,
    "injection": 5,
    "jwt": 6,
    "oauth": 7,
    "api": 8,
    "graphql": 9,
    "cors": 10,
}


class WebAppAgent(BaseAgent):
    """
    Sub-agent specialised in web application attack techniques.

    Runs prioritised web attack tests against the target and aggregates
    all findings for the orchestrator.
    """

    AGENT_NAME = "webapp"

    PREFERRED_TOOLS: List[str] = [
        # XSS
        "reflected_xss",
        "stored_xss",
        "dom_xss",
        # CSRF / SSRF / Open Redirect
        "csrf_detect",
        "csrf_exploit",
        "ssrf_probe",
        "ssrf_blind",
        "open_redirect",
        # IDOR & Access Control
        "idor_detect",
        "idor_exploit",
        "privilege_escalation_web",
        "auth_bypass",
        "session_puzzling",
        "rate_limit_bypass",
        # JWT / OAuth / API keys
        "jwt_analyze",
        "jwt_brute_force",
        "jwt_forge",
        "oauth_flow",
        "oauth_token_leak",
        "api_key_leak",
        # API security
        "openapi_parser",
        "api_fuzz",
        "mass_assignment",
        "graphql_introspection",
        "graphql_injection",
        "graphql_idor",
        "api_rate_limit",
        "cors_misconfig",
        # Advanced injection
        "nosql_injection",
        "ssti_detect",
        "ssti_exploit",
        "ldap_injection",
        "xxe",
        "command_injection",
        "header_injection",
        # HTTP baseline
        "curl",
        "nikto_agent",
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
        return Phase.EXPLOITATION

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the Web Application Agent, an expert in web security "
            "testing for penetration testing engagements.\n\n"
            "Your responsibilities:\n"
            "  1. Test for XSS vulnerabilities (reflected, stored, DOM).\n"
            "  2. Detect and exploit CSRF, SSRF, and open redirect flaws.\n"
            "  3. Test IDOR and access control vulnerabilities.\n"
            "  4. Analyse JWT tokens, OAuth flows, and API key exposure.\n"
            "  5. Test REST and GraphQL API security.\n"
            "  6. Probe for advanced injection flaws (NoSQL, SSTI, XXE, …).\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Return structured findings with severity ratings and proof-of-concept "
            "details where applicable."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Execute the web attack workstream.

        Args:
            state: Shared multi-agent state.
            task:  Natural language task description.

        Returns:
            ``{"agent": "webapp", "findings": [...], "tests_run": [...]}``
        """
        target_info = (state.get("target_info") or {}).copy()
        target = target_info.get("target") or task

        logger.info("WebAppAgent starting web tests for target: %s", target)

        # Compress message history if context window is near capacity
        messages = state.get("messages", [])
        if messages:
            state["messages"] = await self.compress_messages(
                messages,
                flow_id=str(target_info.get("flow_id", "default")),
                session_id=str(target_info.get("session_id", "default")),
            )

        # Query past web vulnerabilities for this target
        past = await self.query_past_knowledge(
            f"web vulnerability XSS CSRF SSRF injection {target}",
            limit=5,
        )
        if past:
            logger.info("WebAppAgent: loaded %d past web vulnerability records", len(past))

        result = await self.test_web_target(target, target_info)
        result["agent"] = self.AGENT_NAME

        # Capture critical findings to memory
        critical = [f for f in result.get("findings", []) if f.get("severity") == "critical"]
        if critical:
            try:
                from app.agent.memory.episodic_memory import MemoryType
                summary = f"Web attacks on {target}: {len(critical)} critical findings"
                await self.capture_memory(
                    content=summary,
                    memory_type=MemoryType.ANSWER,
                    session_id=str(target_info.get("session_id", "default")),
                    target_type="web",
                    score=0.9,
                )
            except ImportError:
                pass

        return result

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def test_web_target(
        self,
        target: str,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Orchestrate all web attack tests against *target*.

        Runs prioritised test groups in parallel where dependencies allow,
        then aggregates findings.

        Args:
            target:      URL or hostname of the web target.
            target_info: Pre-existing recon metadata.

        Returns:
            Dict with ``findings`` list and ``tests_run`` list.
        """
        ordered_tests = self._prioritize_tests()
        findings: List[Dict[str, Any]] = []
        tests_run: List[str] = []

        # Group tests into a single gather for maximum parallelism
        test_tasks = [self._run_test(category, target) for category in ordered_tests]
        results = await asyncio.gather(*test_tasks, return_exceptions=True)

        for category, result in zip(ordered_tests, results):
            tests_run.append(category)
            if isinstance(result, Exception):
                logger.warning("Web test '%s' failed: %s", category, result)
                continue
            if isinstance(result, list):
                findings.extend(result)

        return {
            "findings": findings,
            "tests_run": tests_run,
        }

    def _prioritize_tests(self) -> List[str]:
        """
        Return test categories ordered by priority (most impactful first).

        Categories present in the registry are placed first; remaining
        categories from the default priority map fill in afterwards.
        """
        available_categories: Dict[str, int] = {}

        for tool_name in self.get_tool_names():
            for category, priority in _TEST_PRIORITY.items():
                if category in tool_name:
                    available_categories[category] = priority

        # Add any remaining priority categories not yet found
        for category, priority in _TEST_PRIORITY.items():
            available_categories.setdefault(category, priority)

        return sorted(available_categories, key=lambda c: available_categories[c])

    # ------------------------------------------------------------------
    # Private per-category test runners
    # ------------------------------------------------------------------

    async def _run_test(
        self, category: str, target: str
    ) -> List[Dict[str, Any]]:
        """Dispatch a single test category and return its findings."""
        dispatch: Dict[str, Any] = {
            "xss": self._test_xss,
            "csrf": self._test_csrf,
            "ssrf": self._test_ssrf,
            "idor": self._test_idor,
            "injection": self._test_injection,
            "jwt": self._test_jwt,
            "oauth": self._test_oauth,
            "api": self._test_api,
            "graphql": self._test_graphql,
            "cors": self._test_cors,
        }
        handler = dispatch.get(category)
        if handler is None:
            return []
        return await handler(target)

    async def _test_xss(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tool_name in ("reflected_xss", "stored_xss", "dom_xss"):
            tool = self.registry.get_tool(tool_name)
            if tool is None:
                continue
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "xss",
                    "tool": tool_name,
                    "output": output,
                    "severity": "high",
                })
            except Exception as exc:
                logger.debug("%s error: %s", tool_name, exc)
        return findings

    async def _test_csrf(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tool = self.registry.get_tool("csrf_detect")
        if tool is not None:
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "csrf",
                    "tool": "csrf_detect",
                    "output": output,
                    "severity": "medium",
                })
            except Exception as exc:
                logger.debug("csrf_detect error: %s", exc)
        return findings

    async def _test_ssrf(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tool_name in ("ssrf_probe", "ssrf_blind"):
            tool = self.registry.get_tool(tool_name)
            if tool is None:
                continue
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "ssrf",
                    "tool": tool_name,
                    "output": output,
                    "severity": "high",
                })
            except Exception as exc:
                logger.debug("%s error: %s", tool_name, exc)
        return findings

    async def _test_idor(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tool = self.registry.get_tool("idor_detect")
        if tool is not None:
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "idor",
                    "tool": "idor_detect",
                    "output": output,
                    "severity": "high",
                })
            except Exception as exc:
                logger.debug("idor_detect error: %s", exc)
        return findings

    async def _test_injection(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tool_name in (
            "nosql_injection", "ssti_detect", "ldap_injection",
            "xxe", "command_injection", "header_injection",
        ):
            tool = self.registry.get_tool(tool_name)
            if tool is None:
                continue
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "injection",
                    "tool": tool_name,
                    "output": output,
                    "severity": "critical",
                })
            except Exception as exc:
                logger.debug("%s error: %s", tool_name, exc)
        return findings

    async def _test_jwt(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tool = self.registry.get_tool("jwt_analyze")
        if tool is not None:
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "jwt",
                    "tool": "jwt_analyze",
                    "output": output,
                    "severity": "medium",
                })
            except Exception as exc:
                logger.debug("jwt_analyze error: %s", exc)
        return findings

    async def _test_oauth(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tool = self.registry.get_tool("oauth_flow")
        if tool is not None:
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "oauth",
                    "tool": "oauth_flow",
                    "output": output,
                    "severity": "medium",
                })
            except Exception as exc:
                logger.debug("oauth_flow error: %s", exc)
        return findings

    async def _test_api(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tool_name in ("openapi_parser", "api_fuzz", "mass_assignment", "api_rate_limit"):
            tool = self.registry.get_tool(tool_name)
            if tool is None:
                continue
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "api",
                    "tool": tool_name,
                    "output": output,
                    "severity": "medium",
                })
            except Exception as exc:
                logger.debug("%s error: %s", tool_name, exc)
        return findings

    async def _test_graphql(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tool_name in ("graphql_introspection", "graphql_injection", "graphql_idor"):
            tool = self.registry.get_tool(tool_name)
            if tool is None:
                continue
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "graphql",
                    "tool": tool_name,
                    "output": output,
                    "severity": "high",
                })
            except Exception as exc:
                logger.debug("%s error: %s", tool_name, exc)
        return findings

    async def _test_cors(self, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        tool = self.registry.get_tool("cors_misconfig")
        if tool is not None:
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "cors",
                    "tool": "cors_misconfig",
                    "output": output,
                    "severity": "medium",
                })
            except Exception as exc:
                logger.debug("cors_misconfig error: %s", exc)
        return findings


__all__ = ["WebAppAgent"]
