"""
Recon Agent — Reconnaissance Specialisation

Performs the informational / reconnaissance phase of an engagement:
  - Port scanning (Naabu)
  - HTTP probing and technology detection (Nuclei, Curl)
  - Directory and file fuzzing (Ffuf)
  - Domain and endpoint enumeration
  - Web search for OSINT
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    """
    Sub-agent specialised in passive and active reconnaissance.

    Preferred tools cover port scanning, HTTP probing, endpoint fuzzing,
    and OSINT web search.  The agent never attempts exploitation.
    """

    AGENT_NAME = "recon"

    PREFERRED_TOOLS: List[str] = [
        # Network enumeration
        "naabu",
        "snmp",
        "anonymous_ftp",
        # HTTP probing & content discovery
        "curl",
        "nuclei",
        "nikto_agent",
        # Directory / file / param fuzzing
        "ffuf_fuzz_dirs",
        "ffuf_fuzz_files",
        "ffuf_fuzz_params",
        # OSINT / search
        "web_search",
        "query_graph",
        # CMS fingerprinting
        "wpscan",
        # Exploit database lookup (read-only in recon)
        "searchsploit",
        # Active Directory enumeration (read-only)
        "enum4linux",
        "ldap_enum",
        "kerberoute",
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
        return Phase.INFORMATIONAL

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the Recon Agent, an expert in passive and active "
            "reconnaissance for penetration testing engagements.\n\n"
            "Your responsibilities:\n"
            "  1. Enumerate open ports and running services.\n"
            "  2. Detect technologies and software versions.\n"
            "  3. Discover directories, files, and hidden endpoints.\n"
            "  4. Collect OSINT about the target domain.\n"
            "  5. Identify potential attack surfaces for later phases.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Return structured findings with service names, versions, and "
            "potential attack vectors.  Do NOT attempt exploitation."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Execute the reconnaissance workstream.

        Args:
            state: Shared multi-agent state (reads ``target_info``).
            task:  Natural language description of the recon task.

        Returns:
            ``{"agent": "recon", "findings": [...], "target_info": {...}}``
        """
        target_info = (state.get("target_info") or {}).copy()
        target = target_info.get("target") or task

        logger.info("ReconAgent starting scan for target: %s", target)

        # Compress message history if context window is near capacity
        messages = state.get("messages", [])
        if messages:
            state["messages"] = await self.compress_messages(
                messages,
                flow_id=str(target_info.get("flow_id", "default")),
                session_id=str(target_info.get("session_id", "default")),
            )

        # Query past knowledge for this target before planning
        past = await self.query_past_knowledge(
            f"recon {target} port scan enumeration findings",
            limit=5,
        )
        if past:
            logger.info("ReconAgent: loaded %d past knowledge items for context", len(past))

        result = await self.scan_target(target, target_info)
        result["agent"] = self.AGENT_NAME

        # Capture findings summary to episodic memory
        if result.get("findings"):
            try:
                from app.agent.memory.episodic_memory import MemoryType
                summary = f"Recon of {target}: {len(result['findings'])} findings"
                await self.capture_memory(
                    content=summary,
                    memory_type=MemoryType.ANSWER,
                    session_id=str(target_info.get("session_id", "default")),
                    target_type="network",
                    tool_name="multi",
                )
            except ImportError:
                pass

        return result

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    async def scan_target(
        self,
        target: str,
        target_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Core recon flow: port scan → HTTP probe → dir fuzz → OSINT.

        Args:
            target:      IP address or hostname to scan.
            target_info: Pre-existing metadata to enrich.

        Returns:
            Dict with ``findings`` list and enriched ``target_info``.
        """
        findings: List[Dict[str, Any]] = []
        enriched_info: Dict[str, Any] = dict(target_info or {})
        enriched_info.setdefault("target", target)

        tasks = [
            self._run_port_scan(target),
            self._run_http_probe(target),
            self._run_dir_fuzz(target),
            self._run_osint(target),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.warning("Recon subtask failed: %s", result)
                continue
            if isinstance(result, dict):
                findings.extend(result.get("findings", []))
                enriched_info.update(result.get("info", {}))

        return {
            "findings": findings,
            "target_info": enriched_info,
        }

    # ------------------------------------------------------------------
    # Private scan helpers
    # ------------------------------------------------------------------

    async def _run_port_scan(self, target: str) -> Dict[str, Any]:
        """Execute port scanning via Naabu (or simulate if unavailable)."""
        tool = self.registry.get_tool("naabu")
        findings: List[Dict[str, Any]] = []
        info: Dict[str, Any] = {}

        if tool is not None:
            try:
                output = await tool.execute(target=target, top_ports=1000)
                findings.append({
                    "type": "port_scan",
                    "tool": "naabu",
                    "output": output,
                    "severity": "info",
                })
                info["port_scan_completed"] = True
            except Exception as exc:
                logger.debug("naabu error: %s", exc)
        else:
            findings.append({
                "type": "port_scan",
                "tool": "naabu",
                "output": "naabu not available — skipped",
                "severity": "info",
            })

        return {"findings": findings, "info": info}

    async def _run_http_probe(self, target: str) -> Dict[str, Any]:
        """Probe HTTP/HTTPS services and detect technologies."""
        tool = self.registry.get_tool("nuclei")
        findings: List[Dict[str, Any]] = []

        if tool is not None:
            try:
                output = await tool.execute(target=target, templates="technologies")
                findings.append({
                    "type": "tech_detection",
                    "tool": "nuclei",
                    "output": output,
                    "severity": "info",
                })
            except Exception as exc:
                logger.debug("nuclei error: %s", exc)
        else:
            findings.append({
                "type": "tech_detection",
                "tool": "nuclei",
                "output": "nuclei not available — skipped",
                "severity": "info",
            })

        return {"findings": findings, "info": {}}

    async def _run_dir_fuzz(self, target: str) -> Dict[str, Any]:
        """Fuzz directories and files using ffuf."""
        tool = self.registry.get_tool("ffuf_fuzz_dirs")
        findings: List[Dict[str, Any]] = []

        if tool is not None:
            try:
                output = await tool.execute(url=target)
                findings.append({
                    "type": "dir_fuzzing",
                    "tool": "ffuf_fuzz_dirs",
                    "output": output,
                    "severity": "info",
                })
            except Exception as exc:
                logger.debug("ffuf_fuzz_dirs error: %s", exc)
        else:
            findings.append({
                "type": "dir_fuzzing",
                "tool": "ffuf_fuzz_dirs",
                "output": "ffuf not available — skipped",
                "severity": "info",
            })

        return {"findings": findings, "info": {}}

    async def _run_osint(self, target: str) -> Dict[str, Any]:
        """Collect OSINT via web search."""
        tool = self.registry.get_tool("web_search")
        findings: List[Dict[str, Any]] = []

        if tool is not None:
            try:
                output = await tool.execute(query=f"site:{target} OR \"{target}\" security")
                findings.append({
                    "type": "osint",
                    "tool": "web_search",
                    "output": output,
                    "severity": "info",
                })
            except Exception as exc:
                logger.debug("web_search error: %s", exc)
        else:
            findings.append({
                "type": "osint",
                "tool": "web_search",
                "output": "web_search not available — skipped",
                "severity": "info",
            })

        return {"findings": findings, "info": {}}


__all__ = ["ReconAgent"]
