"""
Job Dispatcher — Local vs Remote Tool Execution Router

(safe: embedding, search, reporting) or ``remote`` (dangerous: exploit,
scan, shell) and routes accordingly.

Classification logic
--------------------
  ALWAYS_REMOTE  — tools that MUST run on the worker node for safety
  ALWAYS_LOCAL   — tools that MUST stay local (access DB / embeddings)
  DEFAULT        — tools not listed above are classified by phase:
                   EXPLOITATION → remote; INFORMATIONAL → local

The dispatcher integrates with ``WorkerClient`` for remote dispatch and
falls back to direct tool execution when the worker is unavailable.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, Optional, Set

from app.agent.state.agent_state import Phase

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------


class JobClassification(str, Enum):
    LOCAL = "local"
    REMOTE = "remote"


# Tools that are always delegated to the worker node regardless of phase
ALWAYS_REMOTE: Set[str] = frozenset({  # type: ignore[assignment]
    # Port scanning / network
    "naabu_scan",
    "port_scan",
    "domain_discovery",
    "http_probe",
    # Exploitation
    "exploit_execute",
    "metasploit_execute",
    "metasploit_session",
    "sqlmap_detect",
    "sqlmap_databases",
    "sqlmap_tables",
    "sqlmap_columns",
    "sqlmap_dump",
    # Post-exploitation
    "brute_force",
    "reverse_shell",
    "file_operations",
    "privilege_escalation",
    "system_enumeration",
    "session_manager",
    "linpeas",
    "winpeas",
    "pass_the_hash",
    "crackmapexec",
    "kerberoast",
    "asreproast",
    # Browser sandbox (runs in isolated container)
    "browser_navigate",
    "browser_screenshot",
    "browser_extract_text",
    "browser_click",
    "browser_fill_form",
    "browser_get_cookies",
    "browser_get_local_storage",
    # Vulnerability scanning
    "nuclei_scan",
    "nuclei_template_select",
    "nikto_scan",
    "ffuf_fuzz_dirs",
    "ffuf_fuzz_files",
    "ffuf_fuzz_params",
    "wpscan",
    "searchsploit",
})

# Tools that always stay on the main node (need database / LLM / embeddings)
ALWAYS_LOCAL: Set[str] = frozenset({  # type: ignore[assignment]
    "echo",
    "calculator",
    "query_graph",
    "web_search",
    "oob_generate_url",
    "oob_check",
    "oob_wait",
    "oob_stats",
    "sploitus_search",
    "duckduckgo_search",
    "google_search",
    "searxng_search",
    "perplexity_search",
    "traversaal_search",
    "attack_surface_query",
    "vulnerability_lookup",
    "exploit_search",
    "cve_lookup",
    "domain_discovery",
})


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class JobDispatcher:
    """
    Classifies tool calls as local or remote and dispatches them accordingly.

    Usage::

        dispatcher = JobDispatcher()
        result = await dispatcher.dispatch(
            tool_name="execute_naabu",
            server_name="naabu",
            params={"target": "10.0.0.1", "ports": "top-100"},
            phase=Phase.EXPLOITATION,
        )
    """

    def __init__(
        self,
        always_remote: Optional[Set[str]] = None,
        always_local: Optional[Set[str]] = None,
        worker_client: Optional[Any] = None,
        tool_registry: Optional[Any] = None,
    ) -> None:
        self._always_remote: Set[str] = always_remote or set(ALWAYS_REMOTE)
        self._always_local: Set[str] = always_local or set(ALWAYS_LOCAL)
        self._worker_client = worker_client
        self._tool_registry = tool_registry

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(
        self, tool_name: str, phase: Optional[Phase] = None
    ) -> JobClassification:
        """
        Classify *tool_name* as ``local`` or ``remote``.

        Priority:
          1. ALWAYS_LOCAL whitelist → local
          2. ALWAYS_REMOTE whitelist → remote
          3. Phase heuristic: EXPLOITATION → remote; others → local
        """
        if tool_name in self._always_local:
            return JobClassification.LOCAL
        if tool_name in self._always_remote:
            return JobClassification.REMOTE
        # Phase heuristic
        if phase == Phase.EXPLOITATION:
            return JobClassification.REMOTE
        return JobClassification.LOCAL

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def dispatch(
        self,
        tool_name: str,
        params: Dict[str, Any],
        phase: Optional[Phase] = None,
        server_name: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Dispatch a tool call to either the worker node or local execution.

        Returns a result dict compatible with ``WorkerJobResult``.
        """
        classification = self.classify(tool_name, phase)
        effective_server = server_name or self._guess_server(tool_name)

        logger.info(
            "JobDispatcher: tool=%s phase=%s classification=%s server=%s",
            tool_name, phase, classification.value, effective_server,
        )

        if classification == JobClassification.REMOTE:
            return await self._dispatch_remote(tool_name, effective_server, params, timeout)
        else:
            return await self._dispatch_local(tool_name, params, timeout)

    async def _dispatch_remote(
        self,
        tool_name: str,
        server_name: str,
        params: Dict[str, Any],
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        """Send job to the WorkerClient."""
        client = self._get_worker_client()
        return await client.execute(
            tool_name=tool_name,
            server_name=server_name,
            params=params,
            timeout=timeout,
        )

    async def _dispatch_local(
        self,
        tool_name: str,
        params: Dict[str, Any],
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        """Execute tool directly on the main node via ToolRegistry."""
        registry = self._get_tool_registry()
        if registry is None:
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": False,
                "error": "ToolRegistry not configured for local dispatch",
            }
        tool = registry.get_tool(tool_name)
        if tool is None:
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": False,
                "error": f"Tool '{tool_name}' not found in registry",
            }
        try:
            import asyncio as _asyncio
            if timeout:
                raw = await _asyncio.wait_for(tool.execute(**params), timeout=timeout)
            else:
                raw = await tool.execute(**params)
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": True,
                "result": raw,
                "error": None,
            }
        except Exception as exc:
            logger.error("JobDispatcher local execute error: %s", exc, exc_info=True)
            return {
                "job_id": "",
                "tool_name": tool_name,
                "success": False,
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_worker_client(self) -> Any:
        if self._worker_client is not None:
            return self._worker_client
        from app.worker.worker_client import get_client
        return get_client()

    def _get_tool_registry(self) -> Optional[Any]:
        if self._tool_registry is not None:
            return self._tool_registry
        try:
            from app.agent.tools.tool_registry import get_global_registry
            return get_global_registry()
        except Exception:
            return None

    @staticmethod
    def _guess_server(tool_name: str) -> str:
        """
        Heuristically map a tool name to its MCP server.

        This is used when ``server_name`` is not explicitly provided.
        """
        mapping = {
            "naabu": "naabu",
            "nuclei": "nuclei",
            "metasploit": "metasploit",
            "sqlmap": "sqlmap",
            "ffuf": "ffuf",
            "nikto": "nikto",
            "wpscan": "nikto",  # bundled with nikto server
            "searchsploit": "nikto",
            "brute_force": "cracker",
            "hash_crack": "cracker",
            "reverse_shell": "metasploit",
            "browser": "browser",
            "curl": "curl",
            "xss": "xss",
            "injection": "injection",
        }
        for key, server in mapping.items():
            if key in tool_name:
                return server
        return "kali-tools"

    # ------------------------------------------------------------------
    # Statistics / introspection
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return dispatcher configuration statistics."""
        return {
            "always_remote_count": len(self._always_remote),
            "always_local_count": len(self._always_local),
            "always_remote": sorted(self._always_remote),
            "always_local": sorted(self._always_local),
        }

    def add_remote_tool(self, tool_name: str) -> None:
        """Dynamically add a tool to the always-remote set."""
        self._always_remote.add(tool_name)
        self._always_local.discard(tool_name)

    def add_local_tool(self, tool_name: str) -> None:
        """Dynamically add a tool to the always-local set."""
        self._always_local.add(tool_name)
        self._always_remote.discard(tool_name)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_dispatcher: Optional[JobDispatcher] = None


def get_dispatcher() -> JobDispatcher:
    """Return (or lazily create) the module-level JobDispatcher singleton."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = JobDispatcher()
    return _dispatcher


__all__ = [
    "JobClassification",
    "JobDispatcher",
    "get_dispatcher",
    "ALWAYS_REMOTE",
    "ALWAYS_LOCAL",
]
