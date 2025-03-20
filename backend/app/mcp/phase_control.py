"""
Phase Restriction Implementation

Provides RBAC (role-based access control) for MCP tools based on the current
agent phase.  The system has four phases:

  1. ``recon``    — passive / active reconnaissance
  2. ``scan``     — service detection, vulnerability scanning
  3. ``exploit``  — active exploitation (requires human approval for most tools)
  4. ``post``     — post-exploitation, lateral movement, data collection

Each phase has an ``ALLOWED_TOOLS`` set and a ``REQUIRE_APPROVAL_FOR`` set.

Public API
----------
``PhaseAccessController``   — validates tool access per phase
``PhaseRestrictionMiddleware`` — wraps MCPServer.execute_tool to enforce rules
``get_phase_permissions``   — inspect the permission table
``PHASE_PERMISSIONS``       — the raw permission table (for testing / docs)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase permission table
# ---------------------------------------------------------------------------

@dataclass
class PhasePermission:
    """Permission rules for a single agent phase."""
    phase: str
    allowed_tools: Set[str] = field(default_factory=set)
    require_approval_for: Set[str] = field(default_factory=set)
    description: str = ""


#: Canonical set of all known MCP tool names
ALL_TOOLS: Set[str] = {
    # Naabu
    "execute_naabu",
    # Nuclei
    "execute_nuclei", "list_templates", "get_template_info",
    # Curl
    "execute_curl",
    # Metasploit
    "search_modules", "get_module_info", "execute_module",
    "list_sessions", "session_command",
    # Graph
    "query_graph_cypher", "get_attack_surface", "find_attack_paths", "get_vulnerabilities",
    # Web search
    "web_search", "search_cve", "search_exploits", "enrich_technology",
}

PHASE_PERMISSIONS: Dict[str, PhasePermission] = {
    "recon": PhasePermission(
        phase="recon",
        description="Passive + active reconnaissance; no exploitation allowed",
        allowed_tools={
            "execute_naabu",
            "execute_curl",
            "web_search",
            "search_cve",
            "enrich_technology",
            "get_attack_surface",
            "query_graph_cypher",
        },
        require_approval_for=set(),  # no approvals needed in recon
    ),
    "scan": PhasePermission(
        phase="scan",
        description="Vulnerability scanning; no exploitation allowed",
        allowed_tools={
            "execute_naabu",
            "execute_nuclei",
            "list_templates",
            "get_template_info",
            "execute_curl",
            "web_search",
            "search_cve",
            "enrich_technology",
            "get_attack_surface",
            "find_attack_paths",
            "get_vulnerabilities",
            "query_graph_cypher",
        },
        require_approval_for={
            "execute_nuclei",  # scanning with templates — approval recommended
        },
    ),
    "exploit": PhasePermission(
        phase="exploit",
        description="Active exploitation; most offensive tools require approval",
        allowed_tools=ALL_TOOLS,  # all tools available
        require_approval_for={
            "execute_module",
            "session_command",
            "search_exploits",
        },
    ),
    "post": PhasePermission(
        phase="post",
        description="Post-exploitation / lateral movement; destructive ops require approval",
        allowed_tools=ALL_TOOLS,
        require_approval_for={
            "execute_module",
            "session_command",
        },
    ),
}


# ---------------------------------------------------------------------------
# Phase Access Controller
# ---------------------------------------------------------------------------

class PhaseAccessController:
    """
    Validates MCP tool access for the current agent phase.

    Usage::

        controller = PhaseAccessController("recon")
        controller.check_access("execute_naabu")    # → None (allowed)
        controller.check_access("execute_module")   # → raises PermissionError
    """

    def __init__(self, phase: str) -> None:
        if phase not in PHASE_PERMISSIONS:
            raise ValueError(
                f"Unknown phase '{phase}'. Valid phases: {list(PHASE_PERMISSIONS)}"
            )
        self._phase = phase
        self._perms = PHASE_PERMISSIONS[phase]

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def allowed_tools(self) -> Set[str]:
        return self._perms.allowed_tools

    @property
    def approval_required_tools(self) -> Set[str]:
        return self._perms.require_approval_for

    def is_allowed(self, tool_name: str) -> bool:
        """Return True if *tool_name* is allowed in the current phase."""
        return tool_name in self._perms.allowed_tools

    def requires_approval(self, tool_name: str) -> bool:
        """Return True if *tool_name* needs human approval before execution."""
        return tool_name in self._perms.require_approval_for

    def check_access(self, tool_name: str) -> None:
        """
        Raise ``PermissionError`` if *tool_name* is not allowed in this phase.

        This is the primary enforcement point; call it before executing any tool.
        """
        if not self.is_allowed(tool_name):
            raise PermissionError(
                f"Tool '{tool_name}' is not allowed in the '{self._phase}' phase. "
                f"Allowed tools: {sorted(self._perms.allowed_tools)}"
            )

    def get_access_report(self) -> Dict[str, Any]:
        """Return a summary dict for the current phase permissions."""
        return {
            "phase": self._phase,
            "description": self._perms.description,
            "allowed_tools": sorted(self._perms.allowed_tools),
            "require_approval_for": sorted(self._perms.require_approval_for),
        }


# ---------------------------------------------------------------------------
# Phase Restriction Middleware
# ---------------------------------------------------------------------------

class PhaseRestrictionMiddleware:
    """
    Wraps an MCPServer's ``execute_tool`` method to enforce phase restrictions.

    Decorating pattern: call ``wrap(server)`` once after construction.  The
    server's ``execute_tool`` is replaced with a guarded version.

    Example::

        server = NaabuServer()
        middleware = PhaseRestrictionMiddleware(phase="recon")
        middleware.wrap(server)
    """

    def __init__(self, phase: str) -> None:
        self._controller = PhaseAccessController(phase)
        self._original_execute: Optional[Callable] = None

    @property
    def phase(self) -> str:
        return self._controller.phase

    @property
    def controller(self) -> PhaseAccessController:
        return self._controller

    def wrap(self, server: Any) -> None:
        """
        Replace *server*.execute_tool with a phase-checked version.

        Args:
            server: Any MCPServer subclass instance.
        """
        self._original_execute = server.execute_tool

        controller = self._controller
        original = self._original_execute

        async def _guarded_execute(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
            controller.check_access(tool_name)  # raises PermissionError if blocked
            return await original(tool_name, params)

        server.execute_tool = _guarded_execute
        logger.info(
            "PhaseRestrictionMiddleware applied: server=%s phase=%s",
            getattr(server, "name", type(server).__name__),
            self._controller.phase,
        )

    def unwrap(self, server: Any) -> None:
        """
        Restore the original execute_tool on *server*.

        Args:
            server: The same MCPServer instance that was previously wrapped.
        """
        if self._original_execute is not None:
            server.execute_tool = self._original_execute
            self._original_execute = None


# ---------------------------------------------------------------------------
# Helper: inspect permission table
# ---------------------------------------------------------------------------

def get_phase_permissions(phase: Optional[str] = None) -> Dict[str, Any]:
    """
    Return permission information for one or all phases.

    Args:
        phase: Phase name to inspect, or None to return all phases.

    Returns:
        Dict with phase name(s) → permission details.
    """
    if phase is not None:
        if phase not in PHASE_PERMISSIONS:
            raise ValueError(f"Unknown phase '{phase}'")
        perms = PHASE_PERMISSIONS[phase]
        return {
            "phase": perms.phase,
            "description": perms.description,
            "allowed_tools": sorted(perms.allowed_tools),
            "require_approval_for": sorted(perms.require_approval_for),
        }

    return {
        name: {
            "description": perms.description,
            "allowed_count": len(perms.allowed_tools),
            "allowed_tools": sorted(perms.allowed_tools),
            "require_approval_for": sorted(perms.require_approval_for),
        }
        for name, perms in PHASE_PERMISSIONS.items()
    }


def validate_tool_phase(tool_name: str, phase: str) -> bool:
    """
    Convenience function: check whether *tool_name* is permitted in *phase*.

    Does not raise — returns a bool.
    """
    try:
        perms = PHASE_PERMISSIONS[phase]
        return tool_name in perms.allowed_tools
    except KeyError:
        return False
