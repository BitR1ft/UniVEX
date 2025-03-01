"""
Installer Agent — Tool Installation Guidance and Environment Setup

Manages tool installation guidance, dependency resolution, and environment
setup for penetration testing toolchains.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class OSType(str, Enum):
    """Supported operating system types."""

    KALI = "kali"
    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    CENTOS = "centos"
    ARCH = "arch"
    MACOS = "macos"
    WINDOWS = "windows"


class ToolStatus(str, Enum):
    """Installation status of a tool."""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    OUTDATED = "outdated"
    UNKNOWN = "unknown"


class InstallerAgent(BaseAgent):
    """
    Sub-agent for tool installation guidance and environment setup.

    Checks tool availability, provides installation instructions for each
    supported OS, and resolves dependency ordering for tool sets.
    """

    AGENT_NAME = "installer"
    PREFERRED_TOOLS: List[str] = ["web_search", "query_graph"]

    # Registry of common pentest tools and install commands per OS
    TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
        "nmap": {
            "description": "Network exploration and security auditing tool",
            "kali": "apt-get install -y nmap",
            "ubuntu": "apt-get install -y nmap",
            "debian": "apt-get install -y nmap",
            "centos": "yum install -y nmap",
            "arch": "pacman -S nmap",
            "macos": "brew install nmap",
            "windows": "choco install nmap",
            "verify": "nmap --version",
        },
        "naabu": {
            "description": "Fast port scanner by ProjectDiscovery",
            "kali": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "ubuntu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "debian": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "macos": "brew install naabu",
            "verify": "naabu -version",
        },
        "nuclei": {
            "description": "Fast and customisable vulnerability scanner",
            "kali": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "ubuntu": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "macos": "brew install nuclei",
            "verify": "nuclei -version",
        },
        "ffuf": {
            "description": "Web fuzzer",
            "kali": "apt-get install -y ffuf",
            "ubuntu": "go install github.com/ffuf/ffuf/v2@latest",
            "macos": "brew install ffuf",
            "verify": "ffuf -V",
        },
        "sqlmap": {
            "description": "Automatic SQL injection detection and exploitation",
            "kali": "apt-get install -y sqlmap",
            "ubuntu": "apt-get install -y sqlmap",
            "debian": "apt-get install -y sqlmap",
            "macos": "brew install sqlmap",
            "verify": "sqlmap --version",
        },
        "metasploit": {
            "description": "Penetration testing framework",
            "kali": "apt-get install -y metasploit-framework",
            "ubuntu": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
            "macos": "brew install metasploit",
            "verify": "msfconsole --version",
        },
        "burpsuite": {
            "description": "Web application security testing platform",
            "kali": "apt-get install -y burpsuite",
            "ubuntu": "Download from https://portswigger.net/burp/releases",
            "macos": "brew install --cask burp-suite",
            "verify": "burpsuite --version",
        },
        "nikto": {
            "description": "Web server scanner",
            "kali": "apt-get install -y nikto",
            "ubuntu": "apt-get install -y nikto",
            "debian": "apt-get install -y nikto",
            "macos": "brew install nikto",
            "verify": "nikto -Version",
        },
        "searchsploit": {
            "description": "Exploit database search tool",
            "kali": "apt-get install -y exploitdb",
            "ubuntu": "apt-get install -y exploitdb",
            "macos": "brew install exploitdb",
            "verify": "searchsploit --version",
        },
        "john": {
            "description": "Password cracker (John the Ripper)",
            "kali": "apt-get install -y john",
            "ubuntu": "apt-get install -y john",
            "macos": "brew install john",
            "verify": "john --version",
        },
        "hashcat": {
            "description": "Advanced password recovery",
            "kali": "apt-get install -y hashcat",
            "ubuntu": "apt-get install -y hashcat",
            "macos": "brew install hashcat",
            "verify": "hashcat --version",
        },
        "gobuster": {
            "description": "Directory/file/DNS/vhost busting tool",
            "kali": "apt-get install -y gobuster",
            "ubuntu": "go install github.com/OJ/gobuster/v3@latest",
            "macos": "brew install gobuster",
            "verify": "gobuster version",
        },
        "enum4linux": {
            "description": "SMB enumeration tool",
            "kali": "apt-get install -y enum4linux",
            "ubuntu": "apt-get install -y enum4linux",
            "verify": "enum4linux --help",
        },
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
        return Phase.INFORMATIONAL

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the Installer Agent, an expert in penetration testing "
            "tool installation and environment configuration.\n\n"
            "Your responsibilities:\n"
            "  1. Check which tools are currently available in the environment.\n"
            "  2. Provide OS-specific installation guides for missing tools.\n"
            "  3. Resolve dependency ordering for tool installation.\n"
            "  4. Verify installed tool versions and configurations.\n"
            "  5. Recommend optimal tool sets for different engagement types.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "Return structured installation guidance with commands, "
            "dependencies, and verification steps."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Check environment and return installation guidance.

        Args:
            state: Shared multi-agent state.
            task:  Tool name(s) or general setup description.

        Returns:
            ``{"agent": "installer", "tool_statuses": dict,
               "installation_guides": list, "recommendations": list}``
        """
        target_info = state.get("target_info") or {}
        os_type_str = target_info.get("os_type", "kali")
        logger.info("InstallerAgent checking environment for task: %s", task[:80])

        # Parse requested tools from the task
        requested_tools = self._extract_tools_from_task(task)
        if not requested_tools:
            requested_tools = ["nmap", "nuclei", "ffuf", "sqlmap"]

        os_type = self._parse_os_type(os_type_str)
        tool_statuses: Dict[str, Any] = {}
        installation_guides: List[Dict[str, Any]] = []

        for tool_name in requested_tools:
            status = self.check_tool(tool_name)
            tool_statuses[tool_name] = status

            if status["status"] in (ToolStatus.NOT_INSTALLED.value, ToolStatus.UNKNOWN.value):
                guide = self.get_installation_guide(tool_name, os_type)
                installation_guides.append(guide)

        dependency_info = self.resolve_dependencies(requested_tools)

        return {
            "agent": self.AGENT_NAME,
            "tool_statuses": tool_statuses,
            "installation_guides": installation_guides,
            "dependency_resolution": dependency_info,
            "recommendations": self._get_recommendations(os_type),
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def check_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Check whether a tool is installed in the current environment.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            Dict with ``status``, ``version``, ``path``.
        """
        import shutil

        path = shutil.which(tool_name)

        if path is not None:
            return {
                "status": ToolStatus.INSTALLED.value,
                "version": "unknown",
                "path": path,
                "tool": tool_name,
            }

        return {
            "status": ToolStatus.NOT_INSTALLED.value,
            "version": None,
            "path": None,
            "tool": tool_name,
        }

    def get_installation_guide(
        self,
        tool_name: str,
        os_type: OSType,
    ) -> Dict[str, Any]:
        """
        Return an installation guide for the given tool and OS.

        Args:
            tool_name: Tool to install.
            os_type:   Target operating system.

        Returns:
            Dict with ``tool``, ``commands``, ``dependencies``,
            ``verification``.
        """
        os_key = os_type.value if isinstance(os_type, OSType) else str(os_type)
        tool_info = self.TOOL_REGISTRY.get(tool_name, {})

        command = tool_info.get(os_key) or tool_info.get("ubuntu", "Not available for this OS")
        verify = tool_info.get("verify", f"{tool_name} --version")

        return {
            "tool": tool_name,
            "description": tool_info.get("description", "Penetration testing tool"),
            "commands": [command] if command else [],
            "dependencies": self._get_dependencies(tool_name),
            "verification": verify,
            "os": os_key,
        }

    def resolve_dependencies(self, tool_list: List[str]) -> Dict[str, Any]:
        """
        Resolve installation dependencies and order for a list of tools.

        Args:
            tool_list: List of tool names to install.

        Returns:
            Dict with ``install_order``, ``commands``, ``dependency_map``.
        """
        # Simple dependency map for common tools
        dep_map: Dict[str, List[str]] = {
            "naabu": ["go"],
            "nuclei": ["go"],
            "ffuf": ["go"],
            "gobuster": ["go"],
            "metasploit": ["ruby"],
            "searchsploit": ["git"],
        }

        # Determine prerequisites
        prerequisites: List[str] = []
        for tool in tool_list:
            deps = dep_map.get(tool, [])
            for dep in deps:
                if dep not in prerequisites and dep not in tool_list:
                    prerequisites.append(dep)

        install_order = prerequisites + [t for t in tool_list if t not in prerequisites]

        return {
            "install_order": install_order,
            "commands": [f"Install {t}" for t in install_order],
            "dependency_map": {t: dep_map.get(t, []) for t in tool_list},
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_tools_from_task(self, task: str) -> List[str]:
        """Extract tool names mentioned in the task description."""
        known_tools = list(self.TOOL_REGISTRY.keys())
        return [t for t in known_tools if t in task.lower()]

    def _parse_os_type(self, os_str: str) -> OSType:
        """Parse OS type string to OSType enum."""
        try:
            return OSType(os_str.lower())
        except ValueError:
            return OSType.KALI

    def _get_dependencies(self, tool_name: str) -> List[str]:
        """Return known system-level dependencies for a tool."""
        dep_map: Dict[str, List[str]] = {
            "naabu": ["go >= 1.21"],
            "nuclei": ["go >= 1.21"],
            "ffuf": ["go >= 1.21"],
            "gobuster": ["go >= 1.21"],
            "metasploit": ["ruby >= 3.0", "postgresql"],
            "sqlmap": ["python3"],
            "searchsploit": ["git"],
        }
        return dep_map.get(tool_name, [])

    def _get_recommendations(self, os_type: OSType) -> List[str]:
        """Return general setup recommendations for the OS."""
        base = [
            "Keep all tools updated regularly.",
            "Use a dedicated penetration testing VM or container.",
            "Document tool versions in your engagement report.",
        ]
        if os_type == OSType.KALI:
            base.insert(0, "Run 'apt-get update && apt-get upgrade' before starting.")
        elif os_type == OSType.MACOS:
            base.insert(0, "Ensure Homebrew is up to date: 'brew update && brew upgrade'.")
        return base


__all__ = ["InstallerAgent", "OSType", "ToolStatus"]
