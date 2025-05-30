"""
PluginTool — Lightweight tool base class for use in plugins.

This is a minimal alternative to app.agent.tools.base_tool.BaseTool that
does not require the full LangChain / agent-tools dependency stack.  Plugin
tools that only need to be called by PluginManager can inherit from here;
tools that need deep LangGraph integration should subclass BaseTool directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class PluginToolMetadata:
    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)


class PluginTool(ABC):
    """
    Minimal abstract base for plugin-provided tools.

    Implements the same interface contract expected by PluginManager
    (name, execute) without pulling in LangChain dependencies.
    """

    def __init__(self) -> None:
        self._metadata = self._define_metadata()

    @abstractmethod
    def _define_metadata(self) -> PluginToolMetadata:
        """Return metadata describing this tool."""

    @abstractmethod
    async def execute(self, **kwargs) -> str:
        """Execute the tool and return a string result."""

    @property
    def name(self) -> str:
        return self._metadata.name

    @property
    def description(self) -> str:
        return self._metadata.description

    @property
    def metadata(self) -> PluginToolMetadata:
        return self._metadata
