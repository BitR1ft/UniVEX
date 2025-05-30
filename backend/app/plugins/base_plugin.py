"""
BasePlugin — Abstract base class for UniVex plugins.
All community and built-in plugins must subclass BasePlugin.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class PluginStatus(str, Enum):
    UNLOADED = "unloaded"
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class PluginManifest:
    name: str
    version: str
    description: str
    author: str
    license: str = "MIT"
    min_univex_version: str = "1.0.0"
    tags: List[str] = field(default_factory=list)
    homepage: str = ""
    dependencies: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "PluginManifest":
        return cls(
            name=data["name"],
            version=data["version"],
            description=data["description"],
            author=data["author"],
            license=data.get("license", "MIT"),
            min_univex_version=data.get("min_univex_version", "1.0.0"),
            tags=data.get("tags", []),
            homepage=data.get("homepage", ""),
            dependencies=data.get("dependencies", []),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "min_univex_version": self.min_univex_version,
            "tags": self.tags,
            "homepage": self.homepage,
            "dependencies": self.dependencies,
        }


@dataclass
class PluginInfo:
    manifest: PluginManifest
    status: PluginStatus = PluginStatus.UNLOADED
    plugin_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    load_error: Optional[str] = None
    loaded_at: Optional[datetime] = None
    path: Optional[str] = None


class BasePlugin(ABC):
    """
    Abstract base class for all UniVex plugins.

    Subclasses must implement:
      - manifest (property)
      - register_tools()
      - register_mcp_servers()
      - register_api_routes()
    """

    @property
    @abstractmethod
    def manifest(self) -> PluginManifest:
        """Plugin manifest describing metadata."""

    @abstractmethod
    def register_tools(self) -> List[Any]:
        """Return list of BaseTool instances provided by this plugin."""

    @abstractmethod
    def register_mcp_servers(self) -> List[Dict[str, Any]]:
        """Return MCP server configs: [{"name": str, "host": str, "port": int}]."""

    @abstractmethod
    def register_api_routes(self) -> List[Any]:
        """Return list of FastAPI APIRouter instances provided by this plugin."""

    # Lifecycle hooks — no-op defaults, subclasses may override

    def on_load(self) -> None:
        """Called when the plugin is loaded."""

    def on_unload(self) -> None:
        """Called when the plugin is unloaded."""

    def on_enable(self) -> None:
        """Called when the plugin is enabled."""

    def on_disable(self) -> None:
        """Called when the plugin is disabled."""

    @property
    def plugin_id(self) -> str:
        """Unique identifier derived from name + version."""
        return f"{self.manifest.name}-{self.manifest.version}"

    def get_info(self) -> PluginInfo:
        """Return a PluginInfo snapshot for this plugin."""
        return PluginInfo(
            manifest=self.manifest,
            plugin_id=self.plugin_id,
        )

    def health_check(self) -> Dict[str, Any]:
        """Return basic health status. Override for custom health logic."""
        return {"healthy": True, "message": "OK"}
