"""
PluginRegistry — Central registry for all loaded plugins with lifecycle management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.plugins.base_plugin import BasePlugin, PluginStatus

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Central registry for all loaded plugins with lifecycle management."""

    def __init__(self) -> None:
        self._plugins: Dict[str, BasePlugin] = {}
        self._statuses: Dict[str, PluginStatus] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, plugin: BasePlugin) -> str:
        """
        Register a plugin.

        Returns the plugin_id. Raises ValueError if a plugin with the same
        name + version is already registered.
        """
        pid = plugin.plugin_id
        for existing in self._plugins.values():
            m = existing.manifest
            if m.name == plugin.manifest.name and m.version == plugin.manifest.version:
                raise ValueError(
                    f"Plugin '{plugin.manifest.name}' v{plugin.manifest.version} "
                    "is already registered."
                )
        self._plugins[pid] = plugin
        self._statuses[pid] = PluginStatus.LOADED
        plugin.on_load()
        logger.info("Registered plugin '%s' (id=%s)", plugin.manifest.name, pid)
        return pid

    def unregister(self, plugin_id: str) -> None:
        """Unregister and unload a plugin. Raises KeyError if not found."""
        if plugin_id not in self._plugins:
            raise KeyError(f"Plugin '{plugin_id}' not found in registry.")
        plugin = self._plugins.pop(plugin_id)
        self._statuses.pop(plugin_id, None)
        plugin.on_unload()
        logger.info("Unregistered plugin '%s' (id=%s)", plugin.manifest.name, plugin_id)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, plugin_id: str) -> Optional[BasePlugin]:
        return self._plugins.get(plugin_id)

    def get_by_name(self, name: str) -> Optional[BasePlugin]:
        for p in self._plugins.values():
            if p.manifest.name == name:
                return p
        return None

    def list_all(self) -> List[BasePlugin]:
        return list(self._plugins.values())

    def list_enabled(self) -> List[BasePlugin]:
        return [
            p for pid, p in self._plugins.items()
            if self._statuses.get(pid) == PluginStatus.ENABLED
        ]

    def list_by_tag(self, tag: str) -> List[BasePlugin]:
        return [p for p in self._plugins.values() if tag in p.manifest.tags]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def enable(self, plugin_id: str) -> None:
        if plugin_id not in self._plugins:
            raise KeyError(f"Plugin '{plugin_id}' not found in registry.")
        self._statuses[plugin_id] = PluginStatus.ENABLED
        self._plugins[plugin_id].on_enable()
        logger.info("Enabled plugin '%s'", plugin_id)

    def disable(self, plugin_id: str) -> None:
        if plugin_id not in self._plugins:
            raise KeyError(f"Plugin '{plugin_id}' not found in registry.")
        self._statuses[plugin_id] = PluginStatus.DISABLED
        self._plugins[plugin_id].on_disable()
        logger.info("Disabled plugin '%s'", plugin_id)

    def get_status(self, plugin_id: str) -> PluginStatus:
        if plugin_id not in self._statuses:
            raise KeyError(f"Plugin '{plugin_id}' not found in registry.")
        return self._statuses[plugin_id]

    # ------------------------------------------------------------------
    # Aggregated resource access
    # ------------------------------------------------------------------

    def get_all_tools(self) -> List[Any]:
        tools = []
        for p in self.list_enabled():
            tools.extend(p.register_tools())
        return tools

    def get_all_mcp_servers(self) -> List[Dict[str, Any]]:
        servers: List[Dict[str, Any]] = []
        for p in self.list_enabled():
            servers.extend(p.register_mcp_servers())
        return servers

    def get_all_routes(self) -> List[Any]:
        routes: List[Any] = []
        for p in self.list_enabled():
            routes.extend(p.register_api_routes())
        return routes

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> List[Dict]:
        result = []
        for pid, plugin in self._plugins.items():
            info = plugin.get_info()
            info.status = self._statuses.get(pid, PluginStatus.LOADED)
            result.append(
                {
                    "plugin_id": pid,
                    "name": plugin.manifest.name,
                    "version": plugin.manifest.version,
                    "description": plugin.manifest.description,
                    "author": plugin.manifest.author,
                    "tags": plugin.manifest.tags,
                    "status": info.status.value,
                    "load_error": info.load_error,
                    "loaded_at": info.loaded_at.isoformat() if info.loaded_at else None,
                    "path": info.path,
                }
            )
        return result

    def count(self) -> int:
        return len(self._plugins)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_global_registry: Optional[PluginRegistry] = None


def get_global_plugin_registry() -> PluginRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry
