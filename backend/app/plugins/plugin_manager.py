"""
PluginManager — High-level orchestrator for the plugin lifecycle.

Integrates PluginLoader + PluginRegistry + SandboxedRunner.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.plugins.base_plugin import BasePlugin
from app.plugins.plugin_loader import PluginLoader
from app.plugins.plugin_registry import PluginRegistry
from app.plugins.sandboxed_runner import ExecutionResult, SandboxConfig, SandboxedRunner

logger = logging.getLogger(__name__)


class PluginManager:
    """High-level orchestrator: PluginLoader + PluginRegistry + SandboxedRunner."""

    def __init__(
        self,
        plugins_dir: str = None,
        sandbox_config: SandboxConfig = None,
    ) -> None:
        self._loader = PluginLoader(plugins_dir=plugins_dir)
        self._registry = PluginRegistry()
        self._runner = SandboxedRunner(config=sandbox_config)

    # ------------------------------------------------------------------
    # Discovery & bulk loading
    # ------------------------------------------------------------------

    def discover_and_load(self) -> Dict[str, Any]:
        """
        Load all plugins from the plugins directory, register and enable them.

        Returns a summary dict: {"loaded": N, "failed": N, "plugins": [...]}.
        """
        loaded_count = 0
        failed_count = 0
        plugin_summaries: List[Dict] = []

        for plugin, error in self._loader.load_all():
            if error is not None or plugin is None:
                failed_count += 1
                plugin_summaries.append({"status": "failed", "error": error})
                continue
            try:
                pid = self._registry.register(plugin)
                self._registry.enable(pid)
                loaded_count += 1
                plugin_summaries.append(
                    {
                        "plugin_id": pid,
                        "name": plugin.manifest.name,
                        "version": plugin.manifest.version,
                        "status": "enabled",
                    }
                )
            except Exception as exc:
                failed_count += 1
                plugin_summaries.append(
                    {
                        "name": getattr(plugin.manifest, "name", "unknown"),
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        return {"loaded": loaded_count, "failed": failed_count, "plugins": plugin_summaries}

    # ------------------------------------------------------------------
    # Individual plugin lifecycle
    # ------------------------------------------------------------------

    def install_plugin(self, plugin: BasePlugin) -> str:
        """Register and enable a plugin. Returns plugin_id."""
        pid = self._registry.register(plugin)
        self._registry.enable(pid)
        logger.info("Installed plugin '%s' (id=%s)", plugin.manifest.name, pid)
        return pid

    def uninstall_plugin(self, plugin_id: str) -> None:
        """Disable and unregister a plugin."""
        try:
            self._registry.disable(plugin_id)
        except Exception:
            pass
        self._registry.unregister(plugin_id)
        logger.info("Uninstalled plugin '%s'", plugin_id)

    def enable_plugin(self, plugin_id: str) -> None:
        self._registry.enable(plugin_id)

    def disable_plugin(self, plugin_id: str) -> None:
        self._registry.disable(plugin_id)

    # ------------------------------------------------------------------
    # Info / listing
    # ------------------------------------------------------------------

    def get_plugin_info(self, plugin_id: str) -> Optional[Dict]:
        plugin = self._registry.get(plugin_id)
        if plugin is None:
            return None
        info = plugin.get_info()
        info.status = self._registry.get_status(plugin_id)
        return {
            "plugin_id": plugin_id,
            "name": plugin.manifest.name,
            "version": plugin.manifest.version,
            "description": plugin.manifest.description,
            "author": plugin.manifest.author,
            "tags": plugin.manifest.tags,
            "status": info.status.value,
            "load_error": info.load_error,
            "loaded_at": info.loaded_at.isoformat() if info.loaded_at else None,
        }

    def list_plugins(self) -> List[Dict]:
        return self._registry.to_dict()

    # ------------------------------------------------------------------
    # Tool execution in sandbox
    # ------------------------------------------------------------------

    def run_plugin_tool(
        self,
        plugin_id: str,
        tool_name: str,
        tool_input: Dict,
    ) -> ExecutionResult:
        """Find a named tool from a plugin and run it inside the sandbox."""
        plugin = self._registry.get(plugin_id)
        if plugin is None:
            return ExecutionResult(
                success=False,
                output="",
                error=f"Plugin '{plugin_id}' not found.",
            )

        tools = {t.name: t for t in plugin.register_tools() if hasattr(t, "name")}
        tool = tools.get(tool_name)
        if tool is None:
            return ExecutionResult(
                success=False,
                output="",
                error=f"Tool '{tool_name}' not found in plugin '{plugin_id}'.",
            )

        import asyncio

        def _run_tool():
            try:
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(tool.execute(**tool_input))
                loop.close()
                return result
            except Exception as exc:
                raise exc

        return self._runner.run(_run_tool)

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    def health_check_all(self) -> Dict[str, Any]:
        """Call health_check() on every enabled plugin."""
        results: Dict[str, Any] = {}
        for plugin in self._registry.list_enabled():
            try:
                results[plugin.plugin_id] = plugin.health_check()
            except Exception as exc:
                results[plugin.plugin_id] = {"healthy": False, "error": str(exc)}
        return results

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_registry(self) -> PluginRegistry:
        return self._registry

    def get_loader(self) -> PluginLoader:
        return self._loader
