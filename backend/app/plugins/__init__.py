"""
Plugin / Extension Architecture package for UniVex.

Public surface:
  BasePlugin, PluginRegistry, PluginLoader, PluginManager,
  SandboxedRunner, PluginManifest, PluginStatus
"""

from app.plugins.base_plugin import (
    BasePlugin,
    PluginInfo,
    PluginManifest,
    PluginStatus,
)
from app.plugins.plugin_loader import PluginLoadError, PluginLoader
from app.plugins.plugin_manager import PluginManager
from app.plugins.plugin_registry import PluginRegistry, get_global_plugin_registry
from app.plugins.plugin_tool import PluginTool, PluginToolMetadata
from app.plugins.sandboxed_runner import (
    ExecutionResult,
    SandboxConfig,
    SandboxedRunner,
    SandboxViolation,
)

__all__ = [
    "BasePlugin",
    "PluginInfo",
    "PluginManifest",
    "PluginStatus",
    "PluginLoadError",
    "PluginLoader",
    "PluginManager",
    "PluginRegistry",
    "get_global_plugin_registry",
    "PluginTool",
    "PluginToolMetadata",
    "ExecutionResult",
    "SandboxConfig",
    "SandboxedRunner",
    "SandboxViolation",
]
