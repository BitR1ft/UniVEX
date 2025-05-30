"""
PluginLoader — Discovers and loads plugins from a plugins/ directory.

Each plugin is a Python package (directory) with:
  - plugin.yaml (manifest)
  - __init__.py (must define a get_plugin() -> BasePlugin function)
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple, Type

import yaml

from app.plugins.base_plugin import BasePlugin, PluginManifest

logger = logging.getLogger(__name__)

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class PluginLoadError(Exception):
    """Raised when a plugin cannot be loaded."""


class PluginLoader:
    """Discovers and loads plugins from a directory on disk."""

    def __init__(self, plugins_dir: str = None) -> None:
        if plugins_dir is None:
            # Default: <repo_root>/plugins/
            self.plugins_dir = (
                Path(__file__).parent.parent.parent.parent / "plugins"
            )
        else:
            self.plugins_dir = Path(plugins_dir)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> List[Path]:
        """Return list of subdirectories that look like valid plugin packages."""
        if not self.plugins_dir.exists():
            return []
        candidates = []
        for entry in sorted(self.plugins_dir.iterdir()):
            if (
                entry.is_dir()
                and (entry / "plugin.yaml").exists()
                and (entry / "__init__.py").exists()
            ):
                candidates.append(entry)
        return candidates

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------

    def load_manifest(self, plugin_path: Path) -> PluginManifest:
        """Parse plugin.yaml and return a PluginManifest."""
        manifest_file = plugin_path / "plugin.yaml"
        try:
            with manifest_file.open() as fh:
                data = yaml.safe_load(fh)
        except Exception as exc:
            raise PluginLoadError(
                f"Cannot read plugin.yaml in {plugin_path}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise PluginLoadError(
                f"plugin.yaml in {plugin_path} is not a YAML mapping."
            )

        required = {"name", "version", "description", "author"}
        missing = required - data.keys()
        if missing:
            raise PluginLoadError(
                f"plugin.yaml in {plugin_path} is missing required fields: {missing}"
            )

        try:
            return PluginManifest.from_dict(data)
        except Exception as exc:
            raise PluginLoadError(
                f"Malformed plugin.yaml in {plugin_path}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_plugin(self, plugin_path: Path) -> BasePlugin:
        """
        Dynamically import the plugin package and call its get_plugin() factory.
        """
        manifest = self.load_manifest(plugin_path)
        # Sanitize plugin name to a valid Python identifier (replace hyphens, dots, etc.)
        safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in manifest.name)
        safe_version = manifest.version.replace(".", "_")
        package_name = f"_univex_plugin_{safe_name}_{safe_version}"

        init_file = plugin_path / "__init__.py"
        spec = importlib.util.spec_from_file_location(package_name, init_file)
        if spec is None or spec.loader is None:
            raise PluginLoadError(
                f"Cannot create module spec for plugin at {plugin_path}"
            )

        module = importlib.util.module_from_spec(spec)
        sys.modules[package_name] = module
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            raise PluginLoadError(
                f"Error importing plugin package at {plugin_path}: {exc}"
            ) from exc

        if not hasattr(module, "get_plugin"):
            raise PluginLoadError(
                f"Plugin at {plugin_path} has no get_plugin() function."
            )

        try:
            plugin = module.get_plugin()
        except Exception as exc:
            raise PluginLoadError(
                f"get_plugin() raised an error in {plugin_path}: {exc}"
            ) from exc

        if not isinstance(plugin, BasePlugin):
            raise PluginLoadError(
                f"get_plugin() in {plugin_path} did not return a BasePlugin instance."
            )

        return plugin

    def load_all(self) -> List[Tuple[Optional[BasePlugin], Optional[str]]]:
        """
        Load all discovered plugins.

        Returns a list of (plugin, error_or_None). Never raises — all errors
        are captured per plugin.
        """
        results: List[Tuple[BasePlugin, Optional[str]]] = []
        for plugin_path in self.discover():
            try:
                plugin = self.load_plugin(plugin_path)
                results.append((plugin, None))
                logger.info("Loaded plugin '%s' from %s", plugin.manifest.name, plugin_path)
            except Exception as exc:
                error = str(exc)
                logger.error("Failed to load plugin from %s: %s", plugin_path, error)
                results.append((None, error))
        return results

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_manifest(self, manifest: PluginManifest) -> List[str]:
        """
        Validate a manifest. Returns a list of error strings (empty = valid).
        """
        errors: List[str] = []
        if not manifest.name or not manifest.name.strip():
            errors.append("name must not be empty.")
        if not _SEMVER_RE.match(manifest.version or ""):
            errors.append(
                f"version '{manifest.version}' is not valid semver (expected x.y.z)."
            )
        if not manifest.description or not manifest.description.strip():
            errors.append("description must not be empty.")
        return errors

    # ------------------------------------------------------------------
    # In-process loading (for testing / runtime registration)
    # ------------------------------------------------------------------

    def load_from_dict(self, manifest_dict: dict, plugin_class: Type) -> BasePlugin:
        """
        Create a plugin instance from a manifest dict and a concrete class.
        Used for testing and in-process plugin registration.
        """
        PluginManifest.from_dict(manifest_dict)  # validate structure
        instance = plugin_class()
        if not isinstance(instance, BasePlugin):
            raise PluginLoadError(
                f"{plugin_class} is not a BasePlugin subclass."
            )
        return instance
