"""
Tests for Day 10 — Plugin / Extension Architecture.

Covers:
  TestPluginManifest (8 tests)
  TestBasePlugin (8 tests)
  TestPluginRegistry (12 tests)
  TestPluginLoader (8 tests)
  TestSandboxedRunner (8 tests)
  TestPluginManager (8 tests)
  TestExamplePlugins (6 tests)

Total: 80 tests
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from app.plugins.base_plugin import (
    BasePlugin,
    PluginInfo,
    PluginManifest,
    PluginStatus,
)
from app.plugins.plugin_loader import PluginLoadError, PluginLoader
from app.plugins.plugin_manager import PluginManager
from app.plugins.plugin_registry import PluginRegistry, get_global_plugin_registry
from app.plugins.sandboxed_runner import (
    ExecutionResult,
    SandboxConfig,
    SandboxedRunner,
    SandboxViolation,
)


# ---------------------------------------------------------------------------
# Helpers / concrete plugin for testing
# ---------------------------------------------------------------------------

def _make_manifest(**overrides) -> PluginManifest:
    defaults = dict(
        name="test-plugin",
        version="1.2.3",
        description="A test plugin",
        author="Tester",
    )
    defaults.update(overrides)
    return PluginManifest(**defaults)


class ConcretePlugin(BasePlugin):
    """Minimal concrete plugin for testing."""

    def __init__(self, name="test-plugin", version="1.2.3"):
        self._manifest = PluginManifest(
            name=name,
            version=version,
            description="A test plugin",
            author="Tester",
            tags=["test", "example"],
        )
        self.load_called = False
        self.unload_called = False
        self.enable_called = False
        self.disable_called = False

    @property
    def manifest(self) -> PluginManifest:
        return self._manifest

    def register_tools(self) -> List[Any]:
        return []

    def register_mcp_servers(self) -> List[Dict[str, Any]]:
        return [{"name": "test-mcp", "host": "localhost", "port": 9999}]

    def register_api_routes(self) -> List[Any]:
        return []

    def on_load(self) -> None:
        self.load_called = True

    def on_unload(self) -> None:
        self.unload_called = True

    def on_enable(self) -> None:
        self.enable_called = True

    def on_disable(self) -> None:
        self.disable_called = True


# Minimal stub tool for PluginManager tool-execution tests
class StubTool:
    name = "stub_tool"

    async def execute(self, **kwargs):
        return f"stub output: {kwargs}"


class PluginWithTool(ConcretePlugin):
    def register_tools(self):
        return [StubTool()]


# ---------------------------------------------------------------------------
# TestPluginManifest
# ---------------------------------------------------------------------------


class TestPluginManifest:

    def test_from_dict_required_fields(self):
        data = {"name": "myplugin", "version": "2.0.0", "description": "desc", "author": "me"}
        m = PluginManifest.from_dict(data)
        assert m.name == "myplugin"
        assert m.version == "2.0.0"
        assert m.author == "me"

    def test_from_dict_defaults(self):
        data = {"name": "x", "version": "0.1.0", "description": "d", "author": "a"}
        m = PluginManifest.from_dict(data)
        assert m.license == "MIT"
        assert m.min_univex_version == "1.0.0"
        assert m.tags == []
        assert m.homepage == ""
        assert m.dependencies == []

    def test_from_dict_optional_fields(self):
        data = {
            "name": "x", "version": "1.0.0", "description": "d", "author": "a",
            "license": "Apache-2.0",
            "tags": ["recon", "osint"],
            "homepage": "https://example.com",
            "dependencies": ["requests>=2.0"],
        }
        m = PluginManifest.from_dict(data)
        assert m.license == "Apache-2.0"
        assert "recon" in m.tags
        assert m.homepage == "https://example.com"
        assert "requests>=2.0" in m.dependencies

    def test_to_dict_roundtrip(self):
        m = _make_manifest(tags=["a", "b"], homepage="https://x.com")
        d = m.to_dict()
        m2 = PluginManifest.from_dict(d)
        assert m.name == m2.name
        assert m.version == m2.version
        assert m.tags == m2.tags
        assert m.homepage == m2.homepage

    def test_to_dict_has_all_keys(self):
        m = _make_manifest()
        d = m.to_dict()
        expected_keys = {
            "name", "version", "description", "author",
            "license", "min_univex_version", "tags", "homepage", "dependencies",
        }
        assert expected_keys.issubset(d.keys())

    def test_from_dict_missing_required_raises(self):
        with pytest.raises(KeyError):
            PluginManifest.from_dict({"name": "x"})

    def test_tags_default_is_independent(self):
        m1 = _make_manifest()
        m2 = _make_manifest()
        m1.tags.append("tag1")
        assert "tag1" not in m2.tags

    def test_dependencies_default_is_independent(self):
        m1 = _make_manifest()
        m2 = _make_manifest()
        m1.dependencies.append("dep1")
        assert "dep1" not in m2.dependencies


# ---------------------------------------------------------------------------
# TestBasePlugin
# ---------------------------------------------------------------------------


class TestBasePlugin:

    def test_concrete_plugin_instantiates(self):
        p = ConcretePlugin()
        assert p is not None

    def test_plugin_id_format(self):
        p = ConcretePlugin(name="myplugin", version="2.3.4")
        assert p.plugin_id == "myplugin-2.3.4"

    def test_manifest_property(self):
        p = ConcretePlugin()
        assert isinstance(p.manifest, PluginManifest)
        assert p.manifest.name == "test-plugin"

    def test_health_check_default(self):
        p = ConcretePlugin()
        result = p.health_check()
        assert result["healthy"] is True
        assert result["message"] == "OK"

    def test_get_info_returns_plugin_info(self):
        p = ConcretePlugin()
        info = p.get_info()
        assert isinstance(info, PluginInfo)
        assert info.manifest.name == "test-plugin"

    def test_lifecycle_hooks_called(self):
        p = ConcretePlugin()
        registry = PluginRegistry()
        pid = registry.register(p)
        assert p.load_called
        registry.enable(pid)
        assert p.enable_called
        registry.disable(pid)
        assert p.disable_called
        registry.unregister(pid)
        assert p.unload_called

    def test_register_tools_returns_list(self):
        p = ConcretePlugin()
        assert isinstance(p.register_tools(), list)

    def test_register_mcp_servers_returns_list(self):
        p = ConcretePlugin()
        servers = p.register_mcp_servers()
        assert isinstance(servers, list)
        assert servers[0]["name"] == "test-mcp"


# ---------------------------------------------------------------------------
# TestPluginRegistry
# ---------------------------------------------------------------------------


class TestPluginRegistry:

    def _registry(self) -> PluginRegistry:
        return PluginRegistry()

    def test_register_returns_plugin_id(self):
        r = self._registry()
        p = ConcretePlugin()
        pid = r.register(p)
        assert pid == p.plugin_id

    def test_register_duplicate_raises_value_error(self):
        r = self._registry()
        r.register(ConcretePlugin())
        with pytest.raises(ValueError, match="already registered"):
            r.register(ConcretePlugin())

    def test_unregister_removes_plugin(self):
        r = self._registry()
        pid = r.register(ConcretePlugin())
        r.unregister(pid)
        assert r.get(pid) is None

    def test_unregister_unknown_raises_key_error(self):
        r = self._registry()
        with pytest.raises(KeyError):
            r.unregister("nonexistent-id")

    def test_get_by_name(self):
        r = self._registry()
        r.register(ConcretePlugin())
        p = r.get_by_name("test-plugin")
        assert p is not None
        assert p.manifest.name == "test-plugin"

    def test_list_all(self):
        r = self._registry()
        r.register(ConcretePlugin(name="a", version="1.0.0"))
        r.register(ConcretePlugin(name="b", version="1.0.0"))
        assert len(r.list_all()) == 2

    def test_list_enabled(self):
        r = self._registry()
        pid = r.register(ConcretePlugin())
        assert r.list_enabled() == []
        r.enable(pid)
        assert len(r.list_enabled()) == 1

    def test_list_by_tag(self):
        r = self._registry()
        r.register(ConcretePlugin())
        result = r.list_by_tag("test")
        assert len(result) == 1

    def test_enable_sets_status(self):
        r = self._registry()
        pid = r.register(ConcretePlugin())
        r.enable(pid)
        assert r.get_status(pid) == PluginStatus.ENABLED

    def test_disable_sets_status(self):
        r = self._registry()
        pid = r.register(ConcretePlugin())
        r.enable(pid)
        r.disable(pid)
        assert r.get_status(pid) == PluginStatus.DISABLED

    def test_get_all_tools_from_enabled(self):
        r = self._registry()
        pid = r.register(PluginWithTool())
        r.enable(pid)
        tools = r.get_all_tools()
        assert len(tools) == 1

    def test_get_all_mcp_servers(self):
        r = self._registry()
        pid = r.register(ConcretePlugin())
        r.enable(pid)
        servers = r.get_all_mcp_servers()
        assert any(s["port"] == 9999 for s in servers)

    def test_to_dict_structure(self):
        r = self._registry()
        r.register(ConcretePlugin())
        result = r.to_dict()
        assert isinstance(result, list)
        assert result[0]["name"] == "test-plugin"
        assert "status" in result[0]

    def test_count(self):
        r = self._registry()
        assert r.count() == 0
        r.register(ConcretePlugin())
        assert r.count() == 1


# ---------------------------------------------------------------------------
# TestPluginLoader
# ---------------------------------------------------------------------------


def _write_plugin_yaml(path: Path, data: dict) -> None:
    import yaml
    with (path / "plugin.yaml").open("w") as fh:
        yaml.dump(data, fh)


def _write_init(path: Path, content: str = "") -> None:
    (path / "__init__.py").write_text(content)


class TestPluginLoader:

    def test_discover_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            loader = PluginLoader(plugins_dir=tmpdir)
            assert loader.discover() == []

    def test_discover_finds_valid_packages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = Path(tmpdir) / "myplugin"
            pkg.mkdir()
            _write_plugin_yaml(pkg, {"name": "x", "version": "1.0.0", "description": "d", "author": "a"})
            _write_init(pkg)
            loader = PluginLoader(plugins_dir=tmpdir)
            assert len(loader.discover()) == 1

    def test_load_manifest_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = Path(tmpdir) / "myplugin"
            pkg.mkdir()
            _write_plugin_yaml(pkg, {"name": "myplugin", "version": "1.0.0", "description": "d", "author": "a"})
            _write_init(pkg)
            loader = PluginLoader(plugins_dir=tmpdir)
            m = loader.load_manifest(pkg)
            assert m.name == "myplugin"

    def test_load_manifest_invalid_yaml_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = Path(tmpdir) / "bad"
            pkg.mkdir()
            (pkg / "plugin.yaml").write_text(": invalid: yaml: [")
            _write_init(pkg)
            loader = PluginLoader(plugins_dir=tmpdir)
            with pytest.raises(PluginLoadError):
                loader.load_manifest(pkg)

    def test_load_manifest_missing_required_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = Path(tmpdir) / "incomplete"
            pkg.mkdir()
            _write_plugin_yaml(pkg, {"name": "x"})  # missing version/description/author
            _write_init(pkg)
            loader = PluginLoader(plugins_dir=tmpdir)
            with pytest.raises(PluginLoadError):
                loader.load_manifest(pkg)

    def test_validate_manifest_valid(self):
        m = _make_manifest()
        loader = PluginLoader()
        errors = loader.validate_manifest(m)
        assert errors == []

    def test_validate_manifest_bad_semver(self):
        m = _make_manifest(version="1.0")  # missing patch
        loader = PluginLoader()
        errors = loader.validate_manifest(m)
        assert any("semver" in e for e in errors)

    def test_load_from_dict(self):
        loader = PluginLoader()
        manifest_dict = {
            "name": "inline",
            "version": "0.0.1",
            "description": "Inline plugin",
            "author": "Dev",
        }
        plugin = loader.load_from_dict(manifest_dict, ConcretePlugin)
        assert isinstance(plugin, BasePlugin)

    def test_load_all_with_real_plugin(self):
        """Write a minimal plugin package to a temp dir and load it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = Path(tmpdir) / "simpleplugin"
            pkg.mkdir()
            _write_plugin_yaml(
                pkg,
                {"name": "simpleplugin", "version": "1.0.0", "description": "Simple", "author": "Dev"},
            )
            init_code = """
from app.plugins.base_plugin import BasePlugin, PluginManifest

class SimplePlugin(BasePlugin):
    @property
    def manifest(self):
        return PluginManifest(name="simpleplugin", version="1.0.0",
                              description="Simple", author="Dev")
    def register_tools(self): return []
    def register_mcp_servers(self): return []
    def register_api_routes(self): return []

def get_plugin():
    return SimplePlugin()
"""
            _write_init(pkg, init_code)
            loader = PluginLoader(plugins_dir=tmpdir)
            results = loader.load_all()
            assert len(results) == 1
            plugin, error = results[0]
            assert error is None
            assert plugin.manifest.name == "simpleplugin"


# ---------------------------------------------------------------------------
# TestSandboxedRunner
# ---------------------------------------------------------------------------


class TestSandboxedRunner:

    def test_successful_run(self):
        runner = SandboxedRunner()
        result = runner.run(lambda: "hello world")
        assert result.success is True
        assert result.output == "hello world"
        assert result.error is None

    def test_timeout_enforced(self):
        runner = SandboxedRunner()

        def slow():
            time.sleep(10)
            return "done"

        result = runner.run(slow, timeout=0.2)
        assert result.success is False
        assert "timed out" in result.error.lower()
        assert len(result.violations) > 0

    def test_exception_captured(self):
        runner = SandboxedRunner()

        def boom():
            raise ValueError("intentional error")

        result = runner.run(boom)
        assert result.success is False
        assert "intentional error" in result.error

    def test_network_allowed_default_cidr(self):
        runner = SandboxedRunner()
        assert runner.check_network_allowed("1.2.3.4") is True

    def test_network_denied_when_restricted(self):
        config = SandboxConfig(allowed_target_cidr="192.168.1.0/24")
        runner = SandboxedRunner(config=config)
        assert runner.check_network_allowed("10.0.0.1") is False
        assert runner.check_network_allowed("192.168.1.50") is True

    def test_filesystem_write_denied_outside_sandbox(self):
        config = SandboxConfig(allow_filesystem_write=True, sandbox_dir="/tmp/univex-sandbox")
        runner = SandboxedRunner(config=config)
        assert runner.check_filesystem_allowed("/etc/passwd", write=True) is False
        assert runner.check_filesystem_allowed("/tmp/univex-sandbox/out.txt", write=True) is True

    def test_audit_log_records_events(self):
        runner = SandboxedRunner()
        runner.run(lambda: "ok")
        log = runner.get_audit_log()
        assert len(log) > 0
        assert all("timestamp" in e and "action" in e and "detail" in e for e in log)

    def test_create_sandbox_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = os.path.join(tmpdir, "sandbox", "nested")
            config = SandboxConfig(sandbox_dir=sandbox)
            runner = SandboxedRunner(config=config)
            runner.create_sandbox_dir()
            assert os.path.isdir(sandbox)

    def test_network_disabled(self):
        config = SandboxConfig(allow_network=False)
        runner = SandboxedRunner(config=config)
        assert runner.check_network_allowed("8.8.8.8") is False

    def test_config_defaults(self):
        config = SandboxConfig()
        assert config.allow_network is True
        assert config.allow_filesystem_write is False
        assert config.max_cpu_seconds == 30.0
        assert config.audit_log is True


# ---------------------------------------------------------------------------
# TestPluginManager
# ---------------------------------------------------------------------------


class TestPluginManager:

    def _manager(self) -> PluginManager:
        with tempfile.TemporaryDirectory() as tmpdir:
            return PluginManager(plugins_dir=tmpdir)

    def test_discover_and_load_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            summary = manager.discover_and_load()
            assert summary["loaded"] == 0
            assert summary["failed"] == 0

    def test_install_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            p = ConcretePlugin()
            pid = manager.install_plugin(p)
            assert pid == p.plugin_id

    def test_uninstall_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            p = ConcretePlugin()
            pid = manager.install_plugin(p)
            manager.uninstall_plugin(pid)
            assert manager.get_plugin_info(pid) is None

    def test_enable_disable_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            p = ConcretePlugin()
            pid = manager.install_plugin(p)
            # already enabled by install_plugin
            manager.disable_plugin(pid)
            status = manager.get_registry().get_status(pid)
            assert status == PluginStatus.DISABLED
            manager.enable_plugin(pid)
            status = manager.get_registry().get_status(pid)
            assert status == PluginStatus.ENABLED

    def test_list_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            manager.install_plugin(ConcretePlugin())
            plugins = manager.list_plugins()
            assert len(plugins) == 1
            assert plugins[0]["name"] == "test-plugin"

    def test_get_plugin_info(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            p = ConcretePlugin()
            pid = manager.install_plugin(p)
            info = manager.get_plugin_info(pid)
            assert info["name"] == "test-plugin"
            assert info["version"] == "1.2.3"

    def test_run_plugin_tool_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            p = PluginWithTool()
            pid = manager.install_plugin(p)
            result = manager.run_plugin_tool(pid, "stub_tool", {"key": "val"})
            assert result.success is True
            assert "stub output" in result.output

    def test_health_check_all(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            p = ConcretePlugin()
            pid = manager.install_plugin(p)
            results = manager.health_check_all()
            assert pid in results
            assert results[pid]["healthy"] is True

    def test_get_registry_returns_registry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            assert isinstance(manager.get_registry(), PluginRegistry)

    def test_get_loader_returns_loader(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager(plugins_dir=tmpdir)
            assert isinstance(manager.get_loader(), PluginLoader)


# ---------------------------------------------------------------------------
# TestExamplePlugins
# ---------------------------------------------------------------------------


class TestExamplePlugins:

    def test_shodan_plugin_manifest(self):
        from app.plugins.examples.shodan_plugin import ShodanPlugin
        p = ShodanPlugin()
        assert p.manifest.name == "shodan"
        assert p.manifest.version == "1.0.0"
        assert "recon" in p.manifest.tags
        assert "osint" in p.manifest.tags

    def test_shodan_plugin_tools_non_empty(self):
        from app.plugins.examples.shodan_plugin import ShodanPlugin
        p = ShodanPlugin()
        tools = p.register_tools()
        assert len(tools) >= 2
        tool_names = [t.name for t in tools]
        assert "shodan_search" in tool_names
        assert "shodan_host_lookup" in tool_names

    def test_shodan_plugin_health_check(self):
        from app.plugins.examples.shodan_plugin import ShodanPlugin
        p = ShodanPlugin()
        h = p.health_check()
        assert h["healthy"] is True
        assert "SHODAN_API_KEY" in h["requires_config"]

    def test_censys_plugin_manifest(self):
        from app.plugins.examples.censys_plugin import CensysPlugin
        p = CensysPlugin()
        assert p.manifest.name == "censys"
        assert "osint" in p.manifest.tags

    def test_censys_plugin_tools_non_empty(self):
        from app.plugins.examples.censys_plugin import CensysPlugin
        p = CensysPlugin()
        tools = p.register_tools()
        assert len(tools) >= 2
        tool_names = [t.name for t in tools]
        assert "censys_search" in tool_names
        assert "censys_certs" in tool_names

    def test_get_plugin_factory_shodan(self):
        from app.plugins.examples.shodan_plugin import get_plugin
        p = get_plugin()
        assert isinstance(p, BasePlugin)
        assert p.manifest.name == "shodan"

    def test_get_plugin_factory_censys(self):
        from app.plugins.examples.censys_plugin import get_plugin
        p = get_plugin()
        assert isinstance(p, BasePlugin)
        assert p.manifest.name == "censys"

    def test_shodan_mcp_server_config(self):
        from app.plugins.examples.shodan_plugin import ShodanPlugin
        p = ShodanPlugin()
        servers = p.register_mcp_servers()
        assert len(servers) == 1
        assert servers[0]["port"] == 9100

    def test_censys_mcp_server_config(self):
        from app.plugins.examples.censys_plugin import CensysPlugin
        p = CensysPlugin()
        servers = p.register_mcp_servers()
        assert len(servers) == 1
        assert servers[0]["port"] == 9101

    def test_shodan_tool_execute(self):
        from app.plugins.examples.shodan_plugin import ShodanSearchTool
        tool = ShodanSearchTool()
        result = asyncio.run(tool.execute(query="port:22"))
        assert "port:22" in result

    def test_censys_tool_execute(self):
        from app.plugins.examples.censys_plugin import CensysCertsTool
        tool = CensysCertsTool()
        test_domain = "example.com"
        result = asyncio.run(tool.execute(domain=test_domain))
        assert test_domain in result


# ---------------------------------------------------------------------------
# Additional edge-case tests to reach 50+
# ---------------------------------------------------------------------------


class TestPluginRegistryEdgeCases:

    def test_get_returns_none_for_unknown(self):
        r = PluginRegistry()
        assert r.get("no-such-id") is None

    def test_get_by_name_returns_none_for_unknown(self):
        r = PluginRegistry()
        assert r.get_by_name("no-such-name") is None

    def test_get_all_tools_empty_when_no_enabled(self):
        r = PluginRegistry()
        r.register(PluginWithTool())
        # not enabled
        assert r.get_all_tools() == []

    def test_get_all_routes_empty(self):
        r = PluginRegistry()
        pid = r.register(ConcretePlugin())
        r.enable(pid)
        assert r.get_all_routes() == []

    def test_enable_unknown_raises_key_error(self):
        r = PluginRegistry()
        with pytest.raises(KeyError):
            r.enable("no-such")

    def test_disable_unknown_raises_key_error(self):
        r = PluginRegistry()
        with pytest.raises(KeyError):
            r.disable("no-such")

    def test_status_after_register_is_loaded(self):
        r = PluginRegistry()
        pid = r.register(ConcretePlugin())
        assert r.get_status(pid) == PluginStatus.LOADED


class TestSandboxConfigDefaults:

    def test_default_sandbox_dir(self):
        c = SandboxConfig()
        assert c.sandbox_dir == "/tmp/univex-sandbox"

    def test_default_cidr_allows_all(self):
        c = SandboxConfig()
        import ipaddress
        net = ipaddress.ip_network(c.allowed_target_cidr, strict=False)
        assert ipaddress.ip_address("8.8.8.8") in net

    def test_execution_result_defaults(self):
        r = ExecutionResult(success=True, output="ok")
        assert r.error is None
        assert r.cpu_time == 0.0
        assert r.violations == []
