"""
Tests for Day 11 — Tunneling & Pivoting Engine

Coverage (72 tests):
  TestHelperFunctions        (10 tests) — _validate_host, _validate_port, _build_ssh_base,
                                          _proxychains_conf, TunnelEntry
  TestSOCKSProxyTool         (11 tests) — SOCKSProxyTool full coverage
  TestPortForwardTool        (12 tests) — PortForwardTool full coverage
  TestChiselTool             (11 tests) — ChiselTool full coverage
  TestProxychainsTool        (9 tests)  — ProxychainsTool full coverage
  TestSSHTunnelManagerTool   (7 tests)  — SSHTunnelManagerTool full coverage
  TestNetworkPivotMapTool    (6 tests)  — NetworkPivotMapTool full coverage

All tests use asyncio.run() and unittest.mock — no live SSH or process spawning.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap minimal stubs
# ---------------------------------------------------------------------------


def _ensure_stub(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


for _pkg in ["app", "app.agent", "app.agent.tools"]:
    _ensure_stub(_pkg)

import pydantic  # noqa: E402

_BACKEND = os.path.join(os.path.dirname(__file__), "..", "..", "app")


def _load_module(rel_path: str, module_name: str):
    path = os.path.normpath(os.path.join(_BACKEND, rel_path))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


_base_tool_mod = _load_module("agent/tools/base_tool.py", "app.agent.tools.base_tool")
_error_mod = _load_module("agent/tools/error_handling.py", "app.agent.tools.error_handling")
_pivot_mod = _load_module("agent/tools/pivoting_tools.py", "app.agent.tools.pivoting_tools")

SOCKSProxyTool = _pivot_mod.SOCKSProxyTool
PortForwardTool = _pivot_mod.PortForwardTool
ChiselTool = _pivot_mod.ChiselTool
ProxychainsTool = _pivot_mod.ProxychainsTool
SSHTunnelManagerTool = _pivot_mod.SSHTunnelManagerTool
NetworkPivotMapTool = _pivot_mod.NetworkPivotMapTool
TunnelEntry = _pivot_mod.TunnelEntry
ToolExecutionError = _error_mod.ToolExecutionError

_validate_host = _pivot_mod._validate_host
_validate_port = _pivot_mod._validate_port
_build_ssh_base = _pivot_mod._build_ssh_base
_proxychains_conf = _pivot_mod._proxychains_conf
_tunnel_registry = _pivot_mod._tunnel_registry
_next_tunnel_id = _pivot_mod._next_tunnel_id


def _run(coro):
    return asyncio.run(coro)


def _clear_registry():
    """Clear the module-level tunnel registry between tests."""
    _pivot_mod._tunnel_registry.clear()


# ---------------------------------------------------------------------------
# 1. TestHelperFunctions
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Test internal helper functions."""

    def test_validate_host_valid_ip(self):
        _validate_host("192.168.1.1")  # should not raise

    def test_validate_host_valid_hostname(self):
        _validate_host("internal.corp.local")

    def test_validate_host_empty_raises(self):
        with pytest.raises(ToolExecutionError):
            _validate_host("")

    def test_validate_host_too_long_raises(self):
        with pytest.raises(ToolExecutionError):
            _validate_host("a" * 300)

    def test_validate_port_valid(self):
        _validate_port(22)
        _validate_port(1)
        _validate_port(65535)

    def test_validate_port_zero_raises(self):
        with pytest.raises(ToolExecutionError):
            _validate_port(0)

    def test_validate_port_too_high_raises(self):
        with pytest.raises(ToolExecutionError):
            _validate_port(65536)

    def test_build_ssh_base_basic(self):
        cmd = _build_ssh_base("root", "10.0.0.1", 22)
        assert "ssh" in cmd
        assert "root@10.0.0.1" in cmd
        assert "-N" in cmd

    def test_build_ssh_base_with_key(self):
        cmd = _build_ssh_base("ubuntu", "10.0.0.5", 2222, ssh_key="/tmp/id_rsa")
        assert "-i" in cmd
        assert "/tmp/id_rsa" in cmd

    def test_proxychains_conf_generates_valid_conf(self):
        proxies = [{"type": "socks5", "host": "127.0.0.1", "port": 1080}]
        conf = _proxychains_conf(proxies)
        assert "socks5" in conf
        assert "127.0.0.1" in conf
        assert "1080" in conf
        assert "[ProxyList]" in conf


# ---------------------------------------------------------------------------
# 2. TestSOCKSProxyTool
# ---------------------------------------------------------------------------


class TestSOCKSProxyTool:
    """Tests for SOCKSProxyTool."""

    def setup_method(self):
        _clear_registry()

    def _tool(self):
        return SOCKSProxyTool()

    def test_metadata_name(self):
        assert self._tool().name == "socks_proxy"

    def test_metadata_description_nonempty(self):
        assert len(self._tool().description) > 20

    def test_create_simulated(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=-1)):
            result = _run(self._tool().execute(
                action="create",
                jump_host="10.0.0.1",
                local_socks_port=1080,
            ))
        data = json.loads(result)
        assert "tunnel_id" in data
        assert data["simulated"] is True
        assert "socks5://127.0.0.1:1080" in data["local_socks_proxy"]

    def test_create_with_pid(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=12345)):
            result = _run(self._tool().execute(
                action="create",
                jump_host="192.168.1.100",
                local_socks_port=1081,
            ))
        data = json.loads(result)
        assert data["simulated"] is False
        assert data["pid"] == 12345

    def test_create_missing_jump_host_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="create"))

    def test_create_invalid_port_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(
                action="create",
                jump_host="10.0.0.1",
                local_socks_port=99999,
            ))

    def test_list_empty(self):
        result = _run(self._tool().execute(action="list"))
        data = json.loads(result)
        assert data["active_socks_proxies"] == 0

    def test_list_after_create(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=100)):
            _run(self._tool().execute(action="create", jump_host="10.0.0.1"))
        result = _run(self._tool().execute(action="list"))
        data = json.loads(result)
        assert data["active_socks_proxies"] >= 1

    def test_destroy_existing_tunnel(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=100)):
            create_result = _run(self._tool().execute(action="create", jump_host="10.0.0.1"))
        tid = json.loads(create_result)["tunnel_id"]
        result = _run(self._tool().execute(action="destroy", tunnel_id=tid))
        data = json.loads(result)
        assert data["status"] == "destroyed"

    def test_destroy_nonexistent_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="destroy", tunnel_id="tun_9999"))

    def test_proxychains_conf_in_create_result(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=-1)):
            result = _run(self._tool().execute(action="create", jump_host="10.0.0.1"))
        data = json.loads(result)
        assert "proxychains_conf" in data
        assert "socks5" in data["proxychains_conf"]

    def test_test_without_test_host(self):
        result = _run(self._tool().execute(action="test", local_socks_port=1080))
        data = json.loads(result)
        assert data["tested"] is False

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="unknown_action"))


# ---------------------------------------------------------------------------
# 3. TestPortForwardTool
# ---------------------------------------------------------------------------


class TestPortForwardTool:
    """Tests for PortForwardTool."""

    def setup_method(self):
        _clear_registry()

    def _tool(self):
        return PortForwardTool()

    def test_metadata_name(self):
        assert self._tool().name == "port_forward"

    def test_create_local_simulated(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=-1)):
            result = _run(self._tool().execute(
                action="create_local",
                jump_host="10.0.0.1",
                local_port=8080,
                remote_host="internal.host",
                remote_port=80,
            ))
        data = json.loads(result)
        assert data["tunnel_type"] == "local"
        assert "127.0.0.1:8080" in data["description"]

    def test_create_local_missing_jump_host_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="create_local", local_port=8080, remote_host="host", remote_port=80))

    def test_create_local_missing_remote_host_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(
                action="create_local",
                jump_host="10.0.0.1",
                local_port=8080,
                remote_port=80,
            ))

    def test_create_remote(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=200)):
            result = _run(self._tool().execute(
                action="create_remote",
                jump_host="10.0.0.1",
                local_port=4444,
                remote_port=4445,
            ))
        data = json.loads(result)
        assert data["tunnel_type"] == "remote"
        assert data["pid"] == 200

    def test_create_dynamic(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=300)):
            result = _run(self._tool().execute(
                action="create_dynamic",
                jump_host="10.0.0.1",
                local_port=1080,
            ))
        data = json.loads(result)
        assert data["tunnel_type"] == "dynamic"

    def test_list_all_tunnels(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=100)):
            _run(self._tool().execute(action="create_local", jump_host="10.0.0.1",
                                      local_port=8080, remote_host="host", remote_port=80))
        result = _run(self._tool().execute(action="list"))
        data = json.loads(result)
        assert data["total_tunnels"] >= 1

    def test_destroy_tunnel(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=100)):
            create_r = _run(self._tool().execute(
                action="create_local", jump_host="10.0.0.1",
                local_port=8080, remote_host="host", remote_port=80,
            ))
        tid = json.loads(create_r)["tunnel_id"]
        result = _run(self._tool().execute(action="destroy", tunnel_id=tid))
        assert json.loads(result)["status"] == "destroyed"

    def test_destroy_nonexistent_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="destroy", tunnel_id="tun_nonexistent"))

    def test_ssh_command_in_result(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=-1)):
            result = _run(self._tool().execute(
                action="create_local",
                jump_host="10.0.0.1",
                local_port=8080,
                remote_host="internal",
                remote_port=80,
            ))
        data = json.loads(result)
        assert "ssh_command" in data
        assert "ssh" in data["ssh_command"]

    def test_invalid_local_port_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(
                action="create_local",
                jump_host="10.0.0.1",
                local_port=0,
                remote_host="host",
                remote_port=80,
            ))

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="bad_action"))

    def test_create_tunnel_includes_usage(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=-1)):
            result = _run(self._tool().execute(
                action="create_local",
                jump_host="10.0.0.1",
                local_port=8080,
                remote_host="internal",
                remote_port=80,
            ))
        data = json.loads(result)
        assert "usage" in data
        assert data["usage"]["local"] is not None


# ---------------------------------------------------------------------------
# 4. TestChiselTool
# ---------------------------------------------------------------------------


class TestChiselTool:
    """Tests for ChiselTool."""

    def setup_method(self):
        _clear_registry()

    def _tool(self):
        return ChiselTool()

    def test_metadata_name(self):
        assert self._tool().name == "chisel_tunnel"

    def test_generate_server_command(self):
        result = _run(self._tool().execute(
            action="generate_command",
            mode="server",
            server_port=8080,
        ))
        data = json.loads(result)
        assert data["mode"] == "server"
        assert "server_command" in data

    def test_generate_server_reverse_command(self):
        result = _run(self._tool().execute(
            action="generate_command",
            mode="server",
            server_port=8080,
            reverse=True,
        ))
        data = json.loads(result)
        assert "--reverse" in data["server_command"]

    def test_generate_client_command(self):
        result = _run(self._tool().execute(
            action="generate_command",
            mode="client",
            server_host="attacker.com",
            server_port=8080,
            tunnels=["R:8888:127.0.0.1:22"],
        ))
        data = json.loads(result)
        assert data["mode"] == "client"
        assert "client_command" in data

    def test_generate_client_socks5(self):
        result = _run(self._tool().execute(
            action="generate_command",
            mode="client",
            server_host="attacker.com",
            server_port=8080,
            socks5=True,
        ))
        data = json.loads(result)
        assert data["socks5_proxy"] == "socks5://127.0.0.1:1080"

    def test_generate_command_download_link(self):
        result = _run(self._tool().execute(
            action="generate_command",
            mode="client",
            server_host="attacker.com",
            target_os="linux",
        ))
        data = json.loads(result)
        assert "download" in data
        assert "linux" in data["download"]

    def test_start_server_simulated(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=-1)):
            result = _run(self._tool().execute(action="start_server", server_port=8080))
        data = json.loads(result)
        assert data["mode"] == "server"
        assert data["simulated"] is True

    def test_start_server_with_pid(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=9999)):
            result = _run(self._tool().execute(action="start_server", server_port=8080))
        data = json.loads(result)
        assert data["pid"] == 9999

    def test_start_client_missing_server_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="start_client", server_port=8080))

    def test_stop_nonexistent_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="stop", tunnel_id="tun_9999"))

    def test_status_empty(self):
        result = _run(self._tool().execute(action="status"))
        data = json.loads(result)
        assert data["active_chisel_tunnels"] == 0

    def test_generate_windows_download_link(self):
        result = _run(self._tool().execute(
            action="generate_command",
            mode="client",
            server_host="attacker.com",
            target_os="windows",
        ))
        data = json.loads(result)
        assert "windows" in data["download"]


# ---------------------------------------------------------------------------
# 5. TestProxychainsTool
# ---------------------------------------------------------------------------


class TestProxychainsTool:
    """Tests for ProxychainsTool."""

    def setup_method(self):
        _clear_registry()

    def _tool(self):
        return ProxychainsTool()

    def test_metadata_name(self):
        assert self._tool().name == "proxychains"

    def test_generate_conf_with_proxies(self):
        result = _run(self._tool().execute(
            action="generate_conf",
            proxies=[{"type": "socks5", "host": "127.0.0.1", "port": 1080}],
            conf_path="/tmp/test_proxychains.conf",
        ))
        data = json.loads(result)
        assert "socks5" in data["conf_content"]
        assert "127.0.0.1" in data["conf_content"]
        assert "[ProxyList]" in data["conf_content"]

    def test_generate_conf_strict_chain(self):
        result = _run(self._tool().execute(
            action="generate_conf",
            proxies=[{"type": "socks5", "host": "127.0.0.1", "port": 1080}],
            chain_type="strict_chain",
            conf_path="/tmp/test_proxychains.conf",
        ))
        data = json.loads(result)
        assert "strict_chain" in data["conf_content"]

    def test_generate_conf_dynamic_chain(self):
        result = _run(self._tool().execute(
            action="generate_conf",
            proxies=[{"type": "socks5", "host": "127.0.0.1", "port": 1080}],
            chain_type="dynamic_chain",
            conf_path="/tmp/test_proxychains.conf",
        ))
        data = json.loads(result)
        assert "dynamic_chain" in data["conf_content"]

    def test_generate_conf_auto_from_active_tunnels(self):
        # Manually add a SOCKS tunnel to registry
        from time import time
        _pivot_mod._tunnel_registry["auto_tun"] = TunnelEntry(
            tunnel_id="auto_tun",
            tunnel_type="dynamic",
            local_port=1082,
            remote_host="*",
            remote_port=0,
            jump_host="10.0.0.1",
            jump_user="root",
            jump_port=22,
            status="active",
            pid=None,
        )
        result = _run(self._tool().execute(
            action="generate_conf",
            conf_path="/tmp/test_proxychains_auto.conf",
        ))
        data = json.loads(result)
        assert any(p["port"] == 1082 for p in data["proxies"])

    def test_run_command_missing_command_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="run_command"))

    def test_run_command_simulated(self):
        with patch.object(_pivot_mod, "_run_subprocess", new=AsyncMock(return_value=(0, "nmap output", ""))):
            result = _run(self._tool().execute(
                action="run_command",
                proxies=[{"type": "socks5", "host": "127.0.0.1", "port": 1080}],
                command="nmap -sT -p 80 10.0.0.1",
                conf_path="/tmp/test_pc_run.conf",
            ))
        data = json.loads(result)
        assert data["success"] is True

    def test_list_proxies_empty(self):
        result = _run(self._tool().execute(action="list_proxies"))
        data = json.loads(result)
        assert "active_socks_proxies" in data

    def test_examples_in_generate_conf(self):
        result = _run(self._tool().execute(
            action="generate_conf",
            proxies=[{"type": "socks5", "host": "127.0.0.1", "port": 1080}],
            conf_path="/tmp/test_examples.conf",
        ))
        data = json.loads(result)
        assert "examples" in data
        assert len(data["examples"]) >= 3


# ---------------------------------------------------------------------------
# 6. TestSSHTunnelManagerTool
# ---------------------------------------------------------------------------


class TestSSHTunnelManagerTool:
    """Tests for SSHTunnelManagerTool."""

    def setup_method(self):
        _clear_registry()

    def _tool(self):
        return SSHTunnelManagerTool()

    def test_metadata_name(self):
        assert self._tool().name == "ssh_tunnel_manager"

    def test_list_empty(self):
        result = _run(self._tool().execute(action="list"))
        data = json.loads(result)
        assert data["total_tunnels"] == 0

    def test_list_with_tunnels(self):
        _pivot_mod._tunnel_registry["t1"] = TunnelEntry(
            tunnel_id="t1", tunnel_type="dynamic", local_port=1080,
            remote_host="*", remote_port=0, jump_host="10.0.0.1",
            jump_user="root", jump_port=22, status="active",
        )
        result = _run(self._tool().execute(action="list"))
        data = json.loads(result)
        assert data["total_tunnels"] == 1
        assert data["summary"]["dynamic_socks"] == 1

    def test_destroy_all(self):
        _pivot_mod._tunnel_registry["t2"] = TunnelEntry(
            tunnel_id="t2", tunnel_type="local", local_port=8080,
            remote_host="host", remote_port=80, jump_host="10.0.0.1",
            jump_user="root", jump_port=22, status="active",
        )
        result = _run(self._tool().execute(action="destroy_all"))
        data = json.loads(result)
        assert data["count"] >= 1
        assert len(_pivot_mod._tunnel_registry) == 0

    def test_health_check_no_pid(self):
        _pivot_mod._tunnel_registry["t3"] = TunnelEntry(
            tunnel_id="t3", tunnel_type="dynamic", local_port=1083,
            remote_host="*", remote_port=0, jump_host="10.0.0.1",
            jump_user="root", jump_port=22, status="active", pid=None,
        )
        result = _run(self._tool().execute(action="health_check", tunnel_id="t3"))
        data = json.loads(result)
        assert data["alive"] is False

    def test_create_tunnel_dynamic(self):
        with patch.object(_pivot_mod, "_start_background", new=AsyncMock(return_value=500)):
            result = _run(self._tool().execute(
                action="create_tunnel",
                jump_host="10.0.0.1",
                forward_spec="-D1085",
            ))
        data = json.loads(result)
        assert data["tunnel_type"] == "dynamic"

    def test_create_tunnel_missing_spec_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="create_tunnel", jump_host="10.0.0.1"))

    def test_create_tunnel_invalid_spec_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(
                action="create_tunnel",
                jump_host="10.0.0.1",
                forward_spec="invalid",
            ))


# ---------------------------------------------------------------------------
# 7. TestNetworkPivotMapTool
# ---------------------------------------------------------------------------


class TestNetworkPivotMapTool:
    """Tests for NetworkPivotMapTool."""

    def _tool(self):
        return NetworkPivotMapTool()

    def test_metadata_name(self):
        assert self._tool().name == "network_pivot_map"

    def test_add_hop(self):
        tool = self._tool()
        result = _run(tool.execute(
            action="add_hop",
            from_host="attacker",
            to_host="10.0.0.1",
            tunnel_type="ssh_dynamic",
            local_port=1080,
        ))
        data = json.loads(result)
        assert data["status"] == "added"
        assert data["total_hops"] == 1

    def test_show_map(self):
        tool = self._tool()
        _run(tool.execute(action="add_hop", from_host="attacker", to_host="10.0.0.1",
                          tunnel_type="ssh_dynamic", local_port=1080))
        result = _run(tool.execute(action="show_map"))
        data = json.loads(result)
        assert data["pivot_chain"]["hops"] == 1
        assert "ascii_diagram" in data["pivot_chain"]
        assert data["neo4j_node_type"] == "PivotHop"

    def test_export_cypher(self):
        tool = self._tool()
        _run(tool.execute(action="add_hop", from_host="attacker", to_host="10.0.0.1",
                          tunnel_type="ssh_dynamic", local_port=1080))
        result = _run(tool.execute(action="export_cypher"))
        data = json.loads(result)
        assert "cypher" in data
        assert "PivotHop" in data["cypher"]
        assert "PIVOTS_THROUGH" in data["cypher"]

    def test_clear_map(self):
        tool = self._tool()
        _run(tool.execute(action="add_hop", from_host="attacker", to_host="10.0.0.1",
                          tunnel_type="ssh_dynamic", local_port=1080))
        result = _run(tool.execute(action="clear_map"))
        data = json.loads(result)
        assert data["hops_removed"] == 1

    def test_add_hop_missing_from_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self._tool().execute(action="add_hop", to_host="10.0.0.1"))

    def test_store_neo4j_simulated(self):
        tool = self._tool()
        _run(tool.execute(action="add_hop", from_host="attacker", to_host="10.0.0.1",
                          tunnel_type="ssh_dynamic", local_port=1080))
        result = _run(tool.execute(action="store_neo4j"))
        data = json.loads(result)
        # Should be simulated if neo4j driver not available
        assert "status" in data
        assert data["hops_to_store"] == 1
