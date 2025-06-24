"""
Week 5 Test Suite – Port Scanning Tools

Covers:
  Day 28 – NaabuConfig safe defaults & NaabuOrchestrator initialisation
  Day 29 – Concurrent scanning logic (asyncio Semaphore), command building
  Day 30 – Unit tests for NaabuOrchestrator (mocked subprocess)
  Day 31 – Port scan results normalisation to canonical ReconResult / Endpoint
  Day 32 – /api/scans/ports endpoints (status/result contracts)
  Day 33 – NmapOrchestrator XML parsing → canonical Endpoint + Technology
  Day 34 – Port scanning documentation contract (README exists, exports correct)
"""
from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.recon.canonical_schemas import Endpoint, ReconResult, Severity, Technology
from app.recon.port_scanning.naabu_orchestrator import (
    NaabuConfig,
    NaabuOrchestrator,
    _is_private,
)
from app.recon.port_scanning.nmap_orchestrator import NmapConfig, NmapOrchestrator
from app.recon.port_scanning import (
    NaabuOrchestrator as ExportedNaabu,
    NaabuConfig as ExportedNaabuConfig,
    NmapOrchestrator as ExportedNmap,
    NmapConfig as ExportedNmapConfig,
)


# ===========================================================================
# ===========================================================================

class TestNaabuConfig:
    def test_defaults_are_safe(self):
        cfg = NaabuConfig()
        assert cfg.scan_type == "c"          # CONNECT, no root required
        assert cfg.rate_limit <= 10000       # not unbounded
        assert cfg.exclude_private is True
        assert cfg.top_ports == 1000

    def test_custom_ports_override(self):
        cfg = NaabuConfig(ports="22,80,443")
        assert cfg.ports == "22,80,443"

    def test_port_range_override(self):
        cfg = NaabuConfig(port_range="1-1024")
        assert cfg.port_range == "1-1024"

    def test_concurrency_cap(self):
        cfg = NaabuConfig(max_concurrent_hosts=5)
        assert cfg.max_concurrent_hosts == 5


class TestNaabuOrchestratorInit:
    def test_valid_domain_target(self):
        orch = NaabuOrchestrator("example.com")
        assert orch.target == "example.com"
        assert orch.TOOL_NAME == "naabu"
        assert orch.BINARY == "naabu"

    def test_valid_ip_target(self):
        orch = NaabuOrchestrator("203.0.113.1")
        assert orch.target == "203.0.113.1"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            NaabuOrchestrator("not a valid target!!")

    def test_custom_config_stored(self):
        cfg = NaabuConfig(rate_limit=500, top_ports=100)
        orch = NaabuOrchestrator("example.com", config=cfg)
        assert orch.naabu_config.rate_limit == 500
        assert orch.naabu_config.top_ports == 100


# ===========================================================================
# ===========================================================================

class TestNaabuCommandBuilding:
    def test_command_includes_host_flag(self):
        orch = NaabuOrchestrator("example.com")
        cmd = orch._build_command()
        assert "-host" in cmd
        host_idx = cmd.index("-host")
        assert cmd[host_idx + 1] == "example.com"

    def test_command_uses_json_flag(self):
        cmd = NaabuOrchestrator("example.com")._build_command()
        assert "-json" in cmd

    def test_custom_ports_in_command(self):
        cfg = NaabuConfig(ports="80,443")
        cmd = NaabuOrchestrator("example.com", config=cfg)._build_command()
        assert "-p" in cmd
        assert "80,443" in cmd

    def test_port_range_in_command(self):
        cfg = NaabuConfig(port_range="1-1024")
        cmd = NaabuOrchestrator("example.com", config=cfg)._build_command()
        assert "-p" in cmd
        assert "1-1024" in cmd

    def test_top_ports_used_when_no_explicit_ports(self):
        cfg = NaabuConfig(top_ports=500)
        cmd = NaabuOrchestrator("example.com", config=cfg)._build_command()
        assert "-top-ports" in cmd
        idx = cmd.index("-top-ports")
        assert cmd[idx + 1] == "500"

    def test_rate_limit_in_command(self):
        cfg = NaabuConfig(rate_limit=250)
        cmd = NaabuOrchestrator("10.0.0.1", config=cfg)._build_command()
        assert "-rate" in cmd
        idx = cmd.index("-rate")
        assert cmd[idx + 1] == "250"


class TestPrivateRangeDetection:
    def test_loopback_is_private(self):
        assert _is_private("127.0.0.1") is True

    def test_rfc1918_is_private(self):
        assert _is_private("192.168.1.1") is True
        assert _is_private("10.0.0.1") is True
        assert _is_private("172.16.0.1") is True

    def test_public_ip_not_private(self):
        assert _is_private("203.0.113.1") is False

    def test_domain_not_private(self):
        assert _is_private("example.com") is False


# ===========================================================================
# ===========================================================================

_SAMPLE_NAABU_OUTPUT = (
    '{"host":"203.0.113.1","port":80,"protocol":"tcp"}\n'
    '{"host":"203.0.113.1","port":443,"protocol":"tcp"}\n'
    '{"host":"203.0.113.1","port":8080,"protocol":"tcp"}\n'
)


def _mock_proc(stdout: str, returncode: int = 0):
    proc = AsyncMock()
    proc.communicate = AsyncMock(
        return_value=(stdout.encode(), b"")
    )
    proc.returncode = returncode
    return proc


class TestNaabuOrchestratorExecution:
    @pytest.mark.asyncio
    async def test_successful_scan_returns_recon_result(self):
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc(_SAMPLE_NAABU_OUTPUT)):
            orch = NaabuOrchestrator("203.0.113.1", config=NaabuConfig())
            result = await orch.run()

        assert isinstance(result, ReconResult)
        assert result.success is True
        assert result.endpoint_count == 3

    @pytest.mark.asyncio
    async def test_endpoints_have_correct_urls(self):
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc(_SAMPLE_NAABU_OUTPUT)):
            orch = NaabuOrchestrator("203.0.113.1", config=NaabuConfig())
            result = await orch.run()

        urls = [ep.url for ep in result.endpoints]
        assert "tcp://203.0.113.1:80" in urls
        assert "tcp://203.0.113.1:443" in urls

    @pytest.mark.asyncio
    async def test_endpoints_have_naabu_metadata(self):
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc(_SAMPLE_NAABU_OUTPUT)):
            orch = NaabuOrchestrator("203.0.113.1", config=NaabuConfig())
            result = await orch.run()

        for ep in result.endpoints:
            assert ep.discovered_by == "naabu"
            assert "port-scan" in ep.tags
            assert "port" in ep.extra

    @pytest.mark.asyncio
    async def test_naabu_failure_returns_failed_result(self):
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch(
                "asyncio.create_subprocess_exec",
                return_value=_mock_proc("", returncode=1),
            ):
            orch = NaabuOrchestrator("203.0.113.1", config=NaabuConfig())
            result = await orch.run()

        assert result.success is False
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_empty_output_returns_empty_endpoints(self):
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc("")):
            orch = NaabuOrchestrator("203.0.113.1", config=NaabuConfig())
            result = await orch.run()

        assert result.success is True
        assert result.endpoint_count == 0

    @pytest.mark.asyncio
    async def test_private_ip_blocked_when_exclude_private(self):
        cfg = NaabuConfig(exclude_private=True)
        # Binary present, but target is private – private check should fire
        with patch("shutil.which", return_value="/usr/bin/naabu"):
            orch = NaabuOrchestrator("192.168.1.1", config=cfg)
            result = await orch.run()
        assert result.success is False
        assert "private" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_private_ip_allowed_when_exclude_disabled(self):
        cfg = NaabuConfig(exclude_private=False)
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch("asyncio.create_subprocess_exec", return_value=_mock_proc("")):
            orch = NaabuOrchestrator("192.168.1.1", config=cfg)
            result = await orch.run()
        assert result.success is True

    @pytest.mark.asyncio
    async def test_scan_targets_concurrent(self):
        """scan_targets() should run multiple hosts concurrently."""
        targets = ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
        with patch("shutil.which", return_value="/usr/bin/naabu"), \
             patch(
                "asyncio.create_subprocess_exec",
                return_value=_mock_proc(_SAMPLE_NAABU_OUTPUT),
            ):
            results = await NaabuOrchestrator.scan_targets(
                targets, config=NaabuConfig()
            )
        assert len(results) == 3
        for r in results:
            assert isinstance(r, ReconResult)


# ===========================================================================
# ===========================================================================

class TestNaabuResultNormalisation:
    def test_normalise_produces_endpoint_per_port(self):
        orch = NaabuOrchestrator("203.0.113.1")
        raw = [
            {"host": "203.0.113.1", "port": 22, "protocol": "tcp"},
            {"host": "203.0.113.1", "port": 443, "protocol": "tcp"},
        ]
        result = orch._normalise(raw)
        assert result.endpoint_count == 2

    def test_normalise_url_format(self):
        orch = NaabuOrchestrator("203.0.113.1")
        raw = [{"host": "203.0.113.1", "port": 80, "protocol": "tcp"}]
        result = orch._normalise(raw)
        assert result.endpoints[0].url == "tcp://203.0.113.1:80"

    def test_normalise_skips_records_without_port(self):
        orch = NaabuOrchestrator("203.0.113.1")
        raw = [{"host": "203.0.113.1"}]
        result = orch._normalise(raw)
        assert result.endpoint_count == 0

    def test_normalise_empty_raw_returns_empty_result(self):
        orch = NaabuOrchestrator("203.0.113.1")
        result = orch._normalise([])
        assert result.endpoint_count == 0

    def test_normalise_endpoint_extra_carries_port_number(self):
        orch = NaabuOrchestrator("203.0.113.1")
        raw = [{"host": "203.0.113.1", "port": 3306, "protocol": "tcp"}]
        result = orch._normalise(raw)
        ep = result.endpoints[0]
        assert ep.extra["port"] == 3306


# ===========================================================================
# ===========================================================================

class TestScanPortsAPIContracts:
    """Verify the port-scan router is importable and exposes correct prefix."""

    def test_router_prefix(self):
        from app.api.scans_ports import router
        assert router.prefix == "/api/scans/ports"

    def test_router_has_post_start_route(self):
        from app.api.scans_ports import router
        all_methods: set = set()
        for r in router.routes:
            all_methods.update(r.methods or set())
        assert "POST" in all_methods

    def test_router_has_get_routes(self):
        from app.api.scans_ports import router
        all_methods: set = set()
        for r in router.routes:
            all_methods.update(r.methods or set())
        assert "GET" in all_methods

    def test_request_schema_validation(self):
        from app.api.scans_ports import PortScanCreateRequest
        req = PortScanCreateRequest(targets=["203.0.113.1"])
        assert req.top_ports == 1000
        assert req.exclude_private is True


# ===========================================================================
# ===========================================================================

_SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestNmapOrchestrator:
    def test_normalise_open_ports_become_endpoints(self):
        orch = NmapOrchestrator("203.0.113.5")
        result = orch._normalise(_SAMPLE_NMAP_XML)
        # Only open ports (22 and 80)
        assert result.endpoint_count == 2

    def test_normalise_closed_port_excluded(self):
        orch = NmapOrchestrator("203.0.113.5")
        result = orch._normalise(_SAMPLE_NMAP_XML)
        urls = [ep.url for ep in result.endpoints]
        assert not any("3306" in u for u in urls)

    def test_normalise_produces_technologies(self):
        orch = NmapOrchestrator("203.0.113.5")
        result = orch._normalise(_SAMPLE_NMAP_XML)
        assert result.technology_count >= 2

    def test_normalise_technology_has_version(self):
        orch = NmapOrchestrator("203.0.113.5")
        result = orch._normalise(_SAMPLE_NMAP_XML)
        nginx = next((t for t in result.technologies if "nginx" in t.name.lower()), None)
        assert nginx is not None
        assert nginx.version == "1.24.0"

    def test_normalise_technology_has_cpe(self):
        orch = NmapOrchestrator("203.0.113.5")
        result = orch._normalise(_SAMPLE_NMAP_XML)
        ssh_tech = next(
            (t for t in result.technologies if "openssh" in t.name.lower()), None
        )
        assert ssh_tech is not None
        assert ssh_tech.cpe is not None

    def test_normalise_invalid_xml_returns_empty_result(self):
        orch = NmapOrchestrator("203.0.113.5")
        result = orch._normalise("<invalid xml>")
        assert result.endpoint_count == 0
        assert result.technology_count == 0

    def test_nmap_config_defaults(self):
        cfg = NmapConfig()
        assert cfg.service_version is True
        assert cfg.os_detection is False   # root not required by default
        assert cfg.max_rate == 500


# ===========================================================================
# ===========================================================================

class TestPortScanningDocumentation:
    def test_readme_exists(self):
        from pathlib import Path
        readme = Path(__file__).parent.parent / "app" / "recon" / "port_scanning" / "README.md"
        assert readme.exists(), "port_scanning/README.md should exist"

    def test_naabu_orchestrator_exported_from_package(self):
        assert ExportedNaabu is NaabuOrchestrator
        assert ExportedNaabuConfig is NaabuConfig

    def test_nmap_orchestrator_exported_from_package(self):
        assert ExportedNmap is NmapOrchestrator
        assert ExportedNmapConfig is NmapConfig
