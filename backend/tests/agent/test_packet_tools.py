"""
Tests for Day 14 — Network Packet Analysis Tools

Coverage (55 tests):
  TestHelperFunctions      (8 tests)  — _validate_interface, _validate_bpf_filter,
                                         _pcap_path, _parse_http_basic, CaptureInfo
  TestPacketCaptureTool    (14 tests) — start/stop/status/list/delete actions,
                                         BPF validation, interface validation
  TestPcapAnalyzeTool      (12 tests) — full/summary/protocols/top_talkers/
                                         connections/credentials analysis
  TestCredentialSnifferTool (11 tests) — list_protocols, sniff_live, analyze_file,
                                          deep_sniff_pcap, format_output
  TestProtocolAnalyzerTool  (10 tests) — HTTP/DNS/SMB/Kerberos/LDAP analysis,
                                          vuln checkers

All tests use asyncio.run() and unittest.mock — no live tcpdump or tshark required.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
import tempfile
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap minimal stubs so app.agent.tools.* can be imported directly
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
_packet_mod = _load_module("agent/tools/packet_tools.py", "app.agent.tools.packet_tools")

PacketCaptureTool = _packet_mod.PacketCaptureTool
PcapAnalyzeTool = _packet_mod.PcapAnalyzeTool
CredentialSnifferTool = _packet_mod.CredentialSnifferTool
ProtocolAnalyzerTool = _packet_mod.ProtocolAnalyzerTool
CaptureInfo = _packet_mod.CaptureInfo
ProtocolStats = _packet_mod.ProtocolStats
CapturedCredential = _packet_mod.CapturedCredential
ToolExecutionError = _error_mod.ToolExecutionError

_validate_interface = _packet_mod._validate_interface
_validate_bpf_filter = _packet_mod._validate_bpf_filter
_pcap_path = _packet_mod._pcap_path
_parse_http_basic = _packet_mod._parse_http_basic
_active_captures = _packet_mod._active_captures
_simulate_pcap_analysis = _packet_mod._simulate_pcap_analysis


def _run(coro):
    return asyncio.run(coro)


def _clear_captures():
    """Clear the module-level capture registry between tests."""
    _packet_mod._active_captures.clear()


# ---------------------------------------------------------------------------
# 1. TestHelperFunctions
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Test internal helper functions."""

    def test_validate_interface_valid_eth0(self):
        assert _validate_interface("eth0") == "eth0"

    def test_validate_interface_valid_lo(self):
        assert _validate_interface("lo") == "lo"

    def test_validate_interface_valid_any(self):
        assert _validate_interface("any") == "any"

    def test_validate_interface_invalid_raises(self):
        with pytest.raises(ToolExecutionError):
            _validate_interface("eth0; rm -rf /")

    def test_validate_bpf_filter_valid(self):
        assert _validate_bpf_filter("port 80") == "port 80"

    def test_validate_bpf_filter_empty(self):
        assert _validate_bpf_filter("") == ""

    def test_validate_bpf_filter_with_host(self):
        assert _validate_bpf_filter("host 10.0.0.1 and port 443") == "host 10.0.0.1 and port 443"

    def test_validate_bpf_filter_invalid_raises(self):
        with pytest.raises(ToolExecutionError):
            _validate_bpf_filter("port 80 | rm -rf /")

    def test_pcap_path_returns_string(self):
        path = _pcap_path("cap_123")
        assert path.endswith(".pcap")
        assert "cap_123" in path

    def test_pcap_path_sanitizes_id(self):
        path = _pcap_path("cap../evil")
        assert "/" not in os.path.basename(path)

    def test_parse_http_basic_valid(self):
        header = "Basic " + base64.b64encode(b"admin:password123").decode()
        result = _parse_http_basic(header)
        assert result is not None
        assert result[0] == "admin"
        assert result[1] == "password123"

    def test_parse_http_basic_no_match(self):
        result = _parse_http_basic("Bearer sometoken")
        assert result is None

    def test_parse_http_basic_no_colon(self):
        header = "Basic " + base64.b64encode(b"nocolon").decode()
        result = _parse_http_basic(header)
        assert result is None

    def test_capture_info_dataclass(self):
        import time
        info = CaptureInfo(
            capture_id="cap_001",
            interface="eth0",
            bpf_filter="port 80",
            pcap_path="/tmp/cap_001.pcap",
            pid=12345,
            status="running",
            started_at=time.time(),
        )
        assert info.capture_id == "cap_001"
        assert info.status == "running"
        assert info.pid == 12345

    def test_simulate_pcap_analysis_returns_dict(self):
        result = _simulate_pcap_analysis("/nonexistent.pcap")
        assert "protocol_distribution" in result
        assert "top_talkers" in result
        assert "note" in result
        assert len(result["protocol_distribution"]) > 0


# ---------------------------------------------------------------------------
# 2. TestPacketCaptureTool
# ---------------------------------------------------------------------------


class TestPacketCaptureTool:
    """Test PacketCaptureTool actions."""

    def setup_method(self):
        _clear_captures()
        self.tool = PacketCaptureTool()

    def test_metadata_name(self):
        assert self.tool.name == "packet_capture"

    def test_metadata_description_not_empty(self):
        assert len(self.tool.description) > 10

    def test_list_empty(self):
        result = _run(self.tool.execute(action="list"))
        data = json.loads(result)
        assert data["total"] == 0
        assert data["captures"] == []

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_start_creates_capture_id(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 9999
        mock_exec.return_value = proc_mock

        result = _run(self.tool.execute(action="start", interface="eth0"))
        data = json.loads(result)
        assert "capture_id" in data
        assert data["interface"] == "eth0"

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_start_records_in_registry(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 1234
        mock_exec.return_value = proc_mock

        result = _run(self.tool.execute(action="start", interface="lo", bpf_filter="port 80"))
        data = json.loads(result)
        cid = data["capture_id"]
        assert cid in _packet_mod._active_captures

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_start_with_bpf_filter(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 5678
        mock_exec.return_value = proc_mock

        result = _run(self.tool.execute(action="start", interface="eth0", bpf_filter="port 443"))
        data = json.loads(result)
        assert data["bpf_filter"] == "port 443"

    def test_start_invalid_interface_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="start", interface="eth0;evil"))

    def test_start_invalid_bpf_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="start", interface="eth0", bpf_filter="port 80 | rm -rf /"))

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_stop_marks_stopped(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 111
        mock_exec.return_value = proc_mock

        start_result = _run(self.tool.execute(action="start", interface="eth0"))
        cid = json.loads(start_result)["capture_id"]

        stop_result = _run(self.tool.execute(action="stop", capture_id=cid))
        data = json.loads(stop_result)
        assert data["status"] == "stopped"
        assert data["capture_id"] == cid

    def test_stop_missing_id_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="stop"))

    def test_stop_unknown_id_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="stop", capture_id="nonexistent_cap"))

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_status_returns_info(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 222
        mock_exec.return_value = proc_mock

        start_result = _run(self.tool.execute(action="start", interface="eth0"))
        cid = json.loads(start_result)["capture_id"]

        status_result = _run(self.tool.execute(action="status", capture_id=cid))
        data = json.loads(status_result)
        assert data["capture_id"] == cid
        assert "elapsed_s" in data

    def test_status_missing_id_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="status"))

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_delete_removes_entry(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 333
        mock_exec.return_value = proc_mock

        start_result = _run(self.tool.execute(action="start", interface="eth0"))
        cid = json.loads(start_result)["capture_id"]

        del_result = _run(self.tool.execute(action="delete", capture_id=cid))
        data = json.loads(del_result)
        assert data["deleted"] is True
        assert cid not in _packet_mod._active_captures

    def test_delete_missing_id_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="delete"))

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="unknown_action"))

    @patch("app.agent.tools.packet_tools.asyncio.create_subprocess_exec")
    def test_list_shows_captures(self, mock_exec):
        proc_mock = AsyncMock()
        proc_mock.pid = 444
        mock_exec.return_value = proc_mock

        _run(self.tool.execute(action="start", interface="eth0"))
        _run(self.tool.execute(action="start", interface="lo"))

        result = _run(self.tool.execute(action="list"))
        data = json.loads(result)
        assert data["total"] == 2


# ---------------------------------------------------------------------------
# 3. TestPcapAnalyzeTool
# ---------------------------------------------------------------------------


class TestPcapAnalyzeTool:
    """Test PcapAnalyzeTool."""

    def setup_method(self):
        self.tool = PcapAnalyzeTool()
        self.tmpdir = tempfile.mkdtemp()

    def test_metadata_name(self):
        assert self.tool.name == "pcap_analyze"

    def test_no_pcap_path_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(pcap_path=""))

    def test_nonexistent_file_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(pcap_path="/nonexistent/path/test.pcap"))

    def _create_temp_pcap(self, content: bytes = b"\xd4\xc3\xb2\xa1\x00\x00") -> str:
        """Create a minimal temp pcap-like file."""
        path = os.path.join(self.tmpdir, "test.pcap")
        with open(path, "wb") as f:
            f.write(content)
        return path

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_full_analysis_returns_all_sections(self, mock_run):
        mock_run.return_value = (1, "", "tshark not found")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="full"))
        data = json.loads(result)
        assert "protocol_distribution" in data
        assert "top_talkers" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_summary_analysis(self, mock_run):
        mock_run.return_value = (1, "", "not found")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="summary"))
        data = json.loads(result)
        assert "summary" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_protocols_analysis_simulated(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="protocols"))
        data = json.loads(result)
        assert "protocol_distribution" in data
        assert len(data["protocol_distribution"]) > 0

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_top_talkers_simulated(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="top_talkers", top_n=5))
        data = json.loads(result)
        assert "top_talkers" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_connections_analysis(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="connections"))
        data = json.loads(result)
        assert "connections" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_credentials_analysis(self, mock_run):
        mock_run.return_value = (0, "", "")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="credentials"))
        data = json.loads(result)
        assert "credentials" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_real_tshark_protocol_output_parsed(self, mock_run):
        tshark_output = "  tcp  frames:100 bytes:5000\n  udp  frames:50 bytes:2000\n"
        mock_run.return_value = (0, tshark_output, "")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="protocols"))
        data = json.loads(result)
        protos = data.get("protocol_distribution", [])
        assert isinstance(protos, list)

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_http_basic_credential_extraction(self, mock_run):
        encoded = base64.b64encode(b"admin:secret123").decode()
        tshark_output = f"1609459200\t192.168.1.100\t10.0.0.1\tBasic {encoded}\n"
        mock_run.return_value = (0, tshark_output, "")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="credentials"))
        data = json.loads(result)
        creds = data.get("credentials", [])
        assert isinstance(creds, list)

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_ftp_credential_extraction(self, mock_run):
        ftp_output = "1234\t10.0.0.1\t192.168.1.1\tUSER\tadmin\n1235\t10.0.0.1\t192.168.1.1\tPASS\tsupersecret\n"
        mock_run.return_value = (0, ftp_output, "")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, analysis_type="credentials"))
        data = json.loads(result)
        assert "credentials" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_display_filter_applied(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, display_filter="http", analysis_type="summary"))
        data = json.loads(result)
        assert "summary" in data


# ---------------------------------------------------------------------------
# 4. TestCredentialSnifferTool
# ---------------------------------------------------------------------------


class TestCredentialSnifferTool:
    """Test CredentialSnifferTool."""

    def setup_method(self):
        self.tool = CredentialSnifferTool()

    def test_metadata_name(self):
        assert self.tool.name == "credential_sniffer"

    def test_list_protocols_returns_dict(self):
        result = _run(self.tool.execute(action="list_protocols"))
        data = json.loads(result)
        assert "supported_protocols" in data
        protocols = data["supported_protocols"]
        assert "http" in protocols
        assert "ftp" in protocols
        assert "smtp" in protocols
        assert "ntlm" in protocols

    def test_list_protocols_has_ports(self):
        result = _run(self.tool.execute(action="list_protocols"))
        data = json.loads(result)
        http_info = data["supported_protocols"]["http"]
        assert "ports" in http_info
        assert 80 in http_info["ports"]

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_sniff_live_no_tshark(self, mock_run):
        mock_run.return_value = (1, "", "tshark: command not found")
        result = _run(self.tool.execute(action="sniff_live", interface="eth0", duration=5))
        data = json.loads(result)
        assert "status" in data
        assert "credentials_found" in data

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_sniff_live_validates_interface(self, mock_run):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="sniff_live", interface="eth0&&evil", duration=5))

    def test_analyze_file_missing_path_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="analyze_file", pcap_path=""))

    def test_analyze_file_nonexistent_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="analyze_file", pcap_path="/no/such/file.pcap"))

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_analyze_file_returns_creds_structure(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\xd4\xc3\xb2\xa1\x00\x00")
            path = f.name

        try:
            result = _run(self.tool.execute(action="analyze_file", pcap_path=path))
            data = json.loads(result)
            assert "credentials_found" in data
            assert "credentials" in data
        finally:
            os.unlink(path)

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="invalid_action"))

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_sniff_live_specific_protocols(self, mock_run):
        mock_run.return_value = (124, "", "")  # 124 = timeout exit
        result = _run(
            self.tool.execute(
                action="sniff_live",
                interface="eth0",
                duration=5,
                protocols=["http", "ftp"],
            )
        )
        data = json.loads(result)
        assert "credentials_found" in data

    def test_parse_tshark_json_empty(self):
        result = self.tool._parse_tshark_json("", ["http"])
        assert result == []

    def test_parse_tshark_json_invalid_json(self):
        result = self.tool._parse_tshark_json("not json {{{{", ["http"])
        assert result == []

    def test_format_output_json(self):
        creds = [{"protocol": "HTTP", "username": "admin", "password": "pass"}]
        result = self.tool._format_output(creds, "json", source="test.pcap")
        data = json.loads(result)
        assert data["credentials_found"] == 1


# ---------------------------------------------------------------------------
# 5. TestProtocolAnalyzerTool
# ---------------------------------------------------------------------------


class TestProtocolAnalyzerTool:
    """Test ProtocolAnalyzerTool."""

    def setup_method(self):
        self.tool = ProtocolAnalyzerTool()
        self.tmpdir = tempfile.mkdtemp()

    def _create_temp_pcap(self) -> str:
        path = os.path.join(self.tmpdir, "test.pcap")
        with open(path, "wb") as f:
            f.write(b"\xd4\xc3\xb2\xa1\x00\x00")
        return path

    def test_metadata_name(self):
        assert self.tool.name == "protocol_analyzer"

    def test_no_pcap_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(pcap_path=""))

    def test_nonexistent_pcap_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(pcap_path="/no/such/file.pcap"))

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_http_analysis(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, protocol="http"))
        data = json.loads(result)
        assert "analysis" in data
        assert "http" in data["analysis"]

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_dns_analysis(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, protocol="dns"))
        data = json.loads(result)
        assert "dns" in data["analysis"]

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_smb_analysis(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, protocol="smb"))
        data = json.loads(result)
        assert "smb" in data["analysis"]

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_kerberos_analysis(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, protocol="kerberos"))
        data = json.loads(result)
        assert "kerberos" in data["analysis"]

    @patch("app.agent.tools.packet_tools._run_cmd")
    def test_all_protocol_analysis(self, mock_run):
        mock_run.return_value = (1, "", "no tshark")
        path = self._create_temp_pcap()
        result = _run(self.tool.execute(pcap_path=path, protocol="all"))
        data = json.loads(result)
        assert "http" in data["analysis"]
        assert "dns" in data["analysis"]
        assert "smb" in data["analysis"]
        assert "kerberos" in data["analysis"]

    def test_check_http_vulns_insecure_cookie(self):
        http_data = {
            "requests": [
                {
                    "http.src": "192.168.1.1",
                    "http.cookie": "session=abc123",
                    "http.request.method": "GET",
                    "http.request.uri": "/dashboard",
                }
            ]
        }
        vulns = self.tool._check_http_vulns(http_data)
        assert any(v["type"] == "INSECURE_COOKIE" for v in vulns)

    def test_check_http_vulns_sensitive_url(self):
        http_data = {
            "requests": [
                {
                    "http.request.method": "GET",
                    "http.request.uri": "/login?password=secret123",
                    "http.cookie": "",
                }
            ]
        }
        vulns = self.tool._check_http_vulns(http_data)
        assert any(v["type"] == "SENSITIVE_DATA_IN_URL" for v in vulns)

    def test_check_smb_vulns_legacy_dialect(self):
        smb_data = {
            "dialects_negotiated": ["NT LM 0.12"],
            "sessions": [],
        }
        vulns = self.tool._check_smb_vulns(smb_data)
        assert any(v["type"] == "LEGACY_SMB_DIALECT" for v in vulns)

    def test_check_kerberos_vulns_weak_etype(self):
        kerb_data = {
            "exchanges": [
                {"etype": "23", "msg_type": "AS-REQ", "realm": "CORP.LOCAL", "principal": "user"}
            ]
        }
        vulns = self.tool._check_kerberos_vulns(kerb_data)
        assert any(v["type"] == "WEAK_KERBEROS_ETYPE" for v in vulns)

    def test_check_dns_vulns_suspicious_domain(self):
        dns_data = {"unique_domains": ["evil.pastebin.com", "c2.onion.link"]}
        vulns = self.tool._check_dns_vulns(dns_data)
        assert len(vulns) > 0
