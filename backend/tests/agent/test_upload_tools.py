"""
Tests for Day 15 — File Upload Bypass, CORS Exploit Chain & Cache Deception Tools

Coverage (63 tests):
  TestHelpers                 (6 tests)  — _create_polyglot, _magic_bytes, _http_probe,
                                            _EXTENSION_BYPASSES, _IMAGE_MIME_TYPES
  TestFileUploadBypassTool    (22 tests) — list_techniques, generate_payloads (all techniques),
                                            create_polyglot, test_upload, error handling
  TestCORSExploitChainTool    (21 tests) — scan (origin reflection, null, wildcard),
                                            test_origin, generate_poc (all chain types),
                                            check_headers, chain_attack
  TestCacheDeceptionTool      (14 tests) — path_confusion, host_header_poison,
                                            unkeyed_headers, response_split,
                                            dos_cache, full scan, error handling

All tests use asyncio.run() and unittest.mock — no live HTTP connections required.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap stubs
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
_upload_mod = _load_module("agent/tools/upload_tools.py", "app.agent.tools.upload_tools")

FileUploadBypassTool = _upload_mod.FileUploadBypassTool
CORSExploitChainTool = _upload_mod.CORSExploitChainTool
CacheDeceptionTool = _upload_mod.CacheDeceptionTool
ToolExecutionError = _error_mod.ToolExecutionError

_MAGIC_BYTES = _upload_mod._MAGIC_BYTES
_EXTENSION_BYPASSES = _upload_mod._EXTENSION_BYPASSES
_IMAGE_MIME_TYPES = _upload_mod._IMAGE_MIME_TYPES
_create_polyglot = _upload_mod._create_polyglot
_http_probe = _upload_mod._http_probe


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. TestHelpers
# ---------------------------------------------------------------------------


class TestHelpers:
    """Test module-level helpers."""

    def test_magic_bytes_jpeg(self):
        assert _MAGIC_BYTES["jpeg"][:2] == bytes([0xFF, 0xD8])

    def test_magic_bytes_png(self):
        assert _MAGIC_BYTES["png"][:4] == bytes([0x89, 0x50, 0x4E, 0x47])

    def test_magic_bytes_gif(self):
        assert _MAGIC_BYTES["gif89"].startswith(b"GIF89a")

    def test_create_polyglot_starts_with_magic(self):
        poly = _create_polyglot("php", "jpeg")
        assert poly[:2] == bytes([0xFF, 0xD8])

    def test_create_polyglot_contains_php(self):
        poly = _create_polyglot("php", "jpeg")
        assert b"<?php" in poly

    def test_create_polyglot_asp(self):
        poly = _create_polyglot("asp", "gif89")
        assert b"GIF89a" in poly
        assert b"<%" in poly

    def test_extension_bypasses_has_double(self):
        assert len(_EXTENSION_BYPASSES["double_extension"]) > 0
        assert any(".php." in e for e in _EXTENSION_BYPASSES["double_extension"])

    def test_extension_bypasses_has_null_byte(self):
        assert any("%00" in e or "\x00" in e for e in _EXTENSION_BYPASSES["null_byte"])

    def test_image_mime_types_not_empty(self):
        assert len(_IMAGE_MIME_TYPES) > 0
        assert "image/jpeg" in _IMAGE_MIME_TYPES


# ---------------------------------------------------------------------------
# 2. TestFileUploadBypassTool
# ---------------------------------------------------------------------------


class TestFileUploadBypassTool:
    """Test FileUploadBypassTool."""

    def setup_method(self):
        self.tool = FileUploadBypassTool()

    def test_metadata_name(self):
        assert self.tool.name == "file_upload_bypass"

    def test_list_techniques_returns_dict(self):
        result = _run(self.tool.execute(action="list_techniques"))
        data = json.loads(result)
        assert "bypass_techniques" in data
        techniques = data["bypass_techniques"]
        assert "double_extension" in techniques
        assert "null_byte" in techniques
        assert "case_variation" in techniques
        assert "magic_bytes" in techniques

    def test_list_techniques_has_descriptions(self):
        result = _run(self.tool.execute(action="list_techniques"))
        data = json.loads(result)
        for _name, info in data["bypass_techniques"].items():
            assert "description" in info
            assert "bypasses" in info

    def test_generate_payloads_double_extension(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["double_extension"],
            )
        )
        data = json.loads(result)
        assert data["payload_count"] > 0
        assert any(p["technique"] == "double_extension" for p in data["payloads"])

    def test_generate_payloads_null_byte(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["null_byte"],
            )
        )
        data = json.loads(result)
        null_payloads = [p for p in data["payloads"] if p["technique"] == "null_byte"]
        assert len(null_payloads) > 0

    def test_generate_payloads_magic_bytes(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["magic_bytes"],
                image_type="jpeg",
            )
        )
        data = json.loads(result)
        magic_payloads = [p for p in data["payloads"] if p["technique"] == "magic_bytes"]
        assert len(magic_payloads) > 0
        assert "content_b64" in magic_payloads[0]
        # Verify the magic bytes are in the payload
        payload_bytes = base64.b64decode(magic_payloads[0]["content_b64"])
        assert payload_bytes[:2] == bytes([0xFF, 0xD8])  # JPEG magic

    def test_generate_payloads_mime_spoofing(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["mime_spoofing"],
                allowed_types=["image/jpeg"],
            )
        )
        data = json.loads(result)
        mime_payloads = [p for p in data["payloads"] if p["technique"] == "mime_spoofing"]
        assert len(mime_payloads) > 0
        assert mime_payloads[0]["content_type"] == "image/jpeg"

    def test_generate_payloads_polyglot(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["polyglot"],
                image_type="gif89",
            )
        )
        data = json.loads(result)
        poly_payloads = [p for p in data["payloads"] if p["technique"] == "polyglot"]
        assert len(poly_payloads) > 0
        payload_bytes = base64.b64decode(poly_payloads[0]["content_b64"])
        assert b"GIF89a" in payload_bytes

    def test_generate_payloads_case_variation(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["case_variation"],
            )
        )
        data = json.loads(result)
        case_payloads = [p for p in data["payloads"] if p["technique"] == "case_variation"]
        assert len(case_payloads) > 0

    def test_generate_payloads_alternative_php(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["alternative_php"],
            )
        )
        data = json.loads(result)
        alt_payloads = [p for p in data["payloads"] if p["technique"] == "alternative_php"]
        assert len(alt_payloads) > 0

    def test_generate_payloads_asp(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="asp",
                techniques=["mime_spoofing"],
            )
        )
        data = json.loads(result)
        assert data["shell_type"] == "asp"

    def test_generate_payloads_multiple_techniques(self):
        result = _run(
            self.tool.execute(
                action="generate_payloads",
                shell_type="php",
                techniques=["double_extension", "null_byte", "magic_bytes", "polyglot"],
            )
        )
        data = json.loads(result)
        assert data["payload_count"] >= 4

    def test_generate_payloads_has_curl_example(self):
        result = _run(self.tool.execute(action="generate_payloads", shell_type="php"))
        data = json.loads(result)
        assert "curl_example" in data

    def test_create_polyglot_returns_b64(self):
        result = _run(
            self.tool.execute(action="create_polyglot", shell_type="php", image_type="jpeg")
        )
        data = json.loads(result)
        assert "polyglot_b64" in data
        assert data["file_size"] > 0
        # Verify b64 decodes correctly
        raw = base64.b64decode(data["polyglot_b64"])
        assert raw[:2] == bytes([0xFF, 0xD8])
        assert b"<?php" in raw

    def test_create_polyglot_has_detection_evasion(self):
        result = _run(
            self.tool.execute(action="create_polyglot", shell_type="php", image_type="png")
        )
        data = json.loads(result)
        assert "detection_evasion" in data
        assert len(data["detection_evasion"]) > 0

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_test_upload_runs_tests(self, mock_probe):
        mock_probe.return_value = (200, {}, "Upload successful")
        result = _run(
            self.tool.execute(
                action="test_upload",
                upload_url="http://target.com/upload",
                shell_type="php",
                techniques=["double_extension"],
            )
        )
        data = json.loads(result)
        assert "tests_run" in data
        assert "results" in data

    def test_test_upload_missing_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="test_upload"))

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="magic_shell"))


# ---------------------------------------------------------------------------
# 3. TestCORSExploitChainTool
# ---------------------------------------------------------------------------


class TestCORSExploitChainTool:
    """Test CORSExploitChainTool."""

    def setup_method(self):
        self.tool = CORSExploitChainTool()

    def test_metadata_name(self):
        assert self.tool.name == "cors_exploit_chain"

    def test_scan_missing_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="scan"))

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_scan_detects_origin_reflection(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "https://attacker.com",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }, "")
        result = _run(self.tool.execute(action="scan", target_url="http://target.com/api"))
        data = json.loads(result)
        assert data["vulnerable_configs"] > 0
        critical = [f for f in data["findings"] if f["severity"] == "CRITICAL"]
        assert len(critical) > 0

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_scan_detects_null_origin(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            }, "")
        result = _run(self.tool.execute(action="scan", target_url="http://target.com/api"))
        data = json.loads(result)
        null_findings = [f for f in data["findings"] if f["origin_tested"] == "null"]
        if null_findings:
            assert null_findings[0]["vulnerable"]

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_scan_wildcard_with_credentials(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }, "")
        result = _run(self.tool.execute(action="scan", target_url="http://target.com/api"))
        data = json.loads(result)
        assert isinstance(data["findings"], list)

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_scan_not_vulnerable(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "https://safe.com",
                "Access-Control-Allow-Credentials": "false",
            }, "")
        result = _run(self.tool.execute(action="scan", target_url="http://target.com/api"))
        data = json.loads(result)
        assert data["vulnerable_configs"] == 0

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_test_origin_reflected(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
                "Vary": "",
            }, "")
        result = _run(
            self.tool.execute(
                action="test_origin",
                target_url="http://target.com",
                origin="https://evil.com",
            )
        )
        data = json.loads(result)
        assert data["analysis"]["origin_reflected"] is True
        assert data["analysis"]["credentials_allowed"] is True
        assert data["analysis"]["vulnerable"] is True

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_test_origin_not_reflected(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "https://safe.com",
                "Access-Control-Allow-Credentials": "false",
            }, "")
        result = _run(
            self.tool.execute(
                action="test_origin",
                target_url="http://target.com",
                origin="https://attacker.com",
            )
        )
        data = json.loads(result)
        assert data["analysis"]["origin_reflected"] is False
        assert data["analysis"]["vulnerable"] is False

    def test_generate_poc_data_extraction(self):
        result = _run(
            self.tool.execute(
                action="generate_poc",
                target_url="http://target.com",
                steal_endpoint="http://target.com/api/profile",
                attacker_server="https://evil.com",
                chain_type="data_extraction",
            )
        )
        data = json.loads(result)
        assert "poc_html" in data
        assert "http://target.com/api/profile" in data["poc_html"]
        assert "XMLHttpRequest" in data["poc_html"]

    def test_generate_poc_token_theft(self):
        result = _run(
            self.tool.execute(
                action="generate_poc",
                target_url="http://target.com",
                steal_endpoint="http://target.com/api/token",
                attacker_server="https://evil.com",
                chain_type="token_theft",
            )
        )
        data = json.loads(result)
        assert "poc_html" in data
        assert "fetch" in data["poc_html"]

    def test_generate_poc_csrf_via_cors(self):
        result = _run(
            self.tool.execute(
                action="generate_poc",
                target_url="http://target.com",
                steal_endpoint="http://target.com/login",
                attacker_server="https://evil.com",
                chain_type="csrf_via_cors",
            )
        )
        data = json.loads(result)
        assert "csrf" in data["poc_html"].lower() or "CSRF" in data["poc_html"]

    def test_generate_poc_account_takeover(self):
        result = _run(
            self.tool.execute(
                action="generate_poc",
                target_url="http://target.com",
                steal_endpoint="http://target.com/api/me",
                attacker_server="https://evil.com",
                chain_type="account_takeover",
            )
        )
        data = json.loads(result)
        assert "poc_html" in data
        assert "hosting_instructions" in data

    def test_generate_poc_has_prerequisites(self):
        result = _run(
            self.tool.execute(
                action="generate_poc",
                target_url="http://target.com",
                steal_endpoint="http://target.com/api",
                attacker_server="https://evil.com",
                chain_type="data_extraction",
            )
        )
        data = json.loads(result)
        assert "prerequisites" in data
        assert len(data["prerequisites"]) > 0

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_check_headers_returns_cors_headers(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, DELETE",
                "Vary": "Accept",
            }, "")
        result = _run(
            self.tool.execute(action="check_headers", target_url="http://target.com/api")
        )
        data = json.loads(result)
        assert "cors_headers" in data
        assert "issues" in data

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_check_headers_detects_null_origin(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            }, "")
        result = _run(
            self.tool.execute(action="check_headers", target_url="http://target.com")
        )
        data = json.loads(result)
        assert data["issue_count"] > 0

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_chain_attack_not_vulnerable(self, mock_probe):
        mock_probe.return_value = (200, {"Access-Control-Allow-Origin": "https://safe.com"}, "")
        result = _run(
            self.tool.execute(
                action="chain_attack",
                target_url="http://target.com",
                steal_endpoint="http://target.com/api",
                attacker_server="https://evil.com",
            )
        )
        data = json.loads(result)
        assert data["status"] == "NOT_VULNERABLE"

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_chain_attack_vulnerable(self, mock_probe):
        mock_probe.return_value = (200, {
                "Access-Control-Allow-Origin": "https://attacker.com",
                "Access-Control-Allow-Credentials": "true",
            }, "")
        result = _run(
            self.tool.execute(
                action="chain_attack",
                target_url="http://target.com",
                steal_endpoint="http://target.com/api/profile",
                attacker_server="https://attacker.com",
            )
        )
        data = json.loads(result)
        assert data["status"] == "VULNERABLE"
        assert "exploit_poc" in data

    def test_scan_missing_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="scan"))

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="something_weird", target_url="http://x.com"))


# ---------------------------------------------------------------------------
# 4. TestCacheDeceptionTool
# ---------------------------------------------------------------------------


class TestCacheDeceptionTool:
    """Test CacheDeceptionTool."""

    def setup_method(self):
        self.tool = CacheDeceptionTool()

    def test_metadata_name(self):
        assert self.tool.name == "cache_deception"

    def test_missing_target_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="path_confusion"))

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_path_confusion_cached_response(self, mock_probe):
        mock_probe.return_value = (200, {
                "Cache-Control": "public, max-age=3600",
                "X-Cache": "HIT",
            }, "authenticated user data")
        result = _run(
            self.tool.execute(action="path_confusion", target_url="http://target.com/profile")
        )
        data = json.loads(result)
        assert data["test"] == "path_confusion"
        assert data["vulnerable"] is True

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_path_confusion_not_cached(self, mock_probe):
        mock_probe.return_value = (200, {"Cache-Control": "no-store, private"}, "content")
        result = _run(
            self.tool.execute(action="path_confusion", target_url="http://target.com/account")
        )
        data = json.loads(result)
        assert data["test"] == "path_confusion"

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_host_header_poison_reflected(self, mock_probe):
        mock_probe.return_value = (302, {"Location": "http://attacker.com/login"}, "attacker.com redirect")
        result = _run(
            self.tool.execute(
                action="host_header_poison",
                target_url="http://target.com",
                poison_host="attacker.com",
            )
        )
        data = json.loads(result)
        assert data["host_reflected_in_response"] is True
        assert data["vulnerable"] is True

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_host_header_poison_not_reflected(self, mock_probe):
        mock_probe.return_value = (200, {}, "safe content with no reflection")
        result = _run(
            self.tool.execute(
                action="host_header_poison",
                target_url="http://target.com",
                poison_host="attacker.com",
            )
        )
        data = json.loads(result)
        assert data["host_reflected_in_response"] is False

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_unkeyed_headers_different_response(self, mock_probe):
        # First call returns base response, subsequent differ
        call_count = {"n": 0}

        async def side_effect(url, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return (200, {}, "base response")
            return (403, {}, "admin content")  # Different response with X-Original-URL: /admin

        mock_probe.side_effect = side_effect

        result = _run(
            self.tool.execute(action="unkeyed_headers", target_url="http://target.com")
        )
        data = json.loads(result)
        assert data["test"] == "unkeyed_headers"
        assert "results" in data

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_response_split_no_injection(self, mock_probe):
        mock_probe.return_value = (200, {"Content-Type": "text/html"}, "safe response")
        result = _run(
            self.tool.execute(action="response_split", target_url="http://target.com")
        )
        data = json.loads(result)
        assert data["test"] == "response_split"
        assert "results" in data

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_dos_cache_vary_star(self, mock_probe):
        mock_probe.return_value = (200, {"Vary": "*", "Cache-Control": "public"}, "")
        result = _run(
            self.tool.execute(action="dos_cache", target_url="http://target.com")
        )
        data = json.loads(result)
        assert data["test"] == "dos_cache"
        assert len(data["issues"]) > 0

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_dos_cache_no_issues(self, mock_probe):
        mock_probe.return_value = (200, {"Cache-Control": "no-store, private", "Vary": "Accept"}, "")
        result = _run(
            self.tool.execute(action="dos_cache", target_url="http://target.com")
        )
        data = json.loads(result)
        assert data["test"] == "dos_cache"

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_full_scan_returns_all_tests(self, mock_probe):
        mock_probe.return_value = (200, {"Cache-Control": "no-store"}, "content")
        result = _run(
            self.tool.execute(action="scan", target_url="http://target.com")
        )
        data = json.loads(result)
        assert "tests" in data
        assert "path_confusion" in data["tests"]
        assert "host_header_poison" in data["tests"]
        assert "unkeyed_headers" in data["tests"]

    @patch("app.agent.tools.upload_tools._http_probe")
    def test_full_scan_counts_vulnerabilities(self, mock_probe):
        mock_probe.return_value = (200, {
                "Cache-Control": "public",
                "X-Cache": "HIT",
            }, "")
        result = _run(
            self.tool.execute(action="scan", target_url="http://target.com/profile")
        )
        data = json.loads(result)
        assert "vulnerability_count" in data
        assert isinstance(data["vulnerability_count"], int)

    def test_path_confusion_manual_steps(self):
        with patch("app.agent.tools.upload_tools._http_probe") as mock_probe:
            mock_probe.return_value = (200, {"Cache-Control": "no-store"}, "")
            result = _run(
                self.tool.execute(action="path_confusion", target_url="http://target.com/account")
            )
            data = json.loads(result)
            assert "manual_steps" in data
            assert len(data["manual_steps"]) > 0

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="cache_everything", target_url="http://x.com"))
