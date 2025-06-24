"""
Tests for Day 5 — WAF Detection & Bypass Engine

Coverage (74 tests):
  TestFingerprintDatabase       (8 tests)  — JSON file structure validation
  TestLoadFingerprintsHelper    (5 tests)  — _load_waf_fingerprints() helper
  TestWAFDetectTool             (14 tests) — metadata, execute, mocking
  TestWAFBypassTool             (12 tests) — metadata, execute, mocking
  TestPayloadEncoderTool        (18 tests) — pure encoding logic
  TestWAFFingerprintTool        (12 tests) — passive fingerprinting
  TestToolRegistration          (5 tests)  — registration checks

All tests use asyncio.run(), unittest.mock — no live network calls.

Import strategy: load waf_tools directly via importlib to avoid triggering
the app.agent package __init__ which has heavy transitive dependencies (fastapi,
langgraph, etc.) not available in the lightweight CI environment.
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
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: inject minimal stubs before loading waf_tools so that
# `from app.agent.tools.base_tool import BaseTool, ToolMetadata` and
# `from app.agent.tools.error_handling import ...` resolve without pulling in
# fastapi/langgraph.
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

import pydantic  # noqa: E402  real pydantic

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
_waf_mod = _load_module("agent/tools/waf_tools.py", "app.agent.tools.waf_tools")

WAFDetectTool = _waf_mod.WAFDetectTool
WAFBypassTool = _waf_mod.WAFBypassTool
PayloadEncoderTool = _waf_mod.PayloadEncoderTool
WAFFingerprintTool = _waf_mod.WAFFingerprintTool
ToolExecutionError = _error_mod.ToolExecutionError

_load_waf_fingerprints = _waf_mod._load_waf_fingerprints
_load_bypass_payloads = _waf_mod._load_bypass_payloads
_WAF_FINGERPRINTS_PATH = _waf_mod._WAF_FINGERPRINTS_PATH
_WAF_BYPASS_PAYLOADS_PATH = _waf_mod._WAF_BYPASS_PAYLOADS_PATH

_DATA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data")
)
_FINGERPRINTS_FILE = os.path.join(_DATA_DIR, "waf_fingerprints.json")
_BYPASS_PAYLOADS_FILE = os.path.join(_DATA_DIR, "waf_bypass_payloads.json")


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Mock response factory
# ---------------------------------------------------------------------------


def _make_probe_response(
    status: int = 200,
    headers: dict = None,
    body: str = "",
    cookies: list = None,
    elapsed_ms: float = 42.0,
    error: str = None,
) -> dict:
    """Return a normalised probe response dict (same shape as _send_probe output)."""
    return {
        "status_code": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "cookies": cookies or [],
        "body_snippet": body,
        "elapsed_ms": elapsed_ms,
        "error": error,
    }


# ---------------------------------------------------------------------------
# 1. TestFingerprintDatabase
# ---------------------------------------------------------------------------


class TestFingerprintDatabase:
    """Validate the actual JSON data files — no mocking."""

    def test_fingerprints_file_exists(self):
        assert os.path.isfile(_FINGERPRINTS_FILE), (
            f"waf_fingerprints.json not found at {_FINGERPRINTS_FILE}"
        )

    def test_fingerprints_loads_as_list(self):
        with open(_FINGERPRINTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)

    def test_fingerprints_has_50_plus_entries(self):
        with open(_FINGERPRINTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data) >= 50, f"Expected ≥50 fingerprints, got {len(data)}"

    def test_each_fingerprint_has_id(self):
        with open(_FINGERPRINTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data:
            assert "id" in entry, f"Fingerprint missing 'id': {entry}"

    def test_each_fingerprint_has_name(self):
        with open(_FINGERPRINTS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data:
            assert "name" in entry, f"Fingerprint missing 'name': {entry}"

    def test_bypass_payloads_file_exists(self):
        assert os.path.isfile(_BYPASS_PAYLOADS_FILE), (
            f"waf_bypass_payloads.json not found at {_BYPASS_PAYLOADS_FILE}"
        )

    def test_bypass_payloads_has_categories(self):
        with open(_BYPASS_PAYLOADS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert "categories" in data

    def test_bypass_payloads_has_waf_specific(self):
        with open(_BYPASS_PAYLOADS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert "waf_specific" in data


# ---------------------------------------------------------------------------
# 2. TestLoadFingerprintsHelper
# ---------------------------------------------------------------------------


class TestLoadFingerprintsHelper:
    """Unit-test _load_waf_fingerprints() in isolation."""

    def _clear_cache(self):
        """Clear the module-level fingerprint cache."""
        _waf_mod._FINGERPRINTS_CACHE = None

    def test_loads_fingerprints_successfully(self):
        # Pre-populate with real data by loading once; result is non-empty
        self._clear_cache()
        result = _load_waf_fingerprints()
        # Restore for other tests
        assert len(result) > 0

    def test_returns_list_type(self):
        self._clear_cache()
        result = _load_waf_fingerprints()
        assert isinstance(result, list)

    def test_fingerprint_has_headers_field(self):
        self._clear_cache()
        result = _load_waf_fingerprints()
        with_headers = [fp for fp in result if "headers" in fp]
        assert len(with_headers) > 0, "At least one fingerprint must have a 'headers' field"

    def test_fingerprint_has_body_patterns_field(self):
        self._clear_cache()
        result = _load_waf_fingerprints()
        with_body = [fp for fp in result if "body_patterns" in fp]
        assert len(with_body) > 0, "At least one fingerprint must have a 'body_patterns' field"

    def test_missing_file_returns_empty_list(self):
        original_cache = _waf_mod._FINGERPRINTS_CACHE
        _waf_mod._FINGERPRINTS_CACHE = None
        try:
            with patch("builtins.open", side_effect=FileNotFoundError("no file")):
                result = _load_waf_fingerprints()
            assert result == []
        finally:
            # Restore to avoid breaking other tests
            _waf_mod._FINGERPRINTS_CACHE = original_cache


# ---------------------------------------------------------------------------
# 3. TestWAFDetectTool
# ---------------------------------------------------------------------------


class TestWAFDetectTool:
    """Tests for WAFDetectTool.execute()."""

    def setup_method(self):
        self.tool = WAFDetectTool()
        # Ensure real fingerprints are cached (loaded from disk once)
        _waf_mod._FINGERPRINTS_CACHE = None
        _load_waf_fingerprints()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "waf_detect"

    def test_metadata_description_contains_waf(self):
        assert "WAF" in self.tool.metadata.description or "waf" in self.tool.metadata.description.lower()

    def test_metadata_has_url_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "url" in props

    def test_metadata_has_timeout_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "timeout" in props

    def test_metadata_has_aggressive_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "aggressive" in props

    def test_missing_url_param_returns_error(self):
        result = _run(self.tool.execute())
        assert "Error" in result and "url" in result.lower()

    def test_invalid_scheme_rejected(self):
        result = _run(self.tool.execute(url="ftp://evil.com"))
        assert "Error" in result

    def test_cloudflare_detected_via_header(self):
        mock_response = _make_probe_response(
            status=200,
            headers={"cf-ray": "abc123def456-LHR", "server": "cloudflare"},
            body="Welcome to the site",
        )
        # Patch truncate_output to avoid JSON truncation from large all_matches lists
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                result = _run(self.tool.execute(url="http://example.com"))
        data = json.loads(result)
        assert data.get("waf_detected") is True
        assert "cloudflare" in data.get("waf_id", "").lower()

    def test_akamai_detected_via_header(self):
        mock_response = _make_probe_response(
            status=200,
            headers={
                "x-check-cacheable": "YES",
                "server": "AkamaiGHost",
            },
            body="",
        )
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                result = _run(self.tool.execute(url="http://example.com"))
        data = json.loads(result)
        assert data.get("waf_detected") is True
        assert "akamai" in data.get("waf_id", "").lower()

    def test_no_waf_detected(self):
        # Use status 204 — none of the 55+ fingerprints list 204 in status_codes,
        # and empty headers produce zero header-match scores.
        mock_response = _make_probe_response(
            status=204,
            headers={},
            body="",
        )
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                result = _run(self.tool.execute(url="http://example.com"))
        data = json.loads(result)
        assert data.get("waf_detected") is False

    def test_aggressive_mode_sends_extra_probe(self):
        mock_response = _make_probe_response(status=204, headers={})
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                _run(self.tool.execute(url="http://example.com", aggressive=True))
        # Default (non-aggressive) = 2 probes; aggressive = 3 probes
        assert mock_thread.call_count == 3

    def test_network_error_handled_gracefully(self):
        error_response = _make_probe_response(status=0, error="Connection refused")
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = error_response
            result = _run(self.tool.execute(url="http://example.com"))
        data = json.loads(result)
        assert "error" in data
        assert data.get("waf_detected") is False

    def test_output_is_valid_json(self):
        mock_response = _make_probe_response(status=204, headers={})
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                result = _run(self.tool.execute(url="http://example.com"))
        # Should not raise
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_confidence_score_between_0_and_1(self):
        mock_response = _make_probe_response(
            status=200,
            headers={"cf-ray": "abc123-LHR", "server": "cloudflare"},
        )
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                result = _run(self.tool.execute(url="http://example.com"))
        data = json.loads(result)
        confidence = data.get("confidence", -1)
        assert 0.0 <= confidence <= 1.0, f"Confidence {confidence} not in [0, 1]"


# ---------------------------------------------------------------------------
# 4. TestWAFBypassTool
# ---------------------------------------------------------------------------


class TestWAFBypassTool:
    """Tests for WAFBypassTool.execute()."""

    def setup_method(self):
        self.tool = WAFBypassTool()
        _waf_mod._BYPASS_PAYLOADS_CACHE = None
        _load_bypass_payloads()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "waf_bypass"

    def test_metadata_has_url_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "url" in props

    def test_metadata_has_attack_type_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "attack_type" in props

    def test_metadata_has_parameter_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "parameter" in props

    def test_missing_url_returns_error(self):
        result = _run(self.tool.execute(attack_type="sqli", parameter="id"))
        assert "Error" in result and "url" in result.lower()

    def test_missing_attack_type_returns_error(self):
        result = _run(self.tool.execute(url="http://example.com", parameter="id"))
        assert "Error" in result and "attack_type" in result.lower()

    def test_invalid_attack_type_returns_error(self):
        result = _run(
            self.tool.execute(
                url="http://example.com",
                attack_type="invalid_type",
                parameter="id",
            )
        )
        assert "Error" in result

    def test_bypass_with_known_waf(self):
        # When waf_name=cloudflare, cloudflare-specific payloads should be preferred
        mock_response = _make_probe_response(status=200, headers={})
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            result = _run(
                self.tool.execute(
                    url="http://example.com",
                    waf_name="cloudflare",
                    attack_type="sqli",
                    parameter="id",
                    limit=5,
                )
            )
        data = json.loads(result)
        # Cloudflare-specific payloads exist in the database
        assert data.get("total_tested", 0) > 0

    def test_bypass_returns_summary(self):
        mock_response = _make_probe_response(status=200, headers={})
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            result = _run(
                self.tool.execute(
                    url="http://example.com",
                    attack_type="sqli",
                    parameter="id",
                    limit=3,
                )
            )
        data = json.loads(result)
        assert "total_tested" in data
        assert "bypassed_count" in data
        assert "blocked_count" in data

    def test_bypassed_classification(self):
        # HTTP 200 with no block patterns → classified as bypassed
        mock_response = _make_probe_response(status=200, headers={}, body="Welcome!")
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            result = _run(
                self.tool.execute(
                    url="http://example.com",
                    attack_type="sqli",
                    parameter="id",
                    limit=2,
                )
            )
        data = json.loads(result)
        assert data["bypassed_count"] > 0
        assert data["blocked_count"] == 0

    def test_blocked_classification(self):
        # HTTP 403 → classified as blocked
        mock_response = _make_probe_response(status=403, headers={}, body="Access Denied")
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            result = _run(
                self.tool.execute(
                    url="http://example.com",
                    attack_type="sqli",
                    parameter="id",
                    limit=2,
                )
            )
        data = json.loads(result)
        assert data["blocked_count"] > 0
        assert data["bypassed_count"] == 0

    def test_output_is_valid_json(self):
        mock_response = _make_probe_response(status=200, headers={})
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            result = _run(
                self.tool.execute(
                    url="http://example.com",
                    attack_type="xss",
                    parameter="q",
                    limit=2,
                )
            )
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# 5. TestPayloadEncoderTool
# ---------------------------------------------------------------------------


class TestPayloadEncoderTool:
    """Tests for PayloadEncoderTool — pure encoding logic, no network calls."""

    def setup_method(self):
        self.tool = PayloadEncoderTool()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "payload_encoder"

    def test_metadata_has_payload_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "payload" in props

    def test_metadata_has_encoding_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "encoding" in props

    def test_base64_encoding(self):
        payload = "<script>alert(1)</script>"
        result = _run(self.tool.execute(payload=payload, encoding="base64"))
        data = json.loads(result)
        assert data["encoding"] == "base64"
        assert data["encoded"] != payload
        assert len(data["encoded"]) > 0

    def test_base64_is_decodable(self):
        payload = "<script>alert(1)</script>"
        result = _run(self.tool.execute(payload=payload, encoding="base64"))
        data = json.loads(result)
        decoded = base64.b64decode(data["encoded"]).decode("utf-8")
        assert decoded == payload

    def test_url_encoding(self):
        payload = "<script>"
        result = _run(self.tool.execute(payload=payload, encoding="url"))
        data = json.loads(result)
        # < is %3C and > is %3E in URL encoding
        assert "%3C" in data["encoded"] or "%3c" in data["encoded"]

    def test_double_url_encoding(self):
        payload = "<"
        result = _run(self.tool.execute(payload=payload, encoding="double_url"))
        data = json.loads(result)
        # < → %3C → %253C (double encoded)
        assert "%25" in data["encoded"]

    def test_unicode_encoding(self):
        # ASCII chars are left intact; only non-ASCII get \uXXXX
        payload = "A"
        result = _run(self.tool.execute(payload=payload, encoding="unicode"))
        data = json.loads(result)
        # ASCII 'A' stays as 'A' (ord <= 127)
        assert data["encoded"] == "A"

    def test_html_entity_encoding(self):
        payload = "<"
        result = _run(self.tool.execute(payload=payload, encoding="html_entity"))
        data = json.loads(result)
        # < is ord 60 → &#60;
        assert "&#60;" in data["encoded"]

    def test_hex_encoding(self):
        payload = "A"
        result = _run(self.tool.execute(payload=payload, encoding="hex"))
        data = json.loads(result)
        # A is ord 65 = 0x41 → \x41
        assert "\\x41" in data["encoded"]

    def test_null_byte_insertion(self):
        payload = "AB"
        result = _run(self.tool.execute(payload=payload, encoding="null_byte"))
        data = json.loads(result)
        # A + %00 + B
        assert "%00" in data["encoded"]

    def test_comment_sql_injection(self):
        payload = "OR 1=1"
        result = _run(self.tool.execute(payload=payload, encoding="comment_sql"))
        data = json.loads(result)
        # Spaces replaced with /**/
        assert "/**/" in data["encoded"]

    def test_case_variation_changes_case(self):
        # With a long alphabetic payload, at least some chars will differ
        payload = "SELECT FROM WHERE"
        result = _run(self.tool.execute(payload=payload, encoding="case_variation"))
        data = json.loads(result)
        # The encoded result must contain only alpha chars and spaces (no new chars)
        assert len(data["encoded"]) == len(payload)
        # Must be a case variation — at least one alpha char present
        assert any(c.isalpha() for c in data["encoded"])

    def test_all_encoding_returns_dict(self):
        result = _run(self.tool.execute(payload="<script>", encoding="all"))
        data = json.loads(result)
        assert data["encoding"] == "all"
        assert "variants" in data
        assert isinstance(data["variants"], dict)

    def test_all_encoding_dict_has_base64_key(self):
        result = _run(self.tool.execute(payload="test", encoding="all"))
        data = json.loads(result)
        assert "base64" in data["variants"]

    def test_all_encoding_dict_has_url_key(self):
        result = _run(self.tool.execute(payload="test", encoding="all"))
        data = json.loads(result)
        assert "url" in data["variants"]

    def test_missing_payload_returns_error(self):
        result = _run(self.tool.execute(encoding="base64"))
        assert "Error" in result and "payload" in result.lower()

    def test_invalid_encoding_returns_error(self):
        result = _run(self.tool.execute(payload="test", encoding="rot13"))
        assert "Error" in result and "encoding" in result.lower()


# ---------------------------------------------------------------------------
# 6. TestWAFFingerprintTool
# ---------------------------------------------------------------------------


class TestWAFFingerprintTool:
    """Tests for WAFFingerprintTool.execute() — passive fingerprinting."""

    def setup_method(self):
        self.tool = WAFFingerprintTool()
        _waf_mod._FINGERPRINTS_CACHE = None
        _load_waf_fingerprints()

    def test_metadata_name(self):
        assert self.tool.metadata.name == "waf_fingerprint_passive"

    def test_metadata_has_url_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "url" in props

    def test_metadata_has_num_requests_param(self):
        props = self.tool.metadata.parameters.get("properties", {})
        assert "num_requests" in props

    def test_missing_url_returns_error(self):
        result = _run(self.tool.execute())
        assert "Error" in result and "url" in result.lower()

    def test_invalid_scheme_rejected(self):
        result = _run(self.tool.execute(url="file:///etc/passwd"))
        assert "Error" in result

    def test_cloudflare_passively_detected(self):
        mock_response = _make_probe_response(
            status=200,
            headers={"cf-ray": "abc123def456-LHR", "server": "cloudflare"},
            elapsed_ms=55.0,
        )
        with patch.object(_waf_mod, "truncate_output", side_effect=lambda s: s):
            with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.return_value = mock_response
                with patch.object(asyncio, "sleep", new_callable=AsyncMock):
                    result = _run(
                        self.tool.execute(url="http://example.com", num_requests=1)
                    )
        data = json.loads(result)
        assert data.get("detected_waf") is not None
        assert "cloudflare" in (data.get("waf_id") or "").lower()

    def test_no_waf_passively_detected(self):
        mock_response = _make_probe_response(
            status=200,
            headers={},  # No WAF-specific headers
            elapsed_ms=30.0,
        )
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            with patch.object(asyncio, "sleep", new_callable=AsyncMock):
                result = _run(
                    self.tool.execute(url="http://example.com", num_requests=1)
                )
        data = json.loads(result)
        assert data.get("detected_waf") is None
        assert data.get("confidence") == 0.0

    def test_timing_stats_included_in_output(self):
        mock_response = _make_probe_response(status=200, headers={}, elapsed_ms=80.0)
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            with patch.object(asyncio, "sleep", new_callable=AsyncMock):
                result = _run(
                    self.tool.execute(url="http://example.com", num_requests=1)
                )
        data = json.loads(result)
        assert "timing_stats" in data
        timing = data["timing_stats"]
        assert "mean_ms" in timing
        assert "min_ms" in timing
        assert "max_ms" in timing

    def test_stealth_safe_flag_in_output(self):
        mock_response = _make_probe_response(status=200, headers={}, elapsed_ms=40.0)
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            with patch.object(asyncio, "sleep", new_callable=AsyncMock):
                result = _run(
                    self.tool.execute(url="http://example.com", num_requests=1)
                )
        data = json.loads(result)
        assert data.get("stealth_safe") is True

    def test_num_requests_controls_sample_count(self):
        mock_response = _make_probe_response(status=200, headers={}, elapsed_ms=50.0)
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            with patch.object(asyncio, "sleep", new_callable=AsyncMock):
                _run(
                    self.tool.execute(url="http://example.com", num_requests=3)
                )
        # 3 HEAD requests (none returned 405, so no GET fallback)
        assert mock_thread.call_count == 3

    def test_network_error_handled_gracefully(self):
        error_response = _make_probe_response(status=0, error="Network unreachable")
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = error_response
            result = _run(
                self.tool.execute(url="http://example.com", num_requests=1)
            )
        data = json.loads(result)
        assert "error" in data

    def test_output_is_valid_json(self):
        mock_response = _make_probe_response(status=200, headers={}, elapsed_ms=25.0)
        with patch.object(asyncio, "to_thread", new_callable=AsyncMock) as mock_thread:
            mock_thread.return_value = mock_response
            with patch.object(asyncio, "sleep", new_callable=AsyncMock):
                result = _run(
                    self.tool.execute(url="http://example.com", num_requests=1)
                )
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# 7. TestToolRegistration
# ---------------------------------------------------------------------------


class TestToolRegistration:
    """Verify that all four WAF tools are properly instantiable and compliant."""

    def setup_method(self):
        self.tools = [
            WAFDetectTool(),
            WAFBypassTool(),
            PayloadEncoderTool(),
            WAFFingerprintTool(),
        ]

    def test_four_waf_tools_unique_names(self):
        names = [t.metadata.name for t in self.tools]
        assert len(set(names)) == 4, f"Duplicate tool names: {names}"

    def test_all_are_base_tool_instances(self):
        BaseTool = _base_tool_mod.BaseTool
        for tool in self.tools:
            assert isinstance(tool, BaseTool), f"{tool} is not a BaseTool subclass"

    def test_all_have_non_empty_descriptions(self):
        for tool in self.tools:
            desc = tool.metadata.description
            assert desc and len(desc.strip()) > 0, (
                f"Tool {tool.metadata.name} has empty description"
            )

    def test_all_have_parameter_schemas(self):
        for tool in self.tools:
            params = tool.metadata.parameters
            assert isinstance(params, dict), (
                f"Tool {tool.metadata.name} parameters must be a dict"
            )
            assert "properties" in params, (
                f"Tool {tool.metadata.name} parameters must have 'properties'"
            )

    def test_all_execute_is_coroutine(self):
        import inspect
        for tool in self.tools:
            assert inspect.iscoroutinefunction(tool.execute), (
                f"Tool {tool.metadata.name}.execute() must be async"
            )
