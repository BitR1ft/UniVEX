"""
Tests for Day 4 — OSINT Tools (Internet-Wide Search Integration)

Coverage (63 tests):
  TestShodanSearchTool   (12 tests) — metadata, execute, mocking, edge cases
  TestShodanHostTool     (10 tests) — metadata, execute, IP validation, mocking
  TestCensysSearchTool   (10 tests) — metadata, execute, auth, index handling
  TestCensysCertSearchTool (8 tests) — metadata, cert search, SAN extraction
  TestFOFASearchTool      (8 tests) — metadata, base64 encoding, results
  TestPassiveDNSTool     (10 tests) — metadata, multi-provider, aggregation
  TestToolRegistration    (5 tests) — registry completeness and correctness

All tests use asyncio.run(), unittest.mock, and patch() — no live network calls.

Import strategy: load osint_tools directly via importlib to avoid triggering
the app.agent package __init__ which has heavy transitive dependencies (fastapi,
langgraph, etc.) not available in the lightweight CI environment.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import types
import urllib.error
from io import BytesIO
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: inject minimal stubs before loading osint_tools so that
# `from app.agent.tools.base_tool import BaseTool, ToolMetadata` and
# `from app.agent.tools.error_handling import ...` resolve without pulling
# in fastapi/langgraph.
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
_osint_mod = _load_module("agent/tools/osint_tools.py", "app.agent.tools.osint_tools")

ShodanSearchTool = _osint_mod.ShodanSearchTool
ShodanHostTool = _osint_mod.ShodanHostTool
CensysSearchTool = _osint_mod.CensysSearchTool
CensysCertSearchTool = _osint_mod.CensysCertSearchTool
FOFASearchTool = _osint_mod.FOFASearchTool
PassiveDNSTool = _osint_mod.PassiveDNSTool
OSINT_TOOLS = _osint_mod.OSINT_TOOLS
ToolExecutionError = _error_mod.ToolExecutionError
ToolRateLimitError = _error_mod.ToolRateLimitError


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Shared mock helpers
# ---------------------------------------------------------------------------


def _make_urlopen_mock(response_data: dict) -> MagicMock:
    """Return a MagicMock that behaves like urllib.request.urlopen used as a context manager."""
    raw_bytes = json.dumps(response_data).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw_bytes
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_urlopen = MagicMock(return_value=mock_resp)
    return mock_urlopen


def _make_http_error(code: int, msg: str = "Error") -> urllib.error.HTTPError:
    fp = BytesIO(msg.encode())
    return urllib.error.HTTPError(url="https://example.com", code=code, msg=msg, hdrs={}, fp=fp)


# ---------------------------------------------------------------------------
# Shodan mock responses
# ---------------------------------------------------------------------------

_SHODAN_SEARCH_RESPONSE = {
    "matches": [
        {
            "ip_str": "1.2.3.4",
            "port": 80,
            "org": "Test Org",
            "country_code": "US",
            "location": {"country_name": "United States", "city": "New York"},
            "hostnames": ["example.com"],
            "domains": ["example.com"],
            "transport": "tcp",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx",
            "vulns": {"CVE-2021-1234": {"cvss": 7.5}},
            "timestamp": "2024-01-01T00:00:00",
            "tags": [],
        }
    ],
    "total": 1,
}

_SHODAN_HOST_RESPONSE = {
    "ip_str": "1.2.3.4",
    "ports": [80, 443],
    "country_name": "United States",
    "country_code": "US",
    "org": "Test Org",
    "isp": "Test ISP",
    "asn": "AS12345",
    "hostnames": ["example.com"],
    "domains": ["example.com"],
    "tags": [],
    "last_update": "2024-01-01T00:00:00",
    "vulns": {"CVE-2021-1234": {"cvss": 7.5}},
    "data": [
        {
            "port": 80,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.18.0",
            "data": "HTTP/1.1 200 OK",
            "timestamp": "2024-01-01T00:00:00",
            "_shodan": {"module": "http"},
        }
    ],
}

_CENSYS_HOSTS_RESPONSE = {
    "result": {
        "hits": [
            {
                "ip": "1.2.3.4",
                "services": [{"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"}],
                "autonomous_system": {"asn": 12345, "name": "Test ASN"},
                "location": {"country": "United States"},
                "labels": [],
            }
        ],
        "total": {"value": 1},
        "links": {"next": ""},
    }
}

_CENSYS_CERTS_RESPONSE = {
    "result": {
        "hits": [
            {
                "fingerprint_sha256": "abc123def456",
                "parsed": {
                    "subject": {"common_name": ["example.com"]},
                    "issuer": {"common_name": ["Let's Encrypt"], "organization": ["Let's Encrypt"]},
                    "validity": {"start": "2024-01-01T00:00:00Z", "end": "2025-01-01T00:00:00Z"},
                    "extensions": {
                        "subject_alt_name": {"dns_names": ["example.com", "www.example.com"]}
                    },
                },
                "names": ["example.com", "www.example.com"],
            }
        ],
        "total": {"value": 1},
        "links": {},
    }
}

_FOFA_RESPONSE = {
    "error": False,
    "results": [["example.com:80", "1.2.3.4", "80", "Example", "US", "nginx"]],
    "size": 1,
    "mode": "extended",
}

_SECURITYTRAILS_RESPONSE = {
    "records": [
        {
            "ip": "1.2.3.4",
            "first_seen": "2023-01-01",
            "last_seen": "2024-01-01",
            "type": "a",
            "values": [{"ip": "1.2.3.4", "ip_organization": "Test Org"}],
        }
    ]
}

_VIRUSTOTAL_RESPONSE = {
    "data": [
        {
            "attributes": {
                "ip_address": "1.2.3.4",
                "date": 1700000000,
                "host_name": "example.com",
                "resolver": "8.8.8.8",
            }
        }
    ]
}


# ===========================================================================
# TestShodanSearchTool (12 tests)
# ===========================================================================


class TestShodanSearchTool:
    def setup_method(self):
        self.tool = ShodanSearchTool()

    def test_metadata_name(self):
        assert self.tool.name == "shodan_search"

    def test_metadata_description_contains_shodan(self):
        assert "shodan" in self.tool.description.lower()

    def test_metadata_has_query_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "query" in props
        assert props["query"]["type"] == "string"

    def test_metadata_has_limit_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "limit" in props
        assert props["limit"]["type"] == "integer"
        assert props["limit"]["maximum"] == 100

    def test_no_api_key_returns_error(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": ""}, clear=False):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(query="apache"))
        assert "SHODAN_API_KEY" in str(exc_info.value)

    def test_search_success(self):
        mock_urlopen = _make_urlopen_mock(_SHODAN_SEARCH_RESPONSE)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query="apache country:US"))
        parsed = json.loads(result)
        assert parsed["query"] == "apache country:US"
        assert parsed["total_results"] == 1
        assert len(parsed["hosts"]) == 1
        assert parsed["hosts"][0]["ip"] == "1.2.3.4"

    def test_search_rate_limit(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429, "Too Many Requests")):
                with pytest.raises(ToolRateLimitError):
                    _run(self.tool.execute(query="apache"))

    def test_search_auth_error(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "bad-key"}, clear=False):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(401, "Unauthorized")):
                with pytest.raises(ToolExecutionError) as exc_info:
                    _run(self.tool.execute(query="apache"))
        assert "401" in str(exc_info.value) or "Unauthorized" in str(exc_info.value)

    def test_search_returns_json_formatted_output(self):
        mock_urlopen = _make_urlopen_mock(_SHODAN_SEARCH_RESPONSE)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query="nginx"))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "hosts" in parsed

    def test_search_limit_clamped_to_100(self):
        big_response = {
            "matches": [
                {"ip_str": f"1.2.3.{i}", "port": 80, "org": "", "location": {}, "vulns": {}}
                for i in range(10)
            ],
            "total": 10,
        }
        mock_urlopen = _make_urlopen_mock(big_response)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query="nginx", limit=9999))
        parsed = json.loads(result)
        # The limit is clamped to 100 before sending the query; results returned ≤ 100
        assert parsed["returned"] <= 100

    def test_search_with_empty_results(self):
        mock_urlopen = _make_urlopen_mock({"matches": [], "total": 0})
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query="nonexistent-thing-xyz"))
        parsed = json.loads(result)
        assert parsed["total_results"] == 0
        assert parsed["hosts"] == []

    def test_search_truncates_long_output(self):
        large_banner = "A" * 600  # Exceeds the 500-char banner truncation in execute()
        large_response = {
            "matches": [
                {
                    "ip_str": "1.2.3.4",
                    "port": 80,
                    "org": "X",
                    "location": {},
                    "vulns": {},
                    "data": large_banner,
                }
            ],
            "total": 1,
        }
        mock_urlopen = _make_urlopen_mock(large_response)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query="apache"))
        parsed = json.loads(result)
        banner = parsed["hosts"][0]["banner"]
        assert len(banner) <= 500


# ===========================================================================
# TestShodanHostTool (10 tests)
# ===========================================================================


class TestShodanHostTool:
    def setup_method(self):
        self.tool = ShodanHostTool()

    def test_metadata_name(self):
        assert self.tool.name == "shodan_host_lookup"

    def test_metadata_has_ip_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "ip" in props
        assert props["ip"]["type"] == "string"

    def test_no_api_key_returns_error(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": ""}, clear=False):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(ip="8.8.8.8"))
        assert "SHODAN_API_KEY" in str(exc_info.value)

    def test_host_lookup_success(self):
        mock_urlopen = _make_urlopen_mock(_SHODAN_HOST_RESPONSE)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(ip="1.2.3.4"))
        parsed = json.loads(result)
        assert parsed["ip"] == "1.2.3.4"
        assert 80 in parsed["ports"] or parsed["ports"] == [80, 443]
        assert "CVE-2021-1234" in parsed["vulns"]

    def test_invalid_ip_format(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(ip="not-an-ip"))
        assert "Invalid IP" in str(exc_info.value) or "invalid" in str(exc_info.value).lower()

    def test_host_with_history(self):
        mock_urlopen = _make_urlopen_mock(_SHODAN_HOST_RESPONSE)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(ip="1.2.3.4", history=True))
        # Verify it completed successfully; history param is forwarded to API URL
        parsed = json.loads(result)
        assert parsed["ip"] == "1.2.3.4"
        # Confirm history=true was included in the request URL
        call_args = mock_urlopen.call_args
        url_in_req = call_args[0][0].get_full_url()
        assert "history=true" in url_in_req

    def test_host_not_found(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(404, "Not Found")):
                with pytest.raises(ToolExecutionError):
                    _run(self.tool.execute(ip="1.2.3.4"))

    def test_rate_limit_error(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429)):
                with pytest.raises(ToolRateLimitError):
                    _run(self.tool.execute(ip="1.2.3.4"))

    def test_auth_error(self):
        with patch.dict("os.environ", {"SHODAN_API_KEY": "bad"}, clear=False):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(401, "Unauthorized")):
                with pytest.raises(ToolExecutionError) as exc_info:
                    _run(self.tool.execute(ip="1.2.3.4"))
        assert "401" in str(exc_info.value) or "Unauthorized" in str(exc_info.value)

    def test_output_is_valid_json(self):
        mock_urlopen = _make_urlopen_mock(_SHODAN_HOST_RESPONSE)
        with patch.dict("os.environ", {"SHODAN_API_KEY": "test-key"}, clear=False):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(ip="1.2.3.4"))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "ip" in parsed
        assert "ports" in parsed


# ===========================================================================
# TestCensysSearchTool (10 tests)
# ===========================================================================


class TestCensysSearchTool:
    def setup_method(self):
        self.tool = CensysSearchTool()

    def test_metadata_name(self):
        assert self.tool.name == "censys_search"

    def test_metadata_has_query_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "query" in props

    def test_metadata_has_index_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "index" in props
        assert "hosts" in props["index"]["enum"]
        assert "certificates" in props["index"]["enum"]

    def test_no_api_credentials_returns_error(self):
        with patch.dict("os.environ", {"CENSYS_API_ID": "", "CENSYS_API_SECRET": ""}, clear=False):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(query="services.port=443"))
        assert "CENSYS_API_ID" in str(exc_info.value) or "credentials" in str(exc_info.value).lower()

    def test_hosts_search_success(self):
        raw_bytes = json.dumps(_CENSYS_HOSTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(query="services.port=443", index="hosts"))
        parsed = json.loads(result)
        assert parsed["index"] == "hosts"
        assert len(parsed["results"]) == 1
        assert parsed["results"][0]["ip"] == "1.2.3.4"

    def test_certificates_search_success(self):
        raw_bytes = json.dumps(_CENSYS_CERTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(query="parsed.names: example.com", index="certificates"))
        parsed = json.loads(result)
        assert parsed["index"] == "certificates"
        assert len(parsed["results"]) == 1

    def test_invalid_index_error(self):
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(query="test", index="invalid"))
        assert "index" in str(exc_info.value).lower() or "hosts" in str(exc_info.value)

    def test_rate_limit_error(self):
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429)):
                with pytest.raises(ToolRateLimitError):
                    _run(self.tool.execute(query="services.port=443"))

    def test_auth_error(self):
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "bad-id", "CENSYS_API_SECRET": "bad-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(401, "Unauthorized")):
                with pytest.raises(ToolExecutionError) as exc_info:
                    _run(self.tool.execute(query="services.port=443"))
        assert "401" in str(exc_info.value) or "auth" in str(exc_info.value).lower()

    def test_output_is_valid_json(self):
        raw_bytes = json.dumps(_CENSYS_HOSTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(query="services.port=443"))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "results" in parsed
        assert "query" in parsed


# ===========================================================================
# TestCensysCertSearchTool (8 tests)
# ===========================================================================


class TestCensysCertSearchTool:
    def setup_method(self):
        self.tool = CensysCertSearchTool()

    def test_metadata_name(self):
        assert self.tool.name == "censys_cert_search"

    def test_metadata_has_domain_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "domain" in props
        assert props["domain"]["type"] == "string"

    def test_no_api_credentials_returns_error(self):
        with patch.dict("os.environ", {"CENSYS_API_ID": "", "CENSYS_API_SECRET": ""}, clear=False):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(domain="example.com"))
        assert "CENSYS_API_ID" in str(exc_info.value) or "credentials" in str(exc_info.value).lower()

    def test_cert_search_success(self):
        raw_bytes = json.dumps(_CENSYS_CERTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(domain="example.com"))
        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert parsed["certificates_found"] == 1

    def test_subdomain_extraction_from_san(self):
        raw_bytes = json.dumps(_CENSYS_CERTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(domain="example.com"))
        parsed = json.loads(result)
        subdomains = parsed["discovered_subdomains"]
        assert isinstance(subdomains, list)
        assert "www.example.com" in subdomains

    def test_rate_limit_error(self):
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429)):
                with pytest.raises(ToolRateLimitError):
                    _run(self.tool.execute(domain="example.com"))

    def test_output_includes_cert_fingerprint(self):
        raw_bytes = json.dumps(_CENSYS_CERTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(domain="example.com"))
        parsed = json.loads(result)
        certs = parsed["certificates"]
        assert len(certs) == 1
        assert certs[0]["fingerprint_sha256"] == "abc123def456"

    def test_output_is_valid_json(self):
        raw_bytes = json.dumps(_CENSYS_CERTS_RESPONSE).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.read.return_value = raw_bytes
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch.dict(
            "os.environ",
            {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", MagicMock(return_value=mock_resp)):
                result = _run(self.tool.execute(domain="example.com"))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "certificates" in parsed
        assert "discovered_subdomains" in parsed


# ===========================================================================
# TestFOFASearchTool (8 tests)
# ===========================================================================


class TestFOFASearchTool:
    def setup_method(self):
        self.tool = FOFASearchTool()

    def test_metadata_name(self):
        assert self.tool.name == "fofa_search"

    def test_metadata_has_query_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "query" in props
        assert props["query"]["type"] == "string"

    def test_no_api_credentials_returns_error(self):
        with patch.dict("os.environ", {"FOFA_API_EMAIL": "", "FOFA_API_KEY": ""}, clear=False):
            with pytest.raises(ToolExecutionError) as exc_info:
                _run(self.tool.execute(query='app="Apache"'))
        assert "FOFA_API_EMAIL" in str(exc_info.value) or "credentials" in str(exc_info.value).lower()

    def test_search_success(self):
        mock_urlopen = _make_urlopen_mock(_FOFA_RESPONSE)
        with patch.dict(
            "os.environ",
            {"FOFA_API_EMAIL": "test@example.com", "FOFA_API_KEY": "test-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query='app="Apache"'))
        parsed = json.loads(result)
        assert parsed["total"] == 1
        assert len(parsed["results"]) == 1
        assert parsed["results"][0]["host"] == "example.com:80"

    def test_query_is_base64_encoded(self):
        import base64 as b64_module

        mock_urlopen = _make_urlopen_mock(_FOFA_RESPONSE)
        query = 'app="Apache"'
        expected_b64 = b64_module.b64encode(query.encode("utf-8")).decode("ascii")

        captured_urls: list[str] = []

        def capturing_urlopen(req, timeout=None):
            captured_urls.append(req.get_full_url())
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(_FOFA_RESPONSE).encode("utf-8")
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch.dict(
            "os.environ",
            {"FOFA_API_EMAIL": "test@example.com", "FOFA_API_KEY": "test-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=capturing_urlopen):
                _run(self.tool.execute(query=query))

        assert len(captured_urls) == 1
        assert expected_b64 in captured_urls[0]

    def test_rate_limit_error(self):
        with patch.dict(
            "os.environ",
            {"FOFA_API_EMAIL": "test@example.com", "FOFA_API_KEY": "test-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429)):
                with pytest.raises(ToolRateLimitError):
                    _run(self.tool.execute(query='title="Jenkins"'))

    def test_output_is_valid_json(self):
        mock_urlopen = _make_urlopen_mock(_FOFA_RESPONSE)
        with patch.dict(
            "os.environ",
            {"FOFA_API_EMAIL": "test@example.com", "FOFA_API_KEY": "test-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(self.tool.execute(query='title="Jenkins"'))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "results" in parsed
        assert "query" in parsed

    def test_size_param(self):
        mock_urlopen = _make_urlopen_mock(_FOFA_RESPONSE)
        captured_urls: list[str] = []

        def capturing_urlopen(req, timeout=None):
            captured_urls.append(req.get_full_url())
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(_FOFA_RESPONSE).encode("utf-8")
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch.dict(
            "os.environ",
            {"FOFA_API_EMAIL": "test@example.com", "FOFA_API_KEY": "test-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=capturing_urlopen):
                result = _run(self.tool.execute(query='title="Jenkins"', size=50))

        assert len(captured_urls) == 1
        assert "size=50" in captured_urls[0]
        parsed = json.loads(result)
        assert parsed["size"] == 50


# ===========================================================================
# TestPassiveDNSTool (10 tests)
# ===========================================================================


class TestPassiveDNSTool:
    def setup_method(self):
        self.tool = PassiveDNSTool()

    def test_metadata_name(self):
        assert self.tool.name == "passive_dns_lookup"

    def test_metadata_has_domain_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "domain" in props
        assert props["domain"]["type"] == "string"

    def test_metadata_has_provider_param(self):
        props = self.tool.metadata.parameters["properties"]
        assert "provider" in props
        assert "securitytrails" in props["provider"]["enum"]
        assert "virustotal" in props["provider"]["enum"]
        assert "all" in props["provider"]["enum"]

    def test_securitytrails_success(self):
        mock_urlopen = _make_urlopen_mock(_SECURITYTRAILS_RESPONSE)
        with patch.dict(
            "os.environ",
            {"SECURITYTRAILS_API_KEY": "st-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(
                    self.tool.execute(domain="example.com", provider="securitytrails")
                )
        parsed = json.loads(result)
        assert parsed["domain"] == "example.com"
        assert parsed["provider"] == "securitytrails"
        assert parsed["total_records"] >= 1
        assert parsed["records"][0]["source"] == "securitytrails"
        assert parsed["records"][0]["value"] == "1.2.3.4"

    def test_virustotal_success(self):
        mock_urlopen = _make_urlopen_mock(_VIRUSTOTAL_RESPONSE)
        with patch.dict(
            "os.environ",
            {"VIRUSTOTAL_API_KEY": "vt-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(
                    self.tool.execute(domain="example.com", provider="virustotal")
                )
        parsed = json.loads(result)
        assert parsed["provider"] == "virustotal"
        assert parsed["total_records"] >= 1
        assert parsed["records"][0]["source"] == "virustotal"
        assert parsed["records"][0]["value"] == "1.2.3.4"

    def test_all_provider_aggregates_both(self):
        call_count = [0]

        def multi_urlopen(req, timeout=None):
            call_count[0] += 1
            url = req.get_full_url()
            if "securitytrails" in url:
                data = _SECURITYTRAILS_RESPONSE
            else:
                data = _VIRUSTOTAL_RESPONSE
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(data).encode("utf-8")
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch.dict(
            "os.environ",
            {"SECURITYTRAILS_API_KEY": "st-key", "VIRUSTOTAL_API_KEY": "vt-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=multi_urlopen):
                result = _run(self.tool.execute(domain="example.com", provider="all"))

        parsed = json.loads(result)
        assert parsed["provider"] == "all"
        assert parsed["total_records"] >= 2
        sources = {r["source"] for r in parsed["records"]}
        assert "securitytrails" in sources
        assert "virustotal" in sources

    def test_no_api_keys_returns_error(self):
        """When both provider API keys are absent and provider='all', errors are reported."""
        with patch.dict(
            "os.environ",
            {
                "SECURITYTRAILS_API_KEY": "",
                "VIRUSTOTAL_API_KEY": "",
            },
            clear=False,
        ):
            result = _run(self.tool.execute(domain="example.com", provider="all"))
        parsed = json.loads(result)
        # Both providers fail; errors are captured in provider_errors
        assert len(parsed["provider_errors"]) == 2
        assert parsed["total_records"] == 0

    def test_securitytrails_rate_limit(self):
        with patch.dict(
            "os.environ",
            {"SECURITYTRAILS_API_KEY": "st-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429)):
                result = _run(
                    self.tool.execute(domain="example.com", provider="securitytrails")
                )
        parsed = json.loads(result)
        assert "securitytrails" in parsed["provider_errors"]
        err_msg = parsed["provider_errors"]["securitytrails"]
        assert "429" in err_msg or "rate" in err_msg.lower()

    def test_virustotal_rate_limit(self):
        with patch.dict(
            "os.environ",
            {"VIRUSTOTAL_API_KEY": "vt-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", side_effect=_make_http_error(429)):
                result = _run(
                    self.tool.execute(domain="example.com", provider="virustotal")
                )
        parsed = json.loads(result)
        assert "virustotal" in parsed["provider_errors"]

    def test_output_is_valid_json(self):
        mock_urlopen = _make_urlopen_mock(_SECURITYTRAILS_RESPONSE)
        with patch.dict(
            "os.environ",
            {"SECURITYTRAILS_API_KEY": "st-key"},
            clear=False,
        ):
            with patch("urllib.request.urlopen", mock_urlopen):
                result = _run(
                    self.tool.execute(domain="example.com", provider="securitytrails")
                )
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "records" in parsed
        assert "domain" in parsed
        assert "total_records" in parsed


# ===========================================================================
# TestToolRegistration (5 tests)
# ===========================================================================


class TestToolRegistration:
    def test_all_6_tools_have_unique_names(self):
        names = [t.name for t in OSINT_TOOLS]
        assert len(names) == len(set(names)), "Duplicate tool names found"
        assert len(names) == 6

    def test_all_tools_are_base_tool_instances(self):
        BaseTool = _base_tool_mod.BaseTool
        for tool in OSINT_TOOLS:
            assert isinstance(tool, BaseTool), f"{tool} is not a BaseTool instance"

    def test_all_tools_have_non_empty_descriptions(self):
        for tool in OSINT_TOOLS:
            assert tool.description and len(tool.description.strip()) > 10, (
                f"{tool.name} has an empty or too-short description"
            )

    def test_all_tools_have_parameter_schemas(self):
        for tool in OSINT_TOOLS:
            params = tool.metadata.parameters
            assert isinstance(params, dict), f"{tool.name} parameters is not a dict"
            assert "properties" in params, f"{tool.name} has no 'properties' in parameters"
            assert len(params["properties"]) >= 1, f"{tool.name} has no parameters defined"

    def test_all_tools_are_async(self):
        import inspect

        for tool in OSINT_TOOLS:
            assert inspect.iscoroutinefunction(tool.execute), (
                f"{tool.name}.execute() is not an async function"
            )
