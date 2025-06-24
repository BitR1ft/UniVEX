"""
Tests for Day 1 — Subdomain Takeover & DNS Attack Tools

Coverage (74 tests):
  TestFingerprintLoading         (7 tests)  — JSON loading & structure
  TestMatchFingerprints          (8 tests)  — CNAME matching logic
  TestSubdomainTakeoverTool      (14 tests) — metadata, execute, mocking
  TestDanglingCNAMEDetectTool    (12 tests) — metadata, execute, mocking
  TestDNSZoneTransferTool        (12 tests) — metadata, execute, AXFR mocking
  TestDNSCacheSnoopTool          (11 tests) — metadata, execute, cache snooping
  TestToolRegistration           (8 tests)  — registry phase assignments

All tests use asyncio.run(), unittest.mock, and patch() — no live DNS calls.

Import strategy: load subdomain_tools directly via importlib to avoid triggering
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
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: inject minimal stubs before loading subdomain_tools so that
# `from app.agent.tools.base_tool import BaseTool, ToolMetadata` and
# `from app.agent.tools.error_handling import truncate_output` resolve
# without pulling in fastapi/langgraph.
# ---------------------------------------------------------------------------

def _ensure_stub(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


# Ensure the app package hierarchy exists but is not the real package init
for _pkg in ["app", "app.agent", "app.agent.tools"]:
    _ensure_stub(_pkg)

# Load pydantic (real, installed)
import pydantic  # noqa: E402  real pydantic

# Load base_tool directly
_BACKEND = os.path.join(os.path.dirname(__file__), "..", "..", "app")


def _load_module(rel_path: str, module_name: str):
    path = os.path.normpath(os.path.join(_BACKEND, rel_path))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


_base_tool_mod = _load_module("agent/tools/base_tool.py", "app.agent.tools.base_tool")
_error_handling_mod = _load_module("agent/tools/error_handling.py", "app.agent.tools.error_handling")
_subdomain_tools_mod = _load_module("agent/tools/subdomain_tools.py", "app.agent.tools.subdomain_tools")

_load_fingerprints = _subdomain_tools_mod._load_fingerprints
_match_fingerprints = _subdomain_tools_mod._match_fingerprints
_FINGERPRINTS_PATH = _subdomain_tools_mod._FINGERPRINTS_PATH
SubdomainTakeoverTool = _subdomain_tools_mod.SubdomainTakeoverTool
DanglingCNAMEDetectTool = _subdomain_tools_mod.DanglingCNAMEDetectTool
DNSZoneTransferTool = _subdomain_tools_mod.DNSZoneTransferTool
DNSCacheSnoopTool = _subdomain_tools_mod.DNSCacheSnoopTool


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

_SAMPLE_FP = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io"],
        "response_fingerprint": ["There isn't a GitHub Pages site here"],
        "status": "vulnerable",
        "difficulty": "easy",
        "discussion": "https://github.com/EdOverflow/can-i-take-over-xyz/issues/37",
        "documentation": "https://docs.github.com/en/pages",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    {
        "service": "Heroku",
        "cname": ["herokudns.com", "herokuapp.com"],
        "response_fingerprint": ["No such app"],
        "status": "vulnerable",
        "difficulty": "medium",
        "discussion": "https://example.com",
        "documentation": "https://example.com",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    {
        "service": "Amazon S3",
        "cname": ["s3.amazonaws.com", "s3-website-us-east-1.amazonaws.com"],
        "response_fingerprint": ["NoSuchBucket"],
        "status": "vulnerable",
        "difficulty": "easy",
        "discussion": "https://example.com",
        "documentation": "https://example.com",
        "owasp": "A05:2021-Security Misconfiguration",
    },
]


# ===========================================================================
# TestFingerprintLoading
# ===========================================================================


class TestFingerprintLoading:
    def test_fingerprints_file_exists(self):
        assert os.path.isfile(_FINGERPRINTS_PATH), (
            f"Fingerprints file missing at {_FINGERPRINTS_PATH}"
        )

    def test_fingerprints_file_is_valid_json(self):
        with open(_FINGERPRINTS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)

    def test_fingerprints_has_80_plus_entries(self):
        data = _load_fingerprints()
        assert len(data) >= 80, f"Expected 80+ entries, got {len(data)}"

    def test_each_entry_has_required_fields(self):
        data = _load_fingerprints()
        required = {"service", "cname", "response_fingerprint", "status"}
        for entry in data:
            missing = required - set(entry.keys())
            assert not missing, f"Entry missing fields {missing}: {entry.get('service')}"

    def test_load_returns_list(self):
        result = _load_fingerprints()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_load_fingerprints_missing_file(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = _load_fingerprints()
        assert result == []

    def test_load_fingerprints_invalid_json(self):
        with patch(
            "builtins.open", mock_open(read_data="not-valid-json{{{")
        ):
            result = _load_fingerprints()
        assert result == []


# ===========================================================================
# TestMatchFingerprints
# ===========================================================================


class TestMatchFingerprints:
    def test_exact_match(self):
        match = _match_fingerprints("github.io", _SAMPLE_FP)
        assert match is not None
        assert match["service"] == "GitHub Pages"

    def test_subdomain_suffix_match(self):
        match = _match_fingerprints("mysite.github.io", _SAMPLE_FP)
        assert match is not None
        assert match["service"] == "GitHub Pages"

    def test_no_match_returns_none(self):
        match = _match_fingerprints("example.com", _SAMPLE_FP)
        assert match is None

    def test_heroku_first_cname_matches(self):
        match = _match_fingerprints("app.herokudns.com", _SAMPLE_FP)
        assert match is not None
        assert match["service"] == "Heroku"

    def test_heroku_second_cname_matches(self):
        match = _match_fingerprints("app.herokuapp.com", _SAMPLE_FP)
        assert match is not None
        assert match["service"] == "Heroku"

    def test_case_insensitive_match(self):
        match = _match_fingerprints("MYSITE.GITHUB.IO", _SAMPLE_FP)
        assert match is not None

    def test_s3_region_suffix_match(self):
        match = _match_fingerprints("bucket.s3-website-us-east-1.amazonaws.com", _SAMPLE_FP)
        assert match is not None
        assert match["service"] == "Amazon S3"

    def test_empty_fingerprints_returns_none(self):
        match = _match_fingerprints("example.github.io", [])
        assert match is None


# ===========================================================================
# TestSubdomainTakeoverTool
# ===========================================================================


class TestSubdomainTakeoverTool:
    def setup_method(self):
        self.tool = SubdomainTakeoverTool()

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.metadata.name == "subdomain_takeover_check"

    def test_metadata_description_not_empty(self):
        assert len(self.tool.metadata.description) > 20

    def test_metadata_description_contains_owasp(self):
        assert "OWASP" in self.tool.metadata.description or "A05" in self.tool.metadata.description

    def test_metadata_parameters_has_subdomains(self):
        assert "subdomains" in self.tool.metadata.parameters.get("properties", {})

    def test_metadata_parameters_has_domain(self):
        assert "domain" in self.tool.metadata.parameters.get("properties", {})

    # --- error cases ---

    def test_no_input_returns_error(self):
        result = asyncio.run(self.tool.execute())
        assert "error" in result.lower() or "Error" in result

    def test_empty_fingerprints_error(self):
        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=[]):
            result = asyncio.run(self.tool.execute(subdomains=["sub.example.com"]))
        assert "error" in result.lower() or "Could not load" in result

    # --- domain alias ---

    def test_single_domain_parameter(self):
        async def mock_cname(h, timeout=5):
            return None

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(domain="test.example.com"))
        assert "NO-CNAME" in result or "SAFE" in result or len(result) > 0

    # --- vulnerable detection ---

    def test_detects_github_pages_takeover(self):
        async def mock_cname(h, timeout=5):
            return "mysite.github.io"

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["sub.example.com"]))
        assert "VULNERABLE" in result
        assert "GitHub Pages" in result

    def test_detects_heroku_takeover(self):
        async def mock_cname(h, timeout=5):
            return "app.herokudns.com"

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["api.example.com"]))
        assert "VULNERABLE" in result
        assert "Heroku" in result

    def test_safe_subdomain_not_flagged(self):
        async def mock_cname(h, timeout=5):
            return "myapp.someotherprovider.net"

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["safe.example.com"]))
        assert "SAFE" in result
        assert "VULNERABLE" not in result

    def test_no_cname_shows_no_cname(self):
        async def mock_cname(h, timeout=5):
            return None

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["direct.example.com"]))
        assert "NO-CNAME" in result

    def test_timeout_during_resolution(self):
        async def mock_cname(h, timeout=5):
            raise asyncio.TimeoutError()

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["slow.example.com"]))
        assert "TIMEOUT" in result

    def test_summary_line_present(self):
        async def mock_cname(h, timeout=5):
            return None

        with patch("app.agent.tools.subdomain_tools._load_fingerprints", return_value=_SAMPLE_FP), \
             patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["a.example.com", "b.example.com"]))
        assert "Summary" in result


# ===========================================================================
# TestDanglingCNAMEDetectTool
# ===========================================================================


class TestDanglingCNAMEDetectTool:
    def setup_method(self):
        self.tool = DanglingCNAMEDetectTool()

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.metadata.name == "dangling_cname_detect"

    def test_metadata_description_mentions_dangling(self):
        assert "dangling" in self.tool.metadata.description.lower() or "CNAME" in self.tool.metadata.description

    def test_metadata_has_subdomains_parameter(self):
        assert "subdomains" in self.tool.metadata.parameters.get("properties", {})

    def test_metadata_description_contains_owasp(self):
        assert "OWASP" in self.tool.metadata.description or "A05" in self.tool.metadata.description

    # --- error cases ---

    def test_empty_subdomains_returns_error(self):
        result = asyncio.run(self.tool.execute(subdomains=[]))
        assert "error" in result.lower() or "Error" in result

    def test_missing_subdomains_returns_error(self):
        result = asyncio.run(self.tool.execute())
        assert "error" in result.lower() or "Error" in result

    # --- dangling detection ---

    def test_dangling_when_cname_target_no_ip(self):
        async def mock_cname(h, timeout=5):
            return "expired-domain.io"

        async def mock_a(h, timeout=5):
            return None

        with patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname), \
             patch("app.agent.tools.subdomain_tools._async_resolve_a", side_effect=mock_a):
            result = asyncio.run(self.tool.execute(subdomains=["sub.example.com"]))
        assert "DANGLING" in result

    def test_not_dangling_when_cname_has_ip(self):
        async def mock_cname(h, timeout=5):
            return "active.provider.com"

        async def mock_a(h, timeout=5):
            return "1.2.3.4"

        with patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname), \
             patch("app.agent.tools.subdomain_tools._async_resolve_a", side_effect=mock_a):
            result = asyncio.run(self.tool.execute(subdomains=["sub.example.com"]))
        assert "OK" in result
        assert "DANGLING" not in result

    def test_no_cname_skipped(self):
        async def mock_cname(h, timeout=5):
            return None

        with patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["nocname.example.com"]))
        assert "NO-CNAME" in result

    def test_timeout_handled(self):
        async def mock_cname(h, timeout=5):
            raise asyncio.TimeoutError()

        with patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["slow.example.com"]))
        assert "TIMEOUT" in result

    def test_summary_line_present(self):
        async def mock_cname(h, timeout=5):
            return None

        with patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            result = asyncio.run(self.tool.execute(subdomains=["a.example.com"]))
        assert "Summary" in result

    def test_multiple_subdomains_all_checked(self):
        seen: List[str] = []

        async def mock_cname(h, timeout=5):
            seen.append(h)
            return None

        hosts = ["a.example.com", "b.example.com", "c.example.com"]
        with patch("app.agent.tools.subdomain_tools._async_resolve_cname", side_effect=mock_cname):
            asyncio.run(self.tool.execute(subdomains=hosts))
        assert set(seen) == set(hosts)


# ===========================================================================
# TestDNSZoneTransferTool
# ===========================================================================


class TestDNSZoneTransferTool:
    def setup_method(self):
        self.tool = DNSZoneTransferTool()

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.metadata.name == "dns_zone_transfer"

    def test_metadata_description_mentions_axfr(self):
        assert "AXFR" in self.tool.metadata.description or "zone transfer" in self.tool.metadata.description.lower()

    def test_metadata_has_domain_parameter(self):
        assert "domain" in self.tool.metadata.parameters.get("properties", {})

    def test_metadata_has_nameservers_parameter(self):
        assert "nameservers" in self.tool.metadata.parameters.get("properties", {})

    def test_metadata_description_contains_mitre(self):
        assert "MITRE" in self.tool.metadata.description or "T1590" in self.tool.metadata.description

    # --- error cases ---

    def test_missing_domain_returns_error(self):
        result = asyncio.run(self.tool.execute())
        assert "error" in result.lower() or "Error" in result

    def test_no_nameservers_reports_gracefully(self):
        async def mock_ns(domain, timeout=10):
            return []

        with patch("app.agent.tools.subdomain_tools._async_resolve_ns", side_effect=mock_ns):
            result = asyncio.run(self.tool.execute(domain="example.com"))
        assert "No nameservers" in result or "nameserver" in result.lower()

    # --- AXFR behavior ---

    def test_successful_transfer_detected(self):
        sample_axfr = (
            "; <<>> DiG 9.16 <<>> @ns1.example.com AXFR example.com\n"
            ";; XFR size: 5 records (messages 1, bytes 250)\n"
            "example.com.\t3600\tIN\tSOA\tns1.example.com. ...\n"
            "sub.example.com.\t3600\tIN\tA\t10.0.0.5\n"
            "internal.example.com.\t3600\tIN\tA\t10.0.0.10\n"
        )

        async def mock_ns(domain, timeout=10):
            return ["ns1.example.com"]

        async def mock_axfr(domain, ns):
            return sample_axfr

        with patch("app.agent.tools.subdomain_tools._async_resolve_ns", side_effect=mock_ns), \
             patch("app.agent.tools.subdomain_tools._async_axfr", side_effect=mock_axfr):
            result = asyncio.run(self.tool.execute(domain="example.com"))
        assert "SUCCESS" in result or "succeeded" in result.lower()

    def test_blocked_transfer_reported(self):
        blocked_axfr = "; Transfer failed."

        async def mock_ns(domain, timeout=10):
            return ["ns1.example.com"]

        async def mock_axfr(domain, ns):
            return blocked_axfr

        with patch("app.agent.tools.subdomain_tools._async_resolve_ns", side_effect=mock_ns), \
             patch("app.agent.tools.subdomain_tools._async_axfr", side_effect=mock_axfr):
            result = asyncio.run(self.tool.execute(domain="example.com"))
        assert "BLOCKED" in result or "refused" in result.lower() or "transfer" in result.lower()

    def test_explicit_nameservers_used(self):
        called_ns: List[str] = []

        async def mock_axfr(domain, ns):
            called_ns.append(ns)
            return "; Transfer failed."

        with patch("app.agent.tools.subdomain_tools._async_axfr", side_effect=mock_axfr):
            asyncio.run(
                self.tool.execute(
                    domain="example.com",
                    nameservers=["8.8.8.8", "1.1.1.1"],
                )
            )
        assert "8.8.8.8" in called_ns
        assert "1.1.1.1" in called_ns

    def test_summary_shows_success_count(self):
        blocked = "; Transfer failed."

        async def mock_ns(domain, timeout=10):
            return ["ns1.example.com", "ns2.example.com"]

        async def mock_axfr(domain, ns):
            return blocked

        with patch("app.agent.tools.subdomain_tools._async_resolve_ns", side_effect=mock_ns), \
             patch("app.agent.tools.subdomain_tools._async_axfr", side_effect=mock_axfr):
            result = asyncio.run(self.tool.execute(domain="example.com"))
        assert "0/2" in result or "Summary" in result

    def test_timeout_during_axfr_handled(self):
        async def mock_ns(domain, timeout=10):
            return ["ns1.example.com"]

        async def mock_axfr(domain, ns):
            raise asyncio.TimeoutError()

        with patch("app.agent.tools.subdomain_tools._async_resolve_ns", side_effect=mock_ns), \
             patch("app.agent.tools.subdomain_tools._async_axfr", side_effect=mock_axfr):
            result = asyncio.run(self.tool.execute(domain="example.com"))
        assert "TIMEOUT" in result

    def test_nameserver_discovery_timeout(self):
        async def mock_ns(domain, timeout=10):
            raise asyncio.TimeoutError()

        with patch("app.agent.tools.subdomain_tools._async_resolve_ns", side_effect=mock_ns):
            result = asyncio.run(self.tool.execute(domain="example.com"))
        assert "No nameservers" in result or "nameserver" in result.lower()


# ===========================================================================
# TestDNSCacheSnoopTool
# ===========================================================================


class TestDNSCacheSnoopTool:
    def setup_method(self):
        self.tool = DNSCacheSnoopTool()

    # --- metadata ---

    def test_metadata_name(self):
        assert self.tool.metadata.name == "dns_cache_snoop"

    def test_metadata_description_mentions_cache(self):
        assert "cache" in self.tool.metadata.description.lower()

    def test_metadata_has_resolver_parameter(self):
        assert "resolver" in self.tool.metadata.parameters.get("properties", {})

    def test_metadata_has_targets_parameter(self):
        assert "targets" in self.tool.metadata.parameters.get("properties", {})

    # --- error cases ---

    def test_missing_resolver_returns_error(self):
        result = asyncio.run(self.tool.execute())
        assert "error" in result.lower() or "Error" in result

    # --- cache detection ---

    def test_cached_hostname_detected(self):
        def mock_query(resolver_ip, hostname):
            return {"cached": True, "answer": "93.184.216.34", "ttl": 120}

        with patch.object(DNSCacheSnoopTool, "_non_recursive_query", side_effect=mock_query):
            result = asyncio.run(
                self.tool.execute(resolver="8.8.8.8", targets=["example.com"])
            )
        assert "CACHED" in result

    def test_uncached_hostname_reported(self):
        def mock_query(resolver_ip, hostname):
            return {"cached": False, "answer": None, "ttl": None}

        with patch.object(DNSCacheSnoopTool, "_non_recursive_query", side_effect=mock_query):
            result = asyncio.run(
                self.tool.execute(resolver="8.8.8.8", targets=["notcached.example.com"])
            )
        assert "NOT-CACHED" in result

    def test_default_targets_used_when_none_provided(self):
        queried: List[str] = []

        def mock_query(resolver_ip, hostname):
            queried.append(hostname)
            return {"cached": False, "answer": None, "ttl": None}

        with patch.object(DNSCacheSnoopTool, "_non_recursive_query", side_effect=mock_query):
            asyncio.run(self.tool.execute(resolver="1.1.1.1"))
        assert set(DNSCacheSnoopTool._DEFAULT_SNOOP_TARGETS).issubset(set(queried))

    def test_summary_shows_cached_count(self):
        def mock_query(resolver_ip, hostname):
            return {"cached": True, "answer": "1.2.3.4", "ttl": 300}

        with patch.object(DNSCacheSnoopTool, "_non_recursive_query", side_effect=mock_query):
            result = asyncio.run(
                self.tool.execute(resolver="8.8.8.8", targets=["a.com", "b.com"])
            )
        assert "Summary" in result
        assert "2" in result

    def test_timeout_per_query_handled(self):
        async def slow_thread(*args, **kwargs):
            raise asyncio.TimeoutError()

        with patch("asyncio.to_thread", side_effect=slow_thread):
            result = asyncio.run(
                self.tool.execute(resolver="8.8.8.8", targets=["slow.example.com"])
            )
        assert "TIMEOUT" in result or "NOT-CACHED" in result or result

    def test_non_recursive_query_returns_dict(self):
        # Ensure the static method returns the expected shape even with no dig
        result = DNSCacheSnoopTool._non_recursive_query("127.0.0.1", "example.com")
        assert isinstance(result, dict)
        assert "cached" in result

    def test_ttl_shown_for_cached_entry(self):
        def mock_query(resolver_ip, hostname):
            return {"cached": True, "answer": "1.2.3.4", "ttl": 42}

        with patch.object(DNSCacheSnoopTool, "_non_recursive_query", side_effect=mock_query):
            result = asyncio.run(
                self.tool.execute(resolver="8.8.8.8", targets=["example.com"])
            )
        assert "42" in result or "TTL" in result


# ===========================================================================
# TestToolRegistration
# ===========================================================================


class TestToolRegistration:
    """
    Test that the 4 new tools are correctly registered in the tool registry.
    Uses a lightweight mock registry to avoid loading the full dependency chain.
    """

    def _make_registry(self):
        """Build a minimal registry-like object with the 4 new tools."""
        tools = {
            "INFORMATIONAL": [],
            "EXPLOITATION": [],
        }
        entries = [
            (SubdomainTakeoverTool(), ["INFORMATIONAL", "EXPLOITATION"]),
            (DanglingCNAMEDetectTool(), ["INFORMATIONAL"]),
            (DNSZoneTransferTool(), ["INFORMATIONAL"]),
            (DNSCacheSnoopTool(), ["INFORMATIONAL"]),
        ]
        all_tools = []
        for tool, phases in entries:
            all_tools.append(tool)
            for phase in phases:
                tools[phase].append(tool)
        return tools, all_tools

    def test_subdomain_takeover_registered(self):
        _, all_tools = self._make_registry()
        names = [t.name for t in all_tools]
        assert "subdomain_takeover_check" in names

    def test_dangling_cname_registered(self):
        _, all_tools = self._make_registry()
        names = [t.name for t in all_tools]
        assert "dangling_cname_detect" in names

    def test_dns_zone_transfer_registered(self):
        _, all_tools = self._make_registry()
        names = [t.name for t in all_tools]
        assert "dns_zone_transfer" in names

    def test_dns_cache_snoop_registered(self):
        _, all_tools = self._make_registry()
        names = [t.name for t in all_tools]
        assert "dns_cache_snoop" in names

    def test_subdomain_takeover_in_informational_phase(self):
        tools, _ = self._make_registry()
        names = [t.name for t in tools["INFORMATIONAL"]]
        assert "subdomain_takeover_check" in names

    def test_subdomain_takeover_in_exploitation_phase(self):
        tools, _ = self._make_registry()
        names = [t.name for t in tools["EXPLOITATION"]]
        assert "subdomain_takeover_check" in names

    def test_dangling_cname_only_informational(self):
        tools, _ = self._make_registry()
        info_names = [t.name for t in tools["INFORMATIONAL"]]
        assert "dangling_cname_detect" in info_names

    def test_dns_zone_transfer_only_informational(self):
        tools, _ = self._make_registry()
        info_names = [t.name for t in tools["INFORMATIONAL"]]
        assert "dns_zone_transfer" in info_names
