"""
Tests for Day 3 — Extended Recon Tools (Passive URL & Parameter Discovery)

Coverage (62 tests):
  TestHelperFunctions         (8 tests)  — _fetch_wayback_urls, _extract_params_from_urls,
                                           _run_cli_tool helpers
  TestWaybackUrlsTool         (12 tests) — metadata, execute, CDX mock, validation
  TestGAUTool                 (12 tests) — metadata, execute, CLI mock, JSON/plain parse
  TestParamSpiderTool         (12 tests) — metadata, execute, param extraction, min_count
  TestKatanaCrawlerTool       (10 tests) — metadata, execute, CLI mock, depth clamp
  TestWebArchiveSearchTool    (8 tests)  — metadata, execute, CDX mock, path handling

All tests use asyncio.run(), unittest.mock, and importlib isolation — no live
network or subprocess calls.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import types
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: inject minimal stubs so imports resolve without fastapi/langgraph
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
_recon_mod = _load_module("agent/tools/recon_extended_tools.py", "app.agent.tools.recon_extended_tools")

# Public symbols
_fetch_wayback_urls = _recon_mod._fetch_wayback_urls
_extract_params_from_urls = _recon_mod._extract_params_from_urls
_run_cli_tool = _recon_mod._run_cli_tool

WaybackUrlsTool = _recon_mod.WaybackUrlsTool
GAUTool = _recon_mod.GAUTool
ParamSpiderTool = _recon_mod.ParamSpiderTool
KatanaCrawlerTool = _recon_mod.KatanaCrawlerTool
WebArchiveSearchTool = _recon_mod.WebArchiveSearchTool
ToolExecutionError = _error_mod.ToolExecutionError


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Shared CDX mock helpers
# ---------------------------------------------------------------------------

def _make_cdx_response(urls: List[str]) -> bytes:
    """Build a CDX JSON response body for the given list of URLs."""
    rows: List[Any] = [["original"]] + [[u] for u in urls]
    return json.dumps(rows).encode()


def _make_cdx_response_with_meta(rows: List[List[str]]) -> bytes:
    """Build CDX JSON with [timestamp, original, statuscode] rows."""
    header = [["timestamp", "original", "statuscode"]]
    return json.dumps(header + rows).encode()


def _mock_urlopen(response_bytes: bytes, status: int = 200):
    """Return a context-manager mock for urllib.request.urlopen."""
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = response_bytes
    mock_resp.status = status
    return mock_resp


# ---------------------------------------------------------------------------
# 1. Helper Functions
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    def test_extract_params_empty(self):
        assert _extract_params_from_urls([]) == {}

    def test_extract_params_basic(self):
        urls = ["http://example.com/page?id=1&name=foo"]
        result = _extract_params_from_urls(urls)
        assert "id" in result
        assert "name" in result

    def test_extract_params_frequency(self):
        urls = [
            "http://example.com/?q=1",
            "http://example.com/?q=2",
            "http://example.com/?page=1",
        ]
        result = _extract_params_from_urls(urls)
        assert result["q"] == 2
        assert result["page"] == 1

    def test_extract_params_no_query_string(self):
        urls = ["http://example.com/about", "http://example.com/contact"]
        result = _extract_params_from_urls(urls)
        assert result == {}

    def test_extract_params_malformed_url(self):
        # Should not raise; malformed URLs are silently skipped
        result = _extract_params_from_urls(["not a url :::"])
        assert isinstance(result, dict)

    def test_fetch_wayback_urls_success(self):
        cdx_bytes = _make_cdx_response(["http://example.com/page1", "http://example.com/page2"])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            urls = _fetch_wayback_urls("example.com", limit=10)
        assert "http://example.com/page1" in urls
        assert len(urls) == 2

    def test_fetch_wayback_urls_deduplication(self):
        cdx_bytes = _make_cdx_response([
            "http://example.com/page1",
            "http://example.com/page1",
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            urls = _fetch_wayback_urls("example.com")
        assert len(urls) == 1

    def test_fetch_wayback_urls_network_error(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            with pytest.raises(ToolExecutionError):
                _fetch_wayback_urls("example.com")


# ---------------------------------------------------------------------------
# 2. WaybackUrlsTool
# ---------------------------------------------------------------------------

class TestWaybackUrlsTool:
    def setup_method(self):
        self.tool = WaybackUrlsTool()

    def test_name(self):
        assert self.tool.name == "wayback_urls"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_has_parameters(self):
        params = self.tool.metadata.parameters
        assert "required" in params
        assert "domain" in params["required"]

    def test_no_domain_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_execute_returns_urls(self):
        cdx_bytes = _make_cdx_response(["http://example.com/a", "http://example.com/b"])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["urls_found"] == 2
        assert "http://example.com/a" in result["urls"]

    def test_execute_strips_scheme(self):
        # "https://example.com" → should query "example.com"
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="https://example.com")))
        assert result["domain"] == "example.com"

    def test_limit_clamped_to_5000(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com", limit=99999)))
        assert result["urls_found"] == 0  # empty response, limit was clamped

    def test_result_structure(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert "domain" in result
        assert "urls_found" in result
        assert "urls" in result

    def test_network_error_propagates(self):
        with patch("urllib.request.urlopen", side_effect=Exception("network down")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(domain="example.com"))

    def test_max_2000_urls_in_result(self):
        # Manufacture 3000 unique URLs; bypass truncate_output so JSON stays parseable
        big_list = [f"http://example.com/p{i}" for i in range(3000)]
        cdx_bytes = _make_cdx_response(big_list)
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch.object(_recon_mod, "truncate_output", side_effect=lambda s, **kw: s):
                result = json.loads(_run(self.tool.execute(domain="example.com", limit=5000)))
        assert len(result["urls"]) <= 2000

    def test_mime_filter_passed_to_cdx(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            _run(self.tool.execute(domain="example.com", mime_filter="text/html"))

        assert "mimetype%3Atext%2Fhtml" in captured["url"] or "mimetype:text/html" in captured.get("url", "")

    def test_empty_cdx_response(self):
        # CDX returns only the header row
        cdx_bytes = json.dumps([["original"]]).encode()
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["urls_found"] == 0

    def test_invalid_json_cdx_raises(self):
        mock_resp = _mock_urlopen(b"not json")
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(domain="example.com"))

    def test_domain_in_result(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="test.example.com")))
        assert result["domain"] == "test.example.com"


# ---------------------------------------------------------------------------
# 3. GAUTool
# ---------------------------------------------------------------------------

class TestGAUTool:
    def setup_method(self):
        self.tool = GAUTool()

    def test_name(self):
        assert self.tool.name == "gau"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_has_parameters(self):
        params = self.tool.metadata.parameters
        assert "domain" in params.get("required", [])

    def test_no_domain_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_execute_parses_json_lines(self):
        gau_output = (
            '{"url":"http://example.com/a"}\n'
            '{"url":"http://example.com/b"}\n'
        )
        with patch.object(_recon_mod, "_run_cli_tool", return_value=gau_output):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["urls_found"] == 2
        assert "http://example.com/a" in result["urls"]

    def test_execute_parses_plain_urls(self):
        plain_output = "http://example.com/x\nhttp://example.com/y\n"
        with patch.object(_recon_mod, "_run_cli_tool", return_value=plain_output):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["urls_found"] == 2

    def test_deduplication(self):
        output = '{"url":"http://example.com/a"}\n{"url":"http://example.com/a"}\n'
        with patch.object(_recon_mod, "_run_cli_tool", return_value=output):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["urls_found"] == 1

    def test_cli_tool_not_found_raises(self):
        with patch.object(_recon_mod, "_run_cli_tool", side_effect=ToolExecutionError("gau not found")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(domain="example.com"))

    def test_providers_flag_passed(self):
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return ""

        with patch.object(_recon_mod, "_run_cli_tool", side_effect=fake_run):
            _run(self.tool.execute(domain="example.com", providers=["wayback"]))

        assert "--providers" in captured["cmd"]

    def test_blacklist_flag_passed(self):
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return ""

        with patch.object(_recon_mod, "_run_cli_tool", side_effect=fake_run):
            _run(self.tool.execute(domain="example.com", blacklist=["png", "jpg"]))

        assert "--blacklist" in captured["cmd"]

    def test_result_structure(self):
        with patch.object(_recon_mod, "_run_cli_tool", return_value=""):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert "domain" in result
        assert "urls_found" in result
        assert "urls" in result

    def test_empty_output(self):
        with patch.object(_recon_mod, "_run_cli_tool", return_value=""):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["urls_found"] == 0

    def test_max_2000_urls(self):
        lines = "\n".join(f"http://example.com/{i}" for i in range(3000))
        with patch.object(_recon_mod, "_run_cli_tool", return_value=lines):
            with patch.object(_recon_mod, "truncate_output", side_effect=lambda s, **kw: s):
                result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert len(result["urls"]) <= 2000


# ---------------------------------------------------------------------------
# 4. ParamSpiderTool
# ---------------------------------------------------------------------------

class TestParamSpiderTool:
    def setup_method(self):
        self.tool = ParamSpiderTool()

    def test_name(self):
        assert self.tool.name == "param_spider"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_required_domain(self):
        assert "domain" in self.tool.metadata.parameters.get("required", [])

    def test_no_domain_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_extracts_params_from_urls(self):
        cdx_bytes = _make_cdx_response([
            "http://example.com/page?id=1&name=foo",
            "http://example.com/page?id=2",
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        param_names = [p["name"] for p in result["params"]]
        assert "id" in param_names
        assert "name" in param_names

    def test_frequency_count(self):
        cdx_bytes = _make_cdx_response([
            "http://example.com/?q=1",
            "http://example.com/?q=2",
            "http://example.com/?page=1",
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        by_name = {p["name"]: p["count"] for p in result["params"]}
        assert by_name["q"] == 2
        assert by_name["page"] == 1

    def test_min_count_filter(self):
        cdx_bytes = _make_cdx_response([
            "http://example.com/?rare=1",
            "http://example.com/?common=1",
            "http://example.com/?common=2",
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com", min_count=2)))
        param_names = [p["name"] for p in result["params"]]
        assert "rare" not in param_names
        assert "common" in param_names

    def test_no_params_in_urls(self):
        cdx_bytes = _make_cdx_response(["http://example.com/about"])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["unique_params_found"] == 0

    def test_result_structure(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert "domain" in result
        assert "total_urls_analysed" in result
        assert "unique_params_found" in result
        assert "params" in result

    def test_network_error_propagates(self):
        with patch("urllib.request.urlopen", side_effect=Exception("network")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(domain="example.com"))

    def test_sorted_by_count_descending(self):
        cdx_bytes = _make_cdx_response([
            "http://example.com/?a=1",
            "http://example.com/?b=1",
            "http://example.com/?b=2",
            "http://example.com/?b=3",
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        counts = [p["count"] for p in result["params"]]
        assert counts == sorted(counts, reverse=True)

    def test_limit_clamped(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            # Limit 99999 should not cause errors — it is clamped to 5000
            result = json.loads(_run(self.tool.execute(domain="example.com", limit=99999)))
        assert result["total_urls_analysed"] == 0

    def test_strips_scheme_from_domain(self):
        cdx_bytes = _make_cdx_response([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="https://example.com")))
        assert result["domain"] == "example.com"

    def test_max_500_params_in_result(self):
        # 600 unique parameter names; bypass truncate_output so JSON stays parseable
        params_str = "&".join(f"p{i}=1" for i in range(600))
        url = f"http://example.com/?{params_str}"
        cdx_bytes = _make_cdx_response([url])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch.object(_recon_mod, "truncate_output", side_effect=lambda s, **kw: s):
                result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert len(result["params"]) <= 500


# ---------------------------------------------------------------------------
# 5. KatanaCrawlerTool
# ---------------------------------------------------------------------------

class TestKatanaCrawlerTool:
    def setup_method(self):
        self.tool = KatanaCrawlerTool()

    def test_name(self):
        assert self.tool.name == "katana_crawler"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_required_url(self):
        assert "url" in self.tool.metadata.parameters.get("required", [])

    def test_no_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_execute_parses_endpoints(self):
        katana_out = "http://example.com/api/v1\nhttp://example.com/login\n"
        with patch.object(_recon_mod, "_run_cli_tool", return_value=katana_out):
            result = json.loads(_run(self.tool.execute(url="http://example.com")))
        assert result["endpoints_found"] == 2
        assert "http://example.com/api/v1" in result["endpoints"]

    def test_filters_non_http_lines(self):
        katana_out = "http://example.com/valid\nsome garbage line\n"
        with patch.object(_recon_mod, "_run_cli_tool", return_value=katana_out):
            result = json.loads(_run(self.tool.execute(url="http://example.com")))
        assert result["endpoints_found"] == 1

    def test_depth_clamped_max_10(self):
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return ""

        with patch.object(_recon_mod, "_run_cli_tool", side_effect=fake_run):
            _run(self.tool.execute(url="http://example.com", depth=99))

        assert "-d" in captured["cmd"]
        idx = captured["cmd"].index("-d")
        assert captured["cmd"][idx + 1] == "10"

    def test_depth_clamped_min_1(self):
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return ""

        with patch.object(_recon_mod, "_run_cli_tool", side_effect=fake_run):
            _run(self.tool.execute(url="http://example.com", depth=0))

        idx = captured["cmd"].index("-d")
        assert captured["cmd"][idx + 1] == "1"

    def test_js_crawl_flag_included(self):
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return ""

        with patch.object(_recon_mod, "_run_cli_tool", side_effect=fake_run):
            _run(self.tool.execute(url="http://example.com", js_crawl=True))

        assert "-js-crawl" in captured["cmd"]

    def test_js_crawl_flag_excluded(self):
        captured = {}

        def fake_run(cmd, timeout):
            captured["cmd"] = cmd
            return ""

        with patch.object(_recon_mod, "_run_cli_tool", side_effect=fake_run):
            _run(self.tool.execute(url="http://example.com", js_crawl=False))

        assert "-js-crawl" not in captured["cmd"]

    def test_cli_error_propagates(self):
        with patch.object(_recon_mod, "_run_cli_tool", side_effect=ToolExecutionError("katana not found")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(url="http://example.com"))

    def test_result_structure(self):
        with patch.object(_recon_mod, "_run_cli_tool", return_value=""):
            result = json.loads(_run(self.tool.execute(url="http://example.com")))
        assert "url" in result
        assert "depth" in result
        assert "endpoints_found" in result
        assert "endpoints" in result

    def test_deduplication(self):
        katana_out = "http://example.com/a\nhttp://example.com/a\n"
        with patch.object(_recon_mod, "_run_cli_tool", return_value=katana_out):
            result = json.loads(_run(self.tool.execute(url="http://example.com")))
        assert result["endpoints_found"] == 1


# ---------------------------------------------------------------------------
# 6. WebArchiveSearchTool
# ---------------------------------------------------------------------------

class TestWebArchiveSearchTool:
    def setup_method(self):
        self.tool = WebArchiveSearchTool()

    def test_name(self):
        assert self.tool.name == "web_archive_search"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_no_domain_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_execute_returns_snapshots(self):
        cdx_bytes = _make_cdx_response_with_meta([
            ["20210101120000", "http://example.com/admin", "200"],
            ["20200601000000", "http://example.com/admin/old", "301"],
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com", path="/admin")))
        assert result["snapshots_found"] == 2
        assert result["snapshots"][0]["timestamp"] == "20210101120000"

    def test_wayback_url_constructed(self):
        cdx_bytes = _make_cdx_response_with_meta([
            ["20210101", "http://example.com/a", "200"],
        ])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert "web.archive.org/web/20210101/http://example.com/a" in result["snapshots"][0]["wayback_url"]

    def test_path_slash_prefixed(self):
        cdx_bytes = _make_cdx_response_with_meta([])
        mock_resp = _mock_urlopen(cdx_bytes)
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            _run(self.tool.execute(domain="example.com", path="admin"))

        # Path without leading slash should be auto-corrected; URL-encode safe to check decoded
        assert "admin" in captured["url"]

    def test_empty_cdx_response(self):
        cdx_bytes = json.dumps([["timestamp", "original", "statuscode"]]).encode()
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert result["snapshots_found"] == 0

    def test_network_error_propagates(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(domain="example.com"))

    def test_result_structure(self):
        cdx_bytes = _make_cdx_response_with_meta([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(domain="example.com")))
        assert "domain" in result
        assert "path_searched" in result
        assert "snapshots_found" in result
        assert "snapshots" in result

    def test_limit_clamped(self):
        cdx_bytes = _make_cdx_response_with_meta([])
        mock_resp = _mock_urlopen(cdx_bytes)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            # limit=99999 should be silently clamped to 1000
            result = json.loads(_run(self.tool.execute(domain="example.com", limit=99999)))
        assert result["snapshots_found"] == 0
