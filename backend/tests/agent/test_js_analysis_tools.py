"""
Tests for Day 2 — JavaScript Analysis Tools

Coverage (71 tests):
  TestHelperFunctions            (14 tests) — _shannon_entropy, _version_tuple,
                                              _version_in_range, _extract_endpoints,
                                              _find_secrets, _find_dom_sinks
  TestJSEndpointExtractTool      (14 tests) — metadata, execute inline, URL fetch mock
  TestJSSecretFinderTool         (14 tests) — metadata, secret patterns, entropy
  TestJSLibVulnTool              (14 tests) — metadata, DB matching, version ranges
  TestSourceMapAnalyzeTool       (8 tests)  — metadata, inline map, URL probe mock
  TestDOMSinkAnalyzerTool        (7 tests)  — metadata, sink detection

All tests use asyncio.run(), unittest.mock, and importlib isolation — no live
network calls.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import types
from typing import Any, Dict
from unittest.mock import MagicMock, patch, mock_open

import pytest

# ---------------------------------------------------------------------------
# Bootstrap: inject minimal stubs before loading js_analysis_tools so that
# `from app.agent.tools.base_tool import BaseTool, ToolMetadata` and
# `from app.agent.tools.error_handling import ...` resolve without fastapi/langgraph.
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
_error_handling_mod = _load_module("agent/tools/error_handling.py", "app.agent.tools.error_handling")
_js_mod = _load_module("agent/tools/js_analysis_tools.py", "app.agent.tools.js_analysis_tools")

# Public symbols
_shannon_entropy = _js_mod._shannon_entropy
_version_tuple = _js_mod._version_tuple
_version_in_range = _js_mod._version_in_range
_extract_endpoints = _js_mod._extract_endpoints
_find_secrets = _js_mod._find_secrets
_find_dom_sinks = _js_mod._find_dom_sinks
_load_vuln_db = _js_mod._load_vuln_db

JSEndpointExtractTool = _js_mod.JSEndpointExtractTool
JSSecretFinderTool = _js_mod.JSSecretFinderTool
JSLibVulnTool = _js_mod.JSLibVulnTool
SourceMapAnalyzeTool = _js_mod.SourceMapAnalyzeTool
DOMSinkAnalyzerTool = _js_mod.DOMSinkAnalyzerTool
ToolExecutionError = _error_handling_mod.ToolExecutionError


# ---------------------------------------------------------------------------
# Helper: run coroutine in a fresh event loop
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. Helper Functions
# ---------------------------------------------------------------------------

class TestHelperFunctions:
    # --- _shannon_entropy ---

    def test_empty_string_entropy(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_entropy(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # A random-looking base64 string should have entropy > 4
        val = "aB3dEfGhIjKlMnOpQrStUvWxYz012345"
        assert _shannon_entropy(val) > 4.0

    def test_low_entropy(self):
        assert _shannon_entropy("aaaaabbbbb") < 2.0

    # --- _version_tuple ---

    def test_version_tuple_simple(self):
        assert _version_tuple("3.5.1") == (3, 5, 1)

    def test_version_tuple_with_prerelease(self):
        tup = _version_tuple("3.5.1-beta")
        assert tup[0] == 3 and tup[1] == 5 and tup[2] == 1

    def test_version_tuple_single(self):
        assert _version_tuple("2") == (2,)

    # --- _version_in_range ---

    def test_in_range_basic(self):
        assert _version_in_range("3.4.0", "1.0.0", "3.5.0")

    def test_below_boundary_excluded(self):
        assert not _version_in_range("3.5.0", "1.0.0", "3.5.0")

    def test_at_or_above_boundary_included(self):
        assert _version_in_range("1.0.0", "1.0.0", "3.5.0")

    def test_below_range_excluded(self):
        assert not _version_in_range("0.9.0", "1.0.0", "3.5.0")

    def test_no_lower_bound(self):
        assert _version_in_range("0.1.0", None, "3.5.0")

    def test_no_upper_bound(self):
        assert _version_in_range("999.0.0", "1.0.0", None)

    # --- _extract_endpoints ---

    def test_fetch_endpoint(self):
        js = 'fetch("/api/v1/users")'
        eps = _extract_endpoints(js)
        assert "/api/v1/users" in eps

    def test_axios_endpoint(self):
        js = 'axios.get("/api/data")'
        eps = _extract_endpoints(js)
        assert "/api/data" in eps

    def test_no_duplicates(self):
        js = 'fetch("/api/v1"); fetch("/api/v1");'
        eps = _extract_endpoints(js)
        assert eps.count("/api/v1") == 1


# ---------------------------------------------------------------------------
# 2. JSEndpointExtractTool
# ---------------------------------------------------------------------------

class TestJSEndpointExtractTool:
    def setup_method(self):
        self.tool = JSEndpointExtractTool()

    def test_name(self):
        assert self.tool.name == "js_endpoint_extract"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_has_parameters(self):
        assert "properties" in self.tool.metadata.parameters

    def test_execute_inline_no_endpoints(self):
        result = json.loads(_run(self.tool.execute(content="console.log('hi');")))
        assert result["endpoints_found"] == 0

    def test_execute_inline_with_fetch(self):
        js = 'fetch("/api/login")'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result["endpoints_found"] >= 1
        assert "/api/login" in result["endpoints"]

    def test_execute_inline_multiple_patterns(self):
        js = 'axios.get("/api/a"); fetch("/api/b"); xhr.open("GET", "/api/c");'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result["endpoints_found"] >= 3

    def test_execute_no_args_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_execute_url_fetch_success(self):
        js_content = b'fetch("/api/data")'
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = js_content
        mock_resp.status = 200

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(url="http://example.com/app.js")))
        assert result["endpoints_found"] >= 1

    def test_execute_url_fetch_failure(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(url="http://example.com/app.js"))

    def test_result_has_source_key(self):
        result = json.loads(_run(self.tool.execute(content="var x = 1;")))
        assert "source" in result

    def test_result_has_endpoints_list(self):
        result = json.loads(_run(self.tool.execute(content="var x = 1;")))
        assert isinstance(result["endpoints"], list)

    def test_deduplicated_endpoints(self):
        js = 'fetch("/api/x"); fetch("/api/x");'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result["endpoints"].count("/api/x") == 1

    def test_max_200_endpoints(self):
        # Manufacture 300 unique endpoints
        lines = [f'fetch("/api/ep{i}")' for i in range(300)]
        js = "\n".join(lines)
        result = json.loads(_run(self.tool.execute(content=js)))
        assert len(result["endpoints"]) <= 200

    def test_execute_xhr_open(self):
        js = 'xhr.open("POST", "/api/submit")'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert "/api/submit" in result["endpoints"]

    def test_content_takes_precedence_over_url(self):
        # content is provided alongside url → should NOT make network call
        js = 'fetch("/api/inline")'
        with patch("urllib.request.urlopen", side_effect=Exception("should not be called")):
            result = json.loads(_run(self.tool.execute(content=js, url="http://example.com/app.js")))
        assert "/api/inline" in result["endpoints"]


# ---------------------------------------------------------------------------
# 3. JSSecretFinderTool
# ---------------------------------------------------------------------------

class TestJSSecretFinderTool:
    def setup_method(self):
        self.tool = JSSecretFinderTool()

    def test_name(self):
        assert self.tool.name == "js_secret_finder"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_has_parameters(self):
        assert "properties" in self.tool.metadata.parameters

    def test_no_args_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_no_secrets_clean_code(self):
        result = json.loads(_run(self.tool.execute(content="function add(a,b){return a+b;}")))
        assert result["secrets_found"] == 0

    def test_detects_aws_access_key(self):
        js = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result["secrets_found"] >= 1
        types_found = [f["type"] for f in result["findings"]]
        assert "AWS Access Key" in types_found

    def test_detects_github_token(self):
        js = "const token = 'ghp_abcdefghijklmnopqrstuvwxyz123456789AB';"
        result = json.loads(_run(self.tool.execute(content=js)))
        types_found = [f["type"] for f in result["findings"]]
        assert "GitHub Token" in types_found

    def test_detects_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = json.loads(_run(self.tool.execute(content=f"var t = '{jwt}';")))
        types_found = [f["type"] for f in result["findings"]]
        assert "JWT" in types_found

    def test_detects_generic_password(self):
        js = "password = 'SuperSecret123!';"
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result["secrets_found"] >= 1

    def test_findings_have_severity(self):
        js = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        result = json.loads(_run(self.tool.execute(content=js)))
        for finding in result["findings"]:
            assert "severity" in finding

    def test_aws_key_is_critical(self):
        js = "var key = 'AKIAIOSFODNN7EXAMPLE';"
        result = json.loads(_run(self.tool.execute(content=js)))
        aws_findings = [f for f in result["findings"] if f["type"] == "AWS Access Key"]
        assert any(f["severity"] == "critical" for f in aws_findings)

    def test_url_fetch_mock(self):
        js_content = b"const token = 'ghp_abcdefghijklmnopqrstuvwxyz123456789AB';"
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = js_content
        mock_resp.status = 200
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(url="http://example.com/app.js")))
        assert result["secrets_found"] >= 1

    def test_url_fetch_failure(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(url="http://example.com/app.js"))

    def test_result_structure(self):
        result = json.loads(_run(self.tool.execute(content="var x = 1;")))
        assert "source" in result
        assert "secrets_found" in result
        assert "findings" in result

    def test_max_100_findings(self):
        # Build a JS with many AWS keys (unique)
        lines = [f"var k{i} = 'AKIA{'A'*16}';" for i in range(120)]
        js = "\n".join(lines)
        result = json.loads(_run(self.tool.execute(content=js)))
        assert len(result["findings"]) <= 100

    def test_high_entropy_detected(self):
        # Insert a high-entropy base64-ish string
        js = "var token = 'aB3dEfGhIjKlMnOpQrStUvWxYz012345Zz9Y';"
        result = json.loads(_run(self.tool.execute(content=js)))
        # Should at least find the high-entropy string
        assert result["secrets_found"] >= 1


# ---------------------------------------------------------------------------
# 4. JSLibVulnTool
# ---------------------------------------------------------------------------

class TestJSLibVulnTool:
    def setup_method(self):
        self.tool = JSLibVulnTool()
        # Minimal in-memory vuln DB for isolation
        self._sample_db = {
            "jquery": {
                "vulnerabilities": [
                    {
                        "below": "3.5.0",
                        "atOrAbove": "1.0.0",
                        "severity": "medium",
                        "identifiers": {"CVE": ["CVE-2020-11022"]},
                        "info": ["https://example.com"],
                    }
                ],
                "extractors": {
                    "filename": ["jquery[^/]*\\.js"],
                    "filecontent": ["jQuery JavaScript Library v([\\d\\.]+)"],
                },
            }
        }

    def test_name(self):
        assert self.tool.name == "js_lib_vuln"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_metadata_has_parameters(self):
        assert "properties" in self.tool.metadata.parameters

    def test_no_args_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_detects_via_filecontent(self):
        js = "/* jQuery JavaScript Library v1.12.4 */ function(){}"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        assert result["vulnerable_libraries"] >= 1
        lib_names = [f["library"] for f in result["findings"]]
        assert "jquery" in lib_names

    def test_detects_via_filename(self):
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(filename="jquery-3.4.1.min.js")))
        assert result["vulnerable_libraries"] >= 1

    def test_no_match_clean_lib(self):
        js = "function hello(){return 'world';}"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        assert result["vulnerable_libraries"] == 0

    def test_version_above_patched_no_match(self):
        # jQuery 3.5.0 is the patched version → not vulnerable
        js = "/* jQuery JavaScript Library v3.5.0 */"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        assert result["vulnerable_libraries"] == 0

    def test_real_db_loads(self):
        db = _load_vuln_db()
        assert len(db) > 0
        assert "jquery" in db

    def test_result_structure(self):
        js = "var x = 1;"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        assert "source" in result
        assert "vulnerable_libraries" in result
        assert "findings" in result

    def test_findings_have_cve(self):
        js = "/* jQuery JavaScript Library v1.12.4 */"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        for finding in result["findings"]:
            assert "cve" in finding

    def test_findings_have_severity(self):
        js = "/* jQuery JavaScript Library v1.12.4 */"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        for finding in result["findings"]:
            assert "severity" in finding

    def test_url_fetch_mock(self):
        js_bytes = b"/* jQuery JavaScript Library v1.12.4 */"
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = js_bytes
        mock_resp.status = 200
        with patch("urllib.request.urlopen", return_value=mock_resp):
            with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
                result = json.loads(
                    _run(self.tool.execute(url="http://example.com/jquery-1.12.4.min.js"))
                )
        assert result["vulnerable_libraries"] >= 1

    def test_url_fetch_failure(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            with pytest.raises(ToolExecutionError):
                _run(self.tool.execute(url="http://example.com/app.js"))

    def test_affected_range_in_findings(self):
        js = "/* jQuery JavaScript Library v1.12.4 */"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        for finding in result["findings"]:
            assert "affected_range" in finding

    def test_info_urls_in_findings(self):
        js = "/* jQuery JavaScript Library v1.12.4 */"
        with patch.object(_js_mod, "_load_vuln_db", return_value=self._sample_db):
            result = json.loads(_run(self.tool.execute(content=js)))
        for finding in result["findings"]:
            assert "info" in finding


# ---------------------------------------------------------------------------
# 5. SourceMapAnalyzeTool
# ---------------------------------------------------------------------------

_SAMPLE_SOURCE_MAP = json.dumps({
    "version": 3,
    "sources": ["src/app.ts", "src/utils.ts"],
    "mappings": "AAAA",
    "sourceRoot": "/src",
})


class TestSourceMapAnalyzeTool:
    def setup_method(self):
        self.tool = SourceMapAnalyzeTool()

    def test_name(self):
        assert self.tool.name == "source_map_analyze"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_no_args_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_inline_valid_map(self):
        result = json.loads(_run(self.tool.execute(map_content=_SAMPLE_SOURCE_MAP)))
        assert result["source_maps_found"] == 1
        assert result["findings"][0]["source_count"] == 2

    def test_inline_invalid_json(self):
        result = json.loads(_run(self.tool.execute(map_content="not json")))
        assert result["source_maps_found"] == 0

    def test_inline_not_a_map(self):
        result = json.loads(_run(self.tool.execute(map_content='{"foo":"bar"}')))
        assert result["source_maps_found"] == 0

    def test_url_probe_found(self):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = _SAMPLE_SOURCE_MAP.encode()
        mock_resp.status = 200
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(url="http://example.com/app.js")))
        assert result["source_maps_found"] == 1
        assert result["severity"] == "high"

    def test_url_probe_not_found(self):
        with patch("urllib.request.urlopen", side_effect=Exception("404")):
            result = json.loads(_run(self.tool.execute(url="http://example.com/app.js")))
        assert result["source_maps_found"] == 0

    def test_candidate_map_urls_min_js(self):
        urls = SourceMapAnalyzeTool._candidate_map_urls("http://example.com/app.min.js")
        assert "http://example.com/app.min.js.map" in urls

    def test_candidate_map_urls_plain_js(self):
        urls = SourceMapAnalyzeTool._candidate_map_urls("http://example.com/app.js")
        assert "http://example.com/app.js.map" in urls

    def test_result_structure(self):
        result = json.loads(_run(self.tool.execute(map_content=_SAMPLE_SOURCE_MAP)))
        assert "source_maps_found" in result
        assert "findings" in result


# ---------------------------------------------------------------------------
# 6. DOMSinkAnalyzerTool
# ---------------------------------------------------------------------------

class TestDOMSinkAnalyzerTool:
    def setup_method(self):
        self.tool = DOMSinkAnalyzerTool()

    def test_name(self):
        assert self.tool.name == "dom_sink_analyzer"

    def test_description_nonempty(self):
        assert len(self.tool.description) > 10

    def test_no_args_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute())

    def test_clean_code_no_sinks(self):
        result = json.loads(_run(self.tool.execute(content="function add(a,b){return a+b;}")))
        assert result["total_sink_occurrences"] == 0

    def test_detects_inner_html(self):
        js = 'el.innerHTML = userInput;'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result["total_sink_occurrences"] >= 1
        assert "innerHTML assignment" in result["sink_summary"]

    def test_detects_eval(self):
        js = 'eval(data);'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert "eval()" in result["sink_summary"]

    def test_detects_document_write(self):
        js = 'document.write(payload);'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert "document.write" in result["sink_summary"]

    def test_url_fetch_mock(self):
        js_bytes = b"el.innerHTML = userInput;"
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = js_bytes
        mock_resp.status = 200
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = json.loads(_run(self.tool.execute(url="http://example.com/app.js")))
        assert result["total_sink_occurrences"] >= 1

    def test_result_has_owasp_tag(self):
        js = 'el.innerHTML = x;'
        result = json.loads(_run(self.tool.execute(content=js)))
        assert result.get("owasp") == "A03:2021-Injection"
