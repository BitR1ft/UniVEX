"""
Tests for Day 7 — Proxy Agent Tools: Replay, Intruder, Comparer

Coverage (92 tests):
  TestHttpInterceptTool       (18 tests) — start/stop/status/add_rule/list_rules/remove_rule
  TestRequestReplayTool       (14 tests) — replay logic, modifications, store_result flag
  TestRequestIntruderTool     (22 tests) — sniper, battering_ram, pitchfork, cluster_bomb,
                                           payload sequences, cap, invalid params
  TestRequestComparerTool     (18 tests) — same/different status, headers, body diffs,
                                           diff_format options, missing requests
  TestTrafficLoggerTool       (14 tests) — search, export (HAR/JSON/CSV), count, clear
  TestScopeManagerTool        (6 tests)  — set/add/list/clear scope actions

All tests use asyncio.run(); no live network calls.
HTTP requests in Replay/Intruder are mocked with unittest.mock.patch.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import time
import types
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap stubs to avoid heavy transitive imports
# ---------------------------------------------------------------------------


def _ensure_stub(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


for _pkg in [
    "app",
    "app.agent",
    "app.agent.tools",
    "app.proxy",
    "app.mcp",
    "app.mcp.base_server",
]:
    _ensure_stub(_pkg)

import pydantic  # real pydantic

_BACKEND = os.path.join(os.path.dirname(__file__), "..", "..", "app")


def _load_module(rel_path: str, module_name: str) -> types.ModuleType:
    path = os.path.normpath(os.path.join(_BACKEND, rel_path))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load dependency chain in order
_base_tool_mod = _load_module("agent/tools/base_tool.py", "app.agent.tools.base_tool")
_error_mod = _load_module("agent/tools/error_handling.py", "app.agent.tools.error_handling")
_store_mod = _load_module("proxy/request_store.py", "app.proxy.request_store")
_interceptor_mod = _load_module("proxy/interceptor.py", "app.proxy.interceptor")
_proxy_tools_mod = _load_module("agent/tools/proxy_tools.py", "app.agent.tools.proxy_tools")

# Aliases
BaseTool = _base_tool_mod.BaseTool
ToolExecutionError = _error_mod.ToolExecutionError
CapturedRequest = _store_mod.CapturedRequest
CapturedResponse = _store_mod.CapturedResponse
RequestStore = _store_mod.RequestStore
InterceptRule = _interceptor_mod.InterceptRule
ScopeFilter = _interceptor_mod.ScopeFilter

HttpInterceptTool = _proxy_tools_mod.HttpInterceptTool
RequestReplayTool = _proxy_tools_mod.RequestReplayTool
RequestIntruderTool = _proxy_tools_mod.RequestIntruderTool
RequestComparerTool = _proxy_tools_mod.RequestComparerTool
TrafficLoggerTool = _proxy_tools_mod.TrafficLoggerTool
ScopeManagerTool = _proxy_tools_mod.ScopeManagerTool
ALL_PROXY_TOOLS = _proxy_tools_mod.ALL_PROXY_TOOLS
_shared_store = _proxy_tools_mod._shared_store
_shared_scope = _proxy_tools_mod._shared_scope
_shared_proxy = _proxy_tools_mod._shared_proxy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_response(**kwargs) -> CapturedResponse:
    defaults = dict(
        status_code=200,
        reason="OK",
        headers={"Content-Type": "text/html"},
        body="<html>hello</html>",
        content_type="text/html",
        elapsed_ms=42.0,
    )
    defaults.update(kwargs)
    return CapturedResponse(**defaults)


def _make_request(store: RequestStore = None, **kwargs) -> CapturedRequest:
    defaults = dict(
        id="",
        timestamp=time.time(),
        method="GET",
        url="https://example.com/page",
        headers={"Host": "example.com"},
        body="",
        response=_make_response(),
        tags=[],
        notes="",
    )
    defaults.update(kwargs)
    req = CapturedRequest(**defaults)
    if store is not None:
        asyncio.run(store.store(req))
    return req


def _fresh_store() -> RequestStore:
    """Return a new empty RequestStore."""
    return RequestStore()


def _fresh_scope() -> ScopeFilter:
    return ScopeFilter()


def _fresh_proxy():
    """Return a fresh ProxyInterceptor backed by a fresh store."""
    from app.proxy.interceptor import ProxyInterceptor

    store = _fresh_store()
    scope = _fresh_scope()
    return _interceptor_mod.ProxyInterceptor(store=store, scope=scope)


# ===========================================================================
# TestHttpInterceptTool
# ===========================================================================


class TestHttpInterceptTool:
    def _tool(self):
        return HttpInterceptTool()

    def test_metadata_name(self):
        assert self._tool().name == "http_intercept"

    def test_metadata_parameters_has_action(self):
        params = self._tool().metadata.parameters
        assert "action" in params["properties"]

    def test_status_not_running(self):
        tool = self._tool()
        # Ensure proxy is stopped before test
        _shared_proxy._running = False
        result = json.loads(asyncio.run(tool.execute(action="status")))
        assert result["running"] is False

    def test_stop_when_not_running(self):
        tool = self._tool()
        _shared_proxy._running = False
        result = json.loads(asyncio.run(tool.execute(action="stop")))
        assert result["status"] == "not_running"

    def test_start_when_mitmproxy_unavailable(self):
        tool = self._tool()
        _shared_proxy._running = False
        with patch.object(_interceptor_mod, "_MITMPROXY_AVAILABLE", False):
            result = json.loads(asyncio.run(tool.execute(action="start", port=9999)))
        assert result["status"] == "error"

    def test_start_when_already_running(self):
        tool = self._tool()
        _shared_proxy._running = True
        result = json.loads(asyncio.run(tool.execute(action="start", port=9999)))
        assert result["status"] == "already_running"
        _shared_proxy._running = False  # cleanup

    def test_add_rule_url_pattern(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        result = json.loads(asyncio.run(tool.execute(action="add_rule", url_pattern=r"/login")))
        assert result["status"] == "rule_added"
        assert result["rule_count"] == 1
        _shared_proxy.clear_rules()

    def test_add_rule_method_filter(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        result = json.loads(asyncio.run(tool.execute(action="add_rule", method="POST")))
        assert result["status"] == "rule_added"
        _shared_proxy.clear_rules()

    def test_add_rule_with_tag(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        result = json.loads(asyncio.run(tool.execute(action="add_rule", url_pattern=r"/admin", tag="admin-area")))
        assert result["rule_count"] == 1
        _shared_proxy.clear_rules()

    def test_add_rule_invalid_regex_raises(self):
        tool = self._tool()
        with pytest.raises(ToolExecutionError):
            asyncio.run(tool.execute(action="add_rule", url_pattern="[invalid"))

    def test_list_rules_empty(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        result = json.loads(asyncio.run(tool.execute(action="list_rules")))
        assert result["rules"] == []

    def test_list_rules_shows_added(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        asyncio.run(tool.execute(action="add_rule", url_pattern=r"/secret", tag="sensitive"))
        result = json.loads(asyncio.run(tool.execute(action="list_rules")))
        assert len(result["rules"]) == 1
        assert result["rules"][0]["tag"] == "sensitive"
        _shared_proxy.clear_rules()

    def test_remove_rule_valid(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        asyncio.run(tool.execute(action="add_rule", url_pattern=r"/test"))
        result = json.loads(asyncio.run(tool.execute(action="remove_rule", rule_index=0)))
        assert result["status"] == "rule_removed"
        assert result["rule_count"] == 0

    def test_remove_rule_out_of_range(self):
        tool = self._tool()
        _shared_proxy.clear_rules()
        with pytest.raises(ToolExecutionError):
            asyncio.run(tool.execute(action="remove_rule", rule_index=99))

    def test_remove_rule_missing_index_raises(self):
        tool = self._tool()
        with pytest.raises(ToolExecutionError):
            asyncio.run(tool.execute(action="remove_rule"))

    def test_unknown_action_raises(self):
        tool = self._tool()
        with pytest.raises(ToolExecutionError):
            asyncio.run(tool.execute(action="fly_to_the_moon"))

    def test_status_shows_captured_count(self):
        tool = self._tool()
        _shared_proxy._running = False
        result = json.loads(asyncio.run(tool.execute(action="status")))
        assert "captured_requests" in result

    def test_is_base_tool_subclass(self):
        assert isinstance(self._tool(), BaseTool)

    def test_all_proxy_tools_includes_http_intercept(self):
        names = [t.name for t in ALL_PROXY_TOOLS]
        assert "http_intercept" in names


# ===========================================================================
# TestRequestReplayTool — mock HTTP calls
# ===========================================================================

_MOCK_HTTP_RESPONSE = (200, "OK", {"Content-Type": "text/html"}, "<html>replayed</html>", 55.0)


class TestRequestReplayTool:
    def _tool(self):
        return RequestReplayTool()

    def _store_with_request(self, req_id: str = "replay-req") -> RequestStore:
        store = _fresh_store()
        req = CapturedRequest(
            id=req_id,
            timestamp=time.time(),
            method="GET",
            url="https://target.com/page",
            headers={"Host": "target.com"},
            body="",
            response=_make_response(status_code=200, body="original body"),
            tags=[],
            notes="",
        )
        asyncio.run(store.store(req))
        return store

    def test_metadata_name(self):
        assert self._tool().name == "request_replay"

    def test_missing_request_raises(self):
        # Patch _shared_store.get to return None
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=None)):
            with pytest.raises(ToolExecutionError, match="not found"):
                asyncio.run(self._tool().execute(request_id="nonexistent"))

    def test_replay_basic(self):
        req = CapturedRequest(
            id="basic-replay",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="new-id")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE):
            result = json.loads(asyncio.run(self._tool().execute(request_id="basic-replay")))
        assert result["replayed"]["status"] == 200

    def test_replay_with_url_override(self):
        req = CapturedRequest(
            id="url-override",
            timestamp=time.time(),
            method="GET",
            url="https://example.com/page",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE):
            result = json.loads(asyncio.run(
                self._tool().execute(request_id="url-override", url="https://other.com/new")
            ))
        assert result["replayed"]["url"] == "https://other.com/new"

    def test_replay_with_method_override(self):
        req = CapturedRequest(
            id="meth-override",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE):
            result = json.loads(asyncio.run(
                self._tool().execute(request_id="meth-override", method="POST")
            ))
        assert result["replayed"]["method"] == "POST"

    def test_replay_with_header_override(self):
        req = CapturedRequest(
            id="hdr-override",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={"Authorization": "Bearer old"},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE) as mock_http:
            asyncio.run(self._tool().execute(
                request_id="hdr-override",
                headers={"Authorization": "Bearer new"}
            ))
            call_headers = mock_http.call_args[0][2]
            assert call_headers.get("Authorization") == "Bearer new"

    def test_replay_cookies_merge(self):
        req = CapturedRequest(
            id="cookie-merge",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={"Cookie": "session=abc"},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE) as mock_http:
            asyncio.run(self._tool().execute(
                request_id="cookie-merge",
                cookies={"admin": "1"}
            ))
            call_headers = mock_http.call_args[0][2]
            assert "session=abc" in call_headers["Cookie"]
            assert "admin=1" in call_headers["Cookie"]

    def test_replay_store_result_false(self):
        req = CapturedRequest(
            id="no-store",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock()) as mock_store, \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE):
            asyncio.run(self._tool().execute(request_id="no-store", store_result=False))
        mock_store.assert_not_called()

    def test_replay_returns_original_info(self):
        req = CapturedRequest(
            id="original-info",
            timestamp=time.time(),
            method="GET",
            url="https://example.com/original",
            headers={},
            body="",
            response=_make_response(status_code=200),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE):
            result = json.loads(asyncio.run(self._tool().execute(request_id="original-info")))
        assert result["original"]["url"] == "https://example.com/original"
        assert result["original"]["status"] == 200

    def test_network_error_raises_tool_error(self):
        req = CapturedRequest(
            id="net-err",
            timestamp=time.time(),
            method="GET",
            url="https://unreachable.internal",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_proxy_tools_mod, "_http_request", side_effect=Exception("Connection refused")):
            with pytest.raises(ToolExecutionError, match="Connection refused"):
                asyncio.run(self._tool().execute(request_id="net-err"))

    def test_metadata_parameters_has_request_id(self):
        params = self._tool().metadata.parameters
        assert "request_id" in params["properties"]

    def test_is_base_tool_subclass(self):
        assert isinstance(self._tool(), BaseTool)

    def test_all_proxy_tools_includes_replay(self):
        names = [t.name for t in ALL_PROXY_TOOLS]
        assert "request_replay" in names

    def test_replay_body_override(self):
        req = CapturedRequest(
            id="body-override",
            timestamp=time.time(),
            method="POST",
            url="https://example.com/api",
            headers={"Content-Type": "application/json"},
            body='{"old": true}',
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE) as mock_http:
            asyncio.run(self._tool().execute(request_id="body-override", body='{"new": true}'))
            sent_body = mock_http.call_args[0][3]
            assert '{"new": true}' in (sent_body or "")

    def test_replay_response_preview_truncated(self):
        req = CapturedRequest(
            id="big-body",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        big_body = "X" * 5000
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=(200, "OK", {}, big_body, 10.0)):
            result = json.loads(asyncio.run(self._tool().execute(request_id="big-body")))
        assert len(result["replayed"]["body_preview"]) <= 500

    def test_replay_elapsed_ms_present(self):
        req = CapturedRequest(
            id="elapsed",
            timestamp=time.time(),
            method="GET",
            url="https://example.com",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="x")), \
             patch.object(_proxy_tools_mod, "_http_request", return_value=_MOCK_HTTP_RESPONSE):
            result = json.loads(asyncio.run(self._tool().execute(request_id="elapsed")))
        assert result["replayed"]["elapsed_ms"] == 55.0


# ===========================================================================
# TestRequestIntruderTool
# ===========================================================================


class TestRequestIntruderTool:
    def _tool(self):
        return RequestIntruderTool()

    def _mock_http(self, status=200):
        return (status, "OK", {"Content-Type": "text/html"}, f"body-{status}", 10.0)

    def test_metadata_name(self):
        assert self._tool().name == "request_intruder"

    def test_is_base_tool_subclass(self):
        assert isinstance(self._tool(), BaseTool)

    def test_sniper_single_position(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com/login?user=§USER§",
                method="GET",
                payloads=[["admin", "root", "user"]],
                attack_type="sniper",
            )))
        assert result["attack_type"] == "sniper"
        assert result["total_requests"] == 3

    def test_sniper_multiple_positions(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                method="POST",
                body="user=§USER§&role=§ROLE§",
                payloads=[["admin", "guest"]],
                attack_type="sniper",
            )))
        # sniper: 2 positions * 2 payloads = 4 requests
        assert result["total_requests"] == 4

    def test_battering_ram(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                body="a=§A§&b=§B§",
                payloads=[["x", "y", "z"]],
                attack_type="battering_ram",
            )))
        assert result["total_requests"] == 3
        # same payload in both positions
        for r in result["results"]:
            assert r["payloads"][0] == r["payloads"][1]

    def test_pitchfork(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                body="user=§U§&pass=§P§",
                payloads=[["admin", "root"], ["password", "toor"]],
                attack_type="pitchfork",
            )))
        # pitchfork: zip → 2 requests
        assert result["total_requests"] == 2
        assert result["results"][0]["payloads"] == ["admin", "password"]
        assert result["results"][1]["payloads"] == ["root", "toor"]

    def test_cluster_bomb(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                body="u=§U§&p=§P§",
                payloads=[["admin", "user"], ["pass1", "pass2"]],
                attack_type="cluster_bomb",
            )))
        # cluster_bomb: 2*2 = 4
        assert result["total_requests"] == 4

    def test_max_requests_cap(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[list("abcdefghijklmnopqrst")],  # 20 string payloads
                attack_type="sniper",
                max_requests=10,
            )))
        assert result["total_requests"] == 10

    def test_invalid_attack_type_raises(self):
        tool = self._tool()
        with pytest.raises(ToolExecutionError, match="attack_type"):
            asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[["a"]],
                attack_type="invalid_type",
            ))

    def test_empty_payloads_raises(self):
        tool = self._tool()
        with pytest.raises(ToolExecutionError):
            asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[],
            ))

    def test_result_includes_status_code(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=(403, "Forbidden", {}, "", 5.0)):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[["payload1"]],
            )))
        assert result["results"][0]["status"] == 403

    def test_network_error_captured_in_results(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", side_effect=Exception("Timeout")):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[["a"]],
            )))
        assert "error" in result["results"][0]

    def test_store_results_false_no_store_call(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()), \
             patch.object(_shared_store, "store", new=AsyncMock()) as mock_store:
            asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[["a"]],
                store_results=False,
            ))
        mock_store.assert_not_called()

    def test_store_results_true_calls_store(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()), \
             patch.object(_shared_store, "store", new=AsyncMock(return_value="stored-id")) as mock_store:
            asyncio.run(tool.execute(
                url="https://example.com/§X§",
                payloads=[["a"]],
                store_results=True,
            ))
        mock_store.assert_called_once()

    def test_positions_listed_in_output(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com/§USERNAME§",
                payloads=[["admin"]],
            )))
        assert "USERNAME" in result["positions"]

    def test_url_encoding_applied_to_payload(self):
        tool = self._tool()
        captured_urls = []

        def _capture(*args, **kwargs):
            captured_urls.append(args[0])
            return self._mock_http()

        with patch.object(_proxy_tools_mod, "_http_request", side_effect=_capture):
            asyncio.run(tool.execute(
                url="https://example.com/?q=§Q§",
                payloads=[["hello world"]],
            ))
        assert "hello%20world" in captured_urls[0]

    def test_pitchfork_padding_unequal_lengths(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                body="a=§A§&b=§B§",
                payloads=[["x", "y", "z"], ["1", "2"]],  # different lengths
                attack_type="pitchfork",
            )))
        # Should pad shorter list → 3 requests (max length)
        assert result["total_requests"] == 3

    def test_metadata_has_attack_types(self):
        params = self._tool().metadata.parameters
        attack_prop = params["properties"]["attack_type"]
        assert "sniper" in attack_prop.get("enum", [])
        assert "cluster_bomb" in attack_prop.get("enum", [])

    def test_default_attack_type_is_sniper(self):
        params = self._tool().metadata.parameters
        assert params["properties"]["attack_type"].get("default") == "sniper"

    def test_all_proxy_tools_includes_intruder(self):
        names = [t.name for t in ALL_PROXY_TOOLS]
        assert "request_intruder" in names

    def test_no_positions_in_url_or_body(self):
        """No §markers§ means no positions — should fire 0 requests for sniper."""
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com/no-markers",
                payloads=[["a", "b"]],
                attack_type="sniper",
            )))
        assert result["total_requests"] == 0

    def test_cluster_bomb_large_product_capped(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                body="a=§A§&b=§B§",
                payloads=[list("abcdefghij"), list("abcdefghij")],  # 10*10 = 100 combos
                attack_type="cluster_bomb",
                max_requests=15,
            )))
        assert result["total_requests"] == 15

    def test_battering_ram_all_positions_same(self):
        tool = self._tool()
        with patch.object(_proxy_tools_mod, "_http_request", return_value=self._mock_http()):
            result = json.loads(asyncio.run(tool.execute(
                url="https://example.com",
                body="f1=§A§&f2=§B§&f3=§C§",
                payloads=[["PAYLOAD"]],
                attack_type="battering_ram",
            )))
        assert result["total_requests"] == 1
        assert result["results"][0]["payloads"] == ["PAYLOAD", "PAYLOAD", "PAYLOAD"]


# ===========================================================================
# TestRequestComparerTool
# ===========================================================================


class TestRequestComparerTool:
    def _tool(self):
        return RequestComparerTool()

    def _req(self, req_id: str, **resp_kwargs) -> CapturedRequest:
        return CapturedRequest(
            id=req_id,
            timestamp=time.time(),
            method="GET",
            url="https://example.com/page",
            headers={},
            body="",
            response=_make_response(**resp_kwargs),
            tags=[],
            notes="",
        )

    def test_metadata_name(self):
        assert self._tool().name == "request_comparer"

    def test_missing_both_raises(self):
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=None)):
            with pytest.raises(ToolExecutionError):
                asyncio.run(self._tool().execute(request_id_a="x", request_id_b="y"))

    def test_identical_requests_no_diff(self):
        req = self._req("same-req")
        with patch.object(_shared_store, "get", new=AsyncMock(return_value=req)):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="same-req", request_id_b="same-req"
            )))
        assert result["has_differences"] is False

    def test_different_status_codes(self):
        req_a = self._req("req-a", status_code=200)
        req_b = self._req("req-b", status_code=403)
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="req-a", request_id_b="req-b"
            )))
        assert "status_code" in result["differences"]
        assert result["differences"]["status_code"]["a"] == 200
        assert result["differences"]["status_code"]["b"] == 403

    def test_different_body_lengths(self):
        req_a = self._req("ba", body="short")
        req_b = self._req("bb", body="this is a much longer response body")
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="ba", request_id_b="bb"
            )))
        assert "body_length" in result["differences"]

    def test_different_headers(self):
        req_a = self._req("ha", headers={"X-Custom": "value-a"})
        req_a.response.headers["X-Custom"] = "value-a"
        req_b = self._req("hb")
        req_b.response.headers["X-Custom"] = "value-b"
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="ha", request_id_b="hb"
            )))
        assert "headers" in result["differences"]

    def test_diff_format_unified(self):
        req_a = self._req("ua", body="line1\nline2\nline3")
        req_b = self._req("ub", body="line1\nmodified\nline3")
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="ua", request_id_b="ub", diff_format="unified"
            )))
        assert "body_diff" in result["differences"]
        assert "---" in result["differences"]["body_diff"] or "@@" in result["differences"]["body_diff"]

    def test_diff_format_side_by_side(self):
        req_a = self._req("sa", body="alpha\nbeta")
        req_b = self._req("sb", body="alpha\ngamma")
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="sa", request_id_b="sb", diff_format="side_by_side"
            )))
        assert "body_diff" in result["differences"]

    def test_diff_format_summary(self):
        req_a = self._req("sma", body="aaa")
        req_b = self._req("smb", body="bbb")
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="sma", request_id_b="smb", diff_format="summary"
            )))
        assert "body_diff" in result["differences"]
        assert "differ" in result["differences"]["body_diff"].lower()

    def test_has_differences_true_when_different(self):
        req_a = self._req("da", status_code=200)
        req_b = self._req("db", status_code=500)
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="da", request_id_b="db"
            )))
        assert result["has_differences"] is True

    def test_elapsed_ms_delta_reported(self):
        req_a = self._req("ea")
        req_a.response.elapsed_ms = 100.0
        req_b = self._req("eb")
        req_b.response.elapsed_ms = 250.0
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="ea", request_id_b="eb"
            )))
        assert "elapsed_ms" in result["differences"]
        assert result["differences"]["elapsed_ms"]["delta"] == 150.0

    def test_metadata_has_required_ids(self):
        params = self._tool().metadata.parameters
        assert "request_id_a" in params.get("required", [])
        assert "request_id_b" in params.get("required", [])

    def test_is_base_tool_subclass(self):
        assert isinstance(self._tool(), BaseTool)

    def test_all_proxy_tools_includes_comparer(self):
        names = [t.name for t in ALL_PROXY_TOOLS]
        assert "request_comparer" in names

    def test_url_difference_detected(self):
        req_a = CapturedRequest(
            id="url-a",
            timestamp=time.time(),
            method="GET",
            url="https://example.com/user/1",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        req_b = CapturedRequest(
            id="url-b",
            timestamp=time.time(),
            method="GET",
            url="https://example.com/user/2",
            headers={},
            body="",
            response=_make_response(),
            tags=[],
            notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="url-a", request_id_b="url-b"
            )))
        assert "url" in result["differences"]

    def test_method_difference_detected(self):
        req_a = CapturedRequest(
            id="ma", timestamp=time.time(), method="GET",
            url="https://example.com", headers={}, body="",
            response=_make_response(), tags=[], notes="",
        )
        req_b = CapturedRequest(
            id="mb", timestamp=time.time(), method="POST",
            url="https://example.com", headers={}, body="",
            response=_make_response(), tags=[], notes="",
        )
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="ma", request_id_b="mb"
            )))
        assert "method" in result["differences"]

    def test_result_contains_request_a_b_info(self):
        req_a = self._req("qa")
        req_b = self._req("qb")
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, req_b])):
            result = json.loads(asyncio.run(self._tool().execute(
                request_id_a="qa", request_id_b="qb"
            )))
        assert result["request_a"]["id"] == "qa"
        assert result["request_b"]["id"] == "qb"

    def test_missing_only_b_raises(self):
        req_a = self._req("only-a")
        with patch.object(_shared_store, "get", new=AsyncMock(side_effect=[req_a, None])):
            with pytest.raises(ToolExecutionError):
                asyncio.run(self._tool().execute(request_id_a="only-a", request_id_b="missing"))


# ===========================================================================
# TestTrafficLoggerTool
# ===========================================================================


class TestTrafficLoggerTool:
    def _tool(self):
        return TrafficLoggerTool()

    def test_metadata_name(self):
        assert self._tool().name == "traffic_logger"

    def test_count_action(self):
        with patch.object(_shared_store, "count", new=AsyncMock(return_value=42)):
            result = json.loads(asyncio.run(self._tool().execute(action="count")))
        assert result["total_captured"] == 42

    def test_clear_action(self):
        with patch.object(_shared_store, "clear", new=AsyncMock(return_value=7)):
            result = json.loads(asyncio.run(self._tool().execute(action="clear")))
        assert result["cleared"] == 7

    def test_search_action_returns_list(self):
        req = CapturedRequest(
            id="log1", timestamp=time.time(), method="GET",
            url="https://example.com", headers={}, body="",
            response=_make_response(), tags=[], notes="",
        )
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[req])):
            result = json.loads(asyncio.run(self._tool().execute(action="search")))
        assert result["total_matching"] == 1
        assert len(result["requests"]) == 1

    def test_search_invalid_regex_raises(self):
        with patch.object(_shared_store, "search", new=AsyncMock(side_effect=ValueError("Invalid body_regex"))):
            with pytest.raises(ToolExecutionError):
                asyncio.run(self._tool().execute(action="search", body_regex="[bad"))

    def test_export_json(self):
        req = CapturedRequest(
            id="ej1", timestamp=time.time(), method="GET",
            url="https://example.com", headers={}, body="",
            response=_make_response(), tags=[], notes="",
        )
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[req])):
            result = asyncio.run(self._tool().execute(action="export", format="json"))
        data = json.loads(result)
        assert isinstance(data, list)

    def test_export_csv(self):
        req = CapturedRequest(
            id="ec1", timestamp=time.time(), method="GET",
            url="https://example.com", headers={}, body="",
            response=_make_response(), tags=[], notes="",
        )
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[req])):
            result = asyncio.run(self._tool().execute(action="export", format="csv"))
        assert "ec1" in result

    def test_export_har(self):
        req = CapturedRequest(
            id="eh1", timestamp=time.time(), method="GET",
            url="https://example.com", headers={}, body="",
            response=_make_response(), tags=[], notes="",
        )
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[req])):
            result = asyncio.run(self._tool().execute(action="export", format="har"))
        har = json.loads(result)
        assert "log" in har

    def test_search_pagination(self):
        reqs = [
            CapturedRequest(
                id=f"pag{i}", timestamp=time.time(), method="GET",
                url="https://example.com", headers={}, body="",
                response=_make_response(), tags=[], notes="",
            )
            for i in range(20)
        ]
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=reqs)):
            result = json.loads(asyncio.run(self._tool().execute(
                action="search", page=2, page_size=5
            )))
        assert len(result["requests"]) == 5
        assert result["page"] == 2

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            asyncio.run(self._tool().execute(action="orbit"))

    def test_default_action_is_search(self):
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[])):
            result = json.loads(asyncio.run(self._tool().execute()))
        assert "total_matching" in result

    def test_is_base_tool_subclass(self):
        assert isinstance(self._tool(), BaseTool)

    def test_all_proxy_tools_includes_logger(self):
        names = [t.name for t in ALL_PROXY_TOOLS]
        assert "traffic_logger" in names

    def test_search_filters_passed_through(self):
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[])) as mock_search:
            asyncio.run(self._tool().execute(
                action="search",
                url_contains="target.com",
                method="POST",
                status_code=200,
                tag="auth",
            ))
        call_kwargs = mock_search.call_args[1]
        assert call_kwargs["url_contains"] == "target.com"
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["status_code"] == 200
        assert call_kwargs["tag"] == "auth"

    def test_export_applies_filters(self):
        with patch.object(_shared_store, "search", new=AsyncMock(return_value=[])) as mock_search:
            asyncio.run(self._tool().execute(action="export", format="json", url_contains="api"))
        call_kwargs = mock_search.call_args[1]
        assert call_kwargs["url_contains"] == "api"

    def test_metadata_has_action_enum(self):
        params = self._tool().metadata.parameters
        action_prop = params["properties"]["action"]
        assert "export" in action_prop.get("enum", [])


# ===========================================================================
# TestScopeManagerTool
# ===========================================================================


class TestScopeManagerTool:
    def _tool(self):
        return ScopeManagerTool()

    def test_metadata_name(self):
        assert self._tool().name == "scope_manager"

    def test_list_empty(self):
        _shared_scope.clear()
        result = json.loads(asyncio.run(self._tool().execute(action="list")))
        assert result["in_scope"] == []
        assert result["out_scope"] == []

    def test_set_scope(self):
        _shared_scope.clear()
        result = json.loads(asyncio.run(self._tool().execute(
            action="set",
            in_scope=[r"target\.com"],
            out_scope=[r"cdn\.target\.com"],
        )))
        assert result["in_scope_count"] == 1
        assert result["out_scope_count"] == 1

    def test_add_in_scope(self):
        _shared_scope.clear()
        result = json.loads(asyncio.run(self._tool().execute(
            action="add_in",
            in_scope=[r"example\.com"],
        )))
        assert "added" in result
        assert r"example\.com" in result["added"]

    def test_add_out_scope(self):
        _shared_scope.clear()
        result = json.loads(asyncio.run(self._tool().execute(
            action="add_out",
            out_scope=[r"google\.com"],
        )))
        assert result["status"] == "added_out_scope"

    def test_clear_action(self):
        _shared_scope.add_in_scope(r"anything\.com")
        result = json.loads(asyncio.run(self._tool().execute(action="clear")))
        assert result["status"] == "scope_cleared"
        assert len(_shared_scope._in_scope) == 0

    def test_all_proxy_tools_includes_scope_manager(self):
        names = [t.name for t in ALL_PROXY_TOOLS]
        assert "scope_manager" in names
