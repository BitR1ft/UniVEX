"""
Tests for Day 6 — Proxy MCP Server & Core Interception Engine

Coverage (85 tests):
  TestCapturedRequest         (12 tests) — dataclass, serialisation, HAR export
  TestCapturedResponse        (5 tests)  — dataclass construction + fields
  TestRequestStore            (28 tests) — store/get/update/delete/clear/search/
                                           TTL expiry/pagination/export/redis fallback
  TestScopeFilter             (10 tests) — in/out scope pattern matching
  TestInterceptRule           (10 tests) — rule matching logic
  TestSSLContextManager       (15 tests) — CA generation, leaf certs, cache, disk I/O
  TestProxyInterceptorState   (5 tests)  — running flag, stats, rules management (no mitmproxy)

All tests use asyncio.run(); no live network or mitmproxy calls.
Redis calls are mocked with MagicMock/AsyncMock.

Import strategy: direct importlib loading to bypass app/agent/__init__.py.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import time
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap stubs for heavy transitive imports
# ---------------------------------------------------------------------------


def _ensure_stub(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


for _pkg in ["app", "app.proxy", "app.mcp", "app.mcp.base_server"]:
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


_store_mod = _load_module("proxy/request_store.py", "app.proxy.request_store")
_scope_mod = None  # loaded as part of interceptor module below

# Load ssl_context — requires cryptography package
try:
    from cryptography import x509  # noqa: F401

    _ssl_mod = _load_module("proxy/ssl_context.py", "app.proxy.ssl_context")
    _SSL_AVAILABLE = True
except ImportError:
    _ssl_mod = None
    _SSL_AVAILABLE = False

# For interceptor we need the store module already registered
_interceptor_mod = _load_module("proxy/interceptor.py", "app.proxy.interceptor")

# Aliases
CapturedRequest = _store_mod.CapturedRequest
CapturedResponse = _store_mod.CapturedResponse
RequestStore = _store_mod.RequestStore

InterceptRule = _interceptor_mod.InterceptRule
ScopeFilter = _interceptor_mod.ScopeFilter
ProxyInterceptor = _interceptor_mod.ProxyInterceptor

if _SSL_AVAILABLE:
    SSLContextManager = _ssl_mod.SSLContextManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_response(**kwargs) -> CapturedResponse:
    defaults = dict(
        status_code=200,
        reason="OK",
        headers={"content-type": "text/html"},
        body="<html>hello</html>",
        content_type="text/html",
        elapsed_ms=42.0,
    )
    defaults.update(kwargs)
    return CapturedResponse(**defaults)


def _make_request(**kwargs) -> CapturedRequest:
    defaults = dict(
        id="test-id-1",
        timestamp=1_700_000_000.0,
        method="GET",
        url="https://example.com/page",
        headers={"Host": "example.com"},
        body="",
        response=_make_response(),
        tags=[],
        notes="",
    )
    defaults.update(kwargs)
    return CapturedRequest(**defaults)


# ===========================================================================
# TestCapturedResponse
# ===========================================================================


class TestCapturedResponse:
    def test_construction(self):
        r = _make_response()
        assert r.status_code == 200
        assert r.reason == "OK"
        assert r.content_type == "text/html"
        assert r.elapsed_ms == 42.0

    def test_headers_dict(self):
        r = _make_response(headers={"X-Foo": "bar"})
        assert r.headers["X-Foo"] == "bar"

    def test_empty_body(self):
        r = _make_response(body="")
        assert r.body == ""

    def test_binary_body_base64(self):
        import base64
        raw = base64.b64encode(b"\x00\x01\x02").decode()
        r = _make_response(body=raw)
        assert r.body == raw

    def test_large_elapsed(self):
        r = _make_response(elapsed_ms=9999.9)
        assert r.elapsed_ms == 9999.9


# ===========================================================================
# TestCapturedRequest
# ===========================================================================


class TestCapturedRequest:
    def test_construction(self):
        req = _make_request()
        assert req.id == "test-id-1"
        assert req.method == "GET"
        assert req.url == "https://example.com/page"

    def test_to_dict_round_trip(self):
        req = _make_request()
        d = req.to_dict()
        assert d["id"] == "test-id-1"
        assert d["method"] == "GET"
        assert d["response"]["status_code"] == 200

    def test_from_dict_round_trip(self):
        req = _make_request()
        d = req.to_dict()
        req2 = CapturedRequest.from_dict(d)
        assert req2.id == req.id
        assert req2.url == req.url
        assert req2.response.status_code == 200

    def test_from_dict_no_response(self):
        req = _make_request(response=None)
        d = req.to_dict()
        req2 = CapturedRequest.from_dict(d)
        assert req2.response is None

    def test_tags_default_empty(self):
        req = _make_request(tags=[])
        assert req.tags == []

    def test_tags_multiple(self):
        req = _make_request(tags=["pentest", "auth"])
        assert "auth" in req.tags

    def test_notes_default(self):
        req = _make_request()
        assert req.notes == ""

    def test_har_entry_structure(self):
        req = _make_request()
        entry = req.to_har_entry()
        assert "startedDateTime" in entry
        assert entry["request"]["method"] == "GET"
        assert entry["request"]["url"] == "https://example.com/page"
        assert entry["response"]["status"] == 200

    def test_har_entry_no_response(self):
        req = _make_request(response=None)
        entry = req.to_har_entry()
        assert entry["response"] == {}

    def test_to_dict_preserves_body(self):
        req = _make_request(body="param=value&other=test")
        d = req.to_dict()
        assert d["body"] == "param=value&other=test"

    def test_post_request(self):
        req = _make_request(method="POST", body="username=admin&password=secret")
        assert req.method == "POST"
        assert "admin" in req.body

    def test_har_timings(self):
        req = _make_request()
        entry = req.to_har_entry()
        assert entry["timings"]["wait"] == 42.0


# ===========================================================================
# TestRequestStore
# ===========================================================================


class TestRequestStore:
    def test_store_and_get(self):
        store = RequestStore()
        req = _make_request(id="")  # no id — store assigns one

        async def _run():
            req_id = await store.store(req)
            assert req_id
            result = await store.get(req_id)
            assert result is not None
            assert result.url == "https://example.com/page"

        asyncio.run(_run())

    def test_get_missing_returns_none(self):
        store = RequestStore()

        async def _run():
            result = await store.get("nonexistent-id")
            assert result is None

        asyncio.run(_run())

    def test_store_assigns_uuid(self):
        store = RequestStore()
        req = _make_request(id="")

        async def _run():
            req_id = await store.store(req)
            assert len(req_id) == 36  # UUID4 format

        asyncio.run(_run())

    def test_store_preserves_existing_id(self):
        store = RequestStore()
        req = _make_request(id="my-custom-id")

        async def _run():
            req_id = await store.store(req)
            assert req_id == "my-custom-id"

        asyncio.run(_run())

    def test_update_existing(self):
        store = RequestStore()
        req = _make_request(id="update-test")

        async def _run():
            await store.store(req)
            result = await store.update("update-test", notes="Updated note")
            assert result is True
            fetched = await store.get("update-test")
            assert fetched.notes == "Updated note"

        asyncio.run(_run())

    def test_update_missing(self):
        store = RequestStore()

        async def _run():
            result = await store.update("nonexistent", notes="x")
            assert result is False

        asyncio.run(_run())

    def test_delete_existing(self):
        store = RequestStore()
        req = _make_request(id="delete-me")

        async def _run():
            await store.store(req)
            deleted = await store.delete("delete-me")
            assert deleted is True
            fetched = await store.get("delete-me")
            assert fetched is None

        asyncio.run(_run())

    def test_delete_missing(self):
        store = RequestStore()

        async def _run():
            deleted = await store.delete("not-there")
            assert deleted is False

        asyncio.run(_run())

    def test_clear(self):
        store = RequestStore()

        async def _run():
            for i in range(5):
                await store.store(_make_request(id=f"req-{i}"))
            count = await store.clear()
            assert count == 5
            total = await store.count()
            assert total == 0

        asyncio.run(_run())

    def test_count(self):
        store = RequestStore()

        async def _run():
            assert await store.count() == 0
            await store.store(_make_request(id="c1"))
            await store.store(_make_request(id="c2"))
            assert await store.count() == 2

        asyncio.run(_run())

    def test_list_all_pagination(self):
        store = RequestStore()

        async def _run():
            for i in range(10):
                await store.store(_make_request(id=f"p-{i}"))
            page1 = await store.list_all(page=1, page_size=5)
            page2 = await store.list_all(page=2, page_size=5)
            assert len(page1) == 5
            assert len(page2) == 5

        asyncio.run(_run())

    def test_search_by_url(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="s1", url="https://target.com/login"))
            await store.store(_make_request(id="s2", url="https://other.com/page"))
            results = await store.search(url_contains="target.com")
            assert len(results) == 1
            assert results[0].id == "s1"

        asyncio.run(_run())

    def test_search_by_method(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="m1", method="POST"))
            await store.store(_make_request(id="m2", method="GET"))
            results = await store.search(method="POST")
            assert len(results) == 1
            assert results[0].method == "POST"

        asyncio.run(_run())

    def test_search_by_status_code(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="st1", response=_make_response(status_code=404)))
            await store.store(_make_request(id="st2", response=_make_response(status_code=200)))
            results = await store.search(status_code=404)
            assert len(results) == 1
            assert results[0].response.status_code == 404

        asyncio.run(_run())

    def test_search_by_content_type(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="ct1", response=_make_response(content_type="application/json")))
            await store.store(_make_request(id="ct2", response=_make_response(content_type="text/html")))
            results = await store.search(content_type_contains="json")
            assert len(results) == 1

        asyncio.run(_run())

    def test_search_by_body_regex(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="br1", body="admin=true&role=superuser"))
            await store.store(_make_request(id="br2", body="user=guest"))
            results = await store.search(body_regex=r"admin=true")
            assert len(results) == 1

        asyncio.run(_run())

    def test_search_by_tag(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="t1", tags=["pentest"]))
            await store.store(_make_request(id="t2", tags=["monitor"]))
            results = await store.search(tag="pentest")
            assert len(results) == 1

        asyncio.run(_run())

    def test_search_invalid_regex_raises(self):
        store = RequestStore()

        async def _run():
            with pytest.raises(ValueError, match="Invalid body_regex"):
                await store.search(body_regex="[invalid")

        asyncio.run(_run())

    def test_search_no_filter_returns_all(self):
        store = RequestStore()

        async def _run():
            await store.store(_make_request(id="a1"))
            await store.store(_make_request(id="a2"))
            results = await store.search()
            assert len(results) == 2

        asyncio.run(_run())

    def test_ttl_expiry(self):
        store = RequestStore(ttl_seconds=0)  # immediate expiry

        async def _run():
            await store.store(_make_request(id="ttl-test"))
            # Force eviction on next access
            await asyncio.sleep(0.01)
            result = await store.get("ttl-test")
            assert result is None

        asyncio.run(_run())

    def test_max_entries_eviction(self):
        store = RequestStore(max_entries=3)

        async def _run():
            for i in range(5):
                await store.store(_make_request(id=f"e-{i}"))
            total = await store.count()
            assert total == 3  # oldest evicted

        asyncio.run(_run())

    def test_export_har(self):
        store = RequestStore()
        entries = [_make_request(id="h1"), _make_request(id="h2")]
        har_str = store.export_har(entries)
        har = json.loads(har_str)
        assert har["log"]["version"] == "1.2"
        assert len(har["log"]["entries"]) == 2

    def test_export_json(self):
        store = RequestStore()
        entries = [_make_request(id="j1")]
        j = json.loads(store.export_json(entries))
        assert isinstance(j, list)
        assert j[0]["id"] == "j1"

    def test_export_csv(self):
        store = RequestStore()
        entries = [_make_request(id="csv1")]
        csv = store.export_csv(entries)
        assert "csv1" in csv
        assert "method" in csv.splitlines()[0]

    def test_redis_fallback_on_miss(self):
        """Store falls back to Redis get when in-memory miss."""
        redis_mock = MagicMock()
        req = _make_request(id="redis-hit")
        redis_mock.get = AsyncMock(return_value=json.dumps(req.to_dict()).encode())
        store = RequestStore(redis_client=redis_mock)

        async def _run():
            result = await store.get("redis-hit")
            assert result is not None
            assert result.id == "redis-hit"

        asyncio.run(_run())

    def test_redis_write_on_store(self):
        """Store writes through to Redis."""
        redis_mock = MagicMock()
        redis_mock.setex = AsyncMock()
        store = RequestStore(redis_client=redis_mock)
        req = _make_request(id="redis-write")

        async def _run():
            await store.store(req)
            redis_mock.setex.assert_called_once()

        asyncio.run(_run())

    def test_redis_failure_is_graceful(self):
        """Redis write failure does not propagate."""
        redis_mock = MagicMock()
        redis_mock.setex = AsyncMock(side_effect=Exception("Redis down"))
        store = RequestStore(redis_client=redis_mock)
        req = _make_request(id="redis-fail")

        async def _run():
            # Should not raise
            req_id = await store.store(req)
            assert req_id == "redis-fail"

        asyncio.run(_run())

    def test_search_combined_filters(self):
        store = RequestStore()

        async def _run():
            await store.store(
                _make_request(
                    id="combo",
                    method="POST",
                    url="https://api.example.com/v1/data",
                    response=_make_response(status_code=201, content_type="application/json"),
                )
            )
            await store.store(_make_request(id="other", method="GET", url="https://other.com"))

            results = await store.search(
                url_contains="api.example.com",
                method="POST",
                status_code=201,
                content_type_contains="json",
            )
            assert len(results) == 1
            assert results[0].id == "combo"

        asyncio.run(_run())


# ===========================================================================
# TestScopeFilter
# ===========================================================================


class TestScopeFilter:
    def test_no_rules_all_in_scope(self):
        sf = ScopeFilter()
        assert sf.is_in_scope("https://anything.com") is True

    def test_in_scope_match(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"target\.com")
        assert sf.is_in_scope("https://target.com/page") is True

    def test_in_scope_no_match(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"target\.com")
        assert sf.is_in_scope("https://other.com") is False

    def test_out_scope_drops(self):
        sf = ScopeFilter()
        sf.add_out_scope(r"cdn\.example\.com")
        assert sf.is_in_scope("https://cdn.example.com/asset.js") is False

    def test_out_scope_takes_priority(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"example\.com")
        sf.add_out_scope(r"cdn\.example\.com")
        assert sf.is_in_scope("https://cdn.example.com/img.png") is False
        assert sf.is_in_scope("https://www.example.com/page") is True

    def test_clear_resets_all(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"target\.com")
        sf.add_out_scope(r"cdn\.target\.com")
        sf.clear()
        assert sf.is_in_scope("https://anything.com") is True

    def test_multiple_in_scope_patterns(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"alpha\.com")
        sf.add_in_scope(r"beta\.com")
        assert sf.is_in_scope("https://alpha.com") is True
        assert sf.is_in_scope("https://beta.com") is True
        assert sf.is_in_scope("https://gamma.com") is False

    def test_case_insensitive(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"Target\.Com")
        assert sf.is_in_scope("https://target.com") is True

    def test_ip_address_in_scope(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"192\.168\.")
        assert sf.is_in_scope("http://192.168.1.100/admin") is True
        assert sf.is_in_scope("https://10.0.0.1") is False

    def test_path_matching(self):
        sf = ScopeFilter()
        sf.add_in_scope(r"/api/")
        assert sf.is_in_scope("https://example.com/api/users") is True
        assert sf.is_in_scope("https://example.com/static/logo.png") is False


# ===========================================================================
# TestInterceptRule
# ===========================================================================


class TestInterceptRule:
    def test_no_filters_matches_all(self):
        rule = InterceptRule()
        assert rule.matches("GET", "https://example.com", "") is True

    def test_url_pattern_match(self):
        rule = InterceptRule(url_pattern=r"login|signin")
        assert rule.matches("POST", "https://example.com/login", "") is True
        assert rule.matches("POST", "https://example.com/home", "") is False

    def test_method_filter(self):
        rule = InterceptRule(method="POST")
        assert rule.matches("POST", "https://example.com", "") is True
        assert rule.matches("GET", "https://example.com", "") is False

    def test_method_case_insensitive(self):
        rule = InterceptRule(method="post")
        assert rule.matches("POST", "https://example.com", "") is True

    def test_content_type_filter(self):
        rule = InterceptRule(content_type="application/json")
        assert rule.matches("POST", "https://example.com", "application/json; charset=utf-8") is True
        assert rule.matches("GET", "https://example.com", "text/html") is False

    def test_combined_filters(self):
        rule = InterceptRule(url_pattern=r"/api/", method="POST", content_type="json")
        assert rule.matches("POST", "https://example.com/api/users", "application/json") is True
        assert rule.matches("GET", "https://example.com/api/users", "application/json") is False

    def test_tag_set(self):
        rule = InterceptRule(tag="auth-endpoints")
        assert rule.tag == "auth-endpoints"

    def test_invalid_url_pattern_raises(self):
        with pytest.raises(ValueError):
            InterceptRule(url_pattern="[invalid")

    def test_pause_for_inspection_default_false(self):
        rule = InterceptRule()
        assert rule.pause_for_inspection is False

    def test_pause_for_inspection_set(self):
        rule = InterceptRule(pause_for_inspection=True)
        assert rule.pause_for_inspection is True


# ===========================================================================
# TestSSLContextManager
# ===========================================================================


@pytest.mark.skipif(not _SSL_AVAILABLE, reason="cryptography not installed")
class TestSSLContextManager:
    def test_initialize_generates_ca(self):
        mgr = SSLContextManager()
        mgr.initialize()
        assert mgr.initialized is True

    def test_ca_cert_pem_is_bytes(self):
        mgr = SSLContextManager()
        mgr.initialize()
        pem = mgr.ca_cert_pem
        assert isinstance(pem, bytes)
        assert b"BEGIN CERTIFICATE" in pem

    def test_ca_key_pem_is_bytes(self):
        mgr = SSLContextManager()
        mgr.initialize()
        pem = mgr.ca_key_pem
        assert isinstance(pem, bytes)
        assert b"BEGIN" in pem

    def test_initialize_idempotent(self):
        mgr = SSLContextManager()
        mgr.initialize()
        cert_pem_1 = mgr.ca_cert_pem
        mgr.initialize()  # second call — should not regenerate
        assert mgr.ca_cert_pem == cert_pem_1

    def test_not_initialized_raises_on_cert_access(self):
        mgr = SSLContextManager()
        with pytest.raises(RuntimeError):
            _ = mgr.ca_cert_pem

    def test_get_cert_returns_pem_tuple(self):
        mgr = SSLContextManager()
        mgr.initialize()
        cert_pem, key_pem = mgr.get_cert("example.com")
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"BEGIN" in key_pem

    def test_get_cert_cached(self):
        mgr = SSLContextManager()
        mgr.initialize()
        cert1 = mgr.get_cert("cached.example.com")
        cert2 = mgr.get_cert("cached.example.com")
        assert cert1[0] == cert2[0]  # same cert PEM returned

    def test_different_hosts_different_certs(self):
        mgr = SSLContextManager()
        mgr.initialize()
        cert_a, _ = mgr.get_cert("alpha.example.com")
        cert_b, _ = mgr.get_cert("beta.example.com")
        assert cert_a != cert_b

    def test_ip_address_cert(self):
        mgr = SSLContextManager()
        mgr.initialize()
        cert_pem, _ = mgr.get_cert("192.168.1.1")
        assert b"BEGIN CERTIFICATE" in cert_pem

    def test_cache_size_tracking(self):
        mgr = SSLContextManager(cache_size=3)
        mgr.initialize()
        mgr.get_cert("a.com")
        mgr.get_cert("b.com")
        mgr.get_cert("c.com")
        assert mgr.cache_size == 3
        mgr.get_cert("d.com")  # evicts LRU
        assert mgr.cache_size == 3

    def test_clear_cache(self):
        mgr = SSLContextManager()
        mgr.initialize()
        mgr.get_cert("test.com")
        assert mgr.cache_size == 1
        mgr.clear_cache()
        assert mgr.cache_size == 0

    def test_persist_and_load_from_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.crt")
            key_path = os.path.join(tmpdir, "ca.key")

            mgr1 = SSLContextManager(ca_cert_path=cert_path, ca_key_path=key_path)
            mgr1.initialize()
            cert_pem_1 = mgr1.ca_cert_pem

            # Second manager loads from disk
            mgr2 = SSLContextManager(ca_cert_path=cert_path, ca_key_path=key_path)
            mgr2.initialize()
            assert mgr2.ca_cert_pem == cert_pem_1

    def test_export_ca_cert(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "exported.crt")
            mgr = SSLContextManager()
            mgr.initialize()
            mgr.export_ca_cert(out_path)
            with open(out_path, "rb") as fh:
                content = fh.read()
            assert b"BEGIN CERTIFICATE" in content

    def test_not_initialized_get_cert_raises(self):
        mgr = SSLContextManager()
        with pytest.raises(RuntimeError):
            mgr.get_cert("test.com")


# ===========================================================================
# TestProxyInterceptorState
# ===========================================================================


class TestProxyInterceptorState:
    """Test ProxyInterceptor state management without actually running mitmproxy."""

    def test_initial_state(self):
        proxy = ProxyInterceptor()
        assert proxy.running is False

    def test_get_stats_not_running(self):
        proxy = ProxyInterceptor()
        stats = proxy.get_stats()
        assert stats["running"] is False
        assert "port" in stats

    def test_add_rule(self):
        proxy = ProxyInterceptor()
        rule = InterceptRule(url_pattern=r"/login", tag="auth")
        proxy.add_rule(rule)
        assert len(proxy.rules) == 1

    def test_remove_rule(self):
        proxy = ProxyInterceptor()
        rule = InterceptRule(url_pattern=r"/login")
        proxy.add_rule(rule)
        proxy.remove_rule(0)
        assert len(proxy.rules) == 0

    def test_clear_rules(self):
        proxy = ProxyInterceptor()
        proxy.add_rule(InterceptRule(url_pattern=r"/a"))
        proxy.add_rule(InterceptRule(url_pattern=r"/b"))
        proxy.clear_rules()
        assert len(proxy.rules) == 0
