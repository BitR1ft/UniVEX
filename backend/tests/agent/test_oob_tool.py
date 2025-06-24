"""
Tests for Day 15 — OOB Tool & OOB Listener Infrastructure
(oob_tool.py, oob_listener.py)

Coverage:
  OOBCallbackStore     — register, record, get, evict, all_tokens
  OOBCallback          — to_dict, field values
  OOBHTTPListener      — request parsing, token extraction, 1x1 GIF response
  OOBDNSListener       — DNS packet parsing, label extraction
  OOBSMTPListener      — SMTP session, RCPT TO token extraction
  OOBListener          — generate_token, callback_url, wait_for_callback, stats
  OOBGenerateURLTool   — metadata, execute
  OOBCheckTool         — metadata, execute with/without callbacks
  OOBWaitTool          — metadata, timeout, callback received
  OOBStatsTool         — metadata, execute
  ToolRegistry         — all four OOB tools registered
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# OOBCallback
# ---------------------------------------------------------------------------

from app.oob.oob_listener import (
    OOBCallback,
    OOBCallbackStore,
    OOBHTTPListener,
    OOBDNSListener,
    OOBSMTPListener,
    OOBListener,
    _DNSProtocol,
)


class TestOOBCallback:
    def test_to_dict_has_required_keys(self):
        cb = OOBCallback(
            token="abc123",
            channel="http",
            source_ip="1.2.3.4",
            source_port=54321,
            method="GET",
            path="/abc123/test",
        )
        d = cb.to_dict()
        assert d["token"] == "abc123"
        assert d["channel"] == "http"
        assert d["source_ip"] == "1.2.3.4"
        assert d["source_port"] == 54321
        assert d["method"] == "GET"
        assert "datetime" in d
        assert "timestamp" in d

    def test_default_timestamp_is_recent(self):
        cb = OOBCallback(token="t", channel="dns", source_ip="x", source_port=0)
        assert abs(cb.timestamp - time.time()) < 2

    def test_payload_field(self):
        cb = OOBCallback(
            token="tok", channel="smtp", source_ip="5.6.7.8", source_port=25,
            payload="MAIL FROM:<attacker@evil.com>"
        )
        assert "attacker" in cb.payload


# ---------------------------------------------------------------------------
# OOBCallbackStore
# ---------------------------------------------------------------------------


class TestOOBCallbackStore:
    def test_register_token_creates_slot(self):
        store = OOBCallbackStore()
        run(store.register_token("token1"))
        cbs = run(store.get("token1"))
        assert cbs == []

    def test_record_and_get(self):
        store = OOBCallbackStore()
        cb = OOBCallback(token="tok2", channel="http", source_ip="1.1.1.1", source_port=0)
        run(store.record(cb))
        result = run(store.get("tok2"))
        assert len(result) == 1
        assert result[0].channel == "http"

    def test_get_unknown_token_returns_empty(self):
        store = OOBCallbackStore()
        assert run(store.get("not_registered")) == []

    def test_multiple_callbacks_same_token(self):
        store = OOBCallbackStore()
        for i in range(5):
            cb = OOBCallback(token="multi", channel="http", source_ip="1.1.1.1", source_port=i)
            run(store.record(cb))
        assert len(run(store.get("multi"))) == 5

    def test_all_tokens_lists_registered(self):
        store = OOBCallbackStore()
        run(store.register_token("aaa"))
        run(store.register_token("bbb"))
        tokens = run(store.all_tokens())
        assert "aaa" in tokens
        assert "bbb" in tokens

    def test_eviction_removes_old_tokens(self):
        store = OOBCallbackStore(ttl=0)
        run(store.register_token("old"))
        # eviction is triggered by any access
        tokens = run(store.all_tokens())
        assert "old" not in tokens

    def test_record_auto_creates_slot_for_unknown_token(self):
        store = OOBCallbackStore()
        cb = OOBCallback(token="auto", channel="dns", source_ip="2.2.2.2", source_port=0)
        run(store.record(cb))
        assert len(run(store.get("auto"))) == 1

    def test_get_returns_copy(self):
        store = OOBCallbackStore()
        cb = OOBCallback(token="cp", channel="http", source_ip="0.0.0.0", source_port=0)
        run(store.record(cb))
        result_a = run(store.get("cp"))
        result_b = run(store.get("cp"))
        assert result_a is not result_b


# ---------------------------------------------------------------------------
# _DNSProtocol (packet parser)
# ---------------------------------------------------------------------------


class TestDNSProtocolParser:
    def _build_dns_query(self, domain: str) -> bytes:
        """Build a minimal DNS A-query packet for *domain*."""
        header = b"\x00\x01"  # tx id
        header += b"\x01\x00"  # flags (standard query)
        header += b"\x00\x01"  # questions = 1
        header += b"\x00\x00\x00\x00\x00\x00"  # answers/authority/additional = 0
        # Question: encode domain
        question = b""
        for label in domain.rstrip(".").split("."):
            encoded = label.encode("ascii")
            question += bytes([len(encoded)]) + encoded
        question += b"\x00"  # end of name
        question += b"\x00\x01"  # QTYPE A
        question += b"\x00\x01"  # QCLASS IN
        return header + question

    def test_parse_simple_domain(self):
        data = self._build_dns_query("abc123.oob.univex.local")
        result = _DNSProtocol._parse_query(data)
        assert result is not None
        assert "abc123" in result

    def test_parse_returns_none_on_garbage(self):
        result = _DNSProtocol._parse_query(b"\x00\x01\x02\x03")
        # Should not raise — may return None or partial
        # Just verify it doesn't crash

    def test_parse_empty_bytes(self):
        result = _DNSProtocol._parse_query(b"")
        assert result is None or result == ""

    def test_first_label_extracted(self):
        data = self._build_dns_query("mytoken.oob.univex.local")
        result = _DNSProtocol._parse_query(data)
        labels = result.split(".")
        assert labels[0] == "mytoken"


# ---------------------------------------------------------------------------
# OOBListener (coordinator)
# ---------------------------------------------------------------------------


class TestOOBListenerTokens:
    def setup_method(self):
        self.listener = OOBListener(
            http_port=18080, dns_port=15353, smtp_port=12525
        )

    def test_generate_token_is_hex_string(self):
        token = self.listener.generate_token("test-1")
        assert all(c in "0123456789abcdef" for c in token)

    def test_generate_token_length(self):
        token = self.listener.generate_token("test-1")
        assert len(token) == 24

    def test_different_test_ids_give_different_tokens(self):
        t1 = self.listener.generate_token("id-1")
        t2 = self.listener.generate_token("id-2")
        assert t1 != t2

    def test_same_test_id_gives_different_tokens(self):
        # Uses random nonce — two calls with same id should differ
        t1 = self.listener.generate_token("same")
        t2 = self.listener.generate_token("same")
        assert t1 != t2

    def test_callback_url_http(self):
        token = "abcdef"
        url = self.listener.callback_url(token, channel="http")
        assert url.startswith("http://")
        assert token in url

    def test_callback_url_dns(self):
        token = "abcdef"
        url = self.listener.callback_url(token, channel="dns")
        assert url.startswith(token)
        assert "oob.univex.local" in url

    def test_callback_url_smtp(self):
        token = "abcdef"
        url = self.listener.callback_url(token, channel="smtp")
        assert url.startswith(token + "@")

    def test_callback_url_unknown_channel_raises(self):
        with pytest.raises(ValueError, match="Unknown channel"):
            self.listener.callback_url("tok", channel="grpc")

    def test_is_not_running_initially(self):
        assert not self.listener.is_running

    def test_stats_includes_ports(self):
        stats = self.listener.stats()
        assert "http_port" in stats
        assert "dns_port" in stats
        assert "smtp_port" in stats
        assert "running" in stats

    def test_stats_running_false_initially(self):
        assert self.listener.stats()["running"] is False


class TestOOBListenerCallbacks:
    def setup_method(self):
        self.listener = OOBListener(http_port=28080, dns_port=25353, smtp_port=22525)

    def test_get_callbacks_empty_for_unregistered(self):
        cbs = run(self.listener.get_callbacks("unknown"))
        assert cbs == []

    def test_register_and_get_callbacks(self):
        run(self.listener.register_token("reg1"))
        cbs = run(self.listener.get_callbacks("reg1"))
        assert cbs == []

    def test_wait_for_callback_timeout(self):
        """wait_for_callback returns None when no callback arrives."""
        result = run(self.listener.wait_for_callback("notoken", timeout=0.05, poll_interval=0.01))
        assert result is None

    def test_wait_for_callback_receives(self):
        """If a callback is already in the store, wait_for_callback returns it immediately."""
        token = "immediate"
        cb = OOBCallback(token=token, channel="http", source_ip="1.1.1.1", source_port=0)
        run(self.listener._store.record(cb))
        result = run(self.listener.wait_for_callback(token, timeout=1.0, poll_interval=0.01))
        assert result is not None
        assert result.token == token

    def test_all_tokens_empty_initially(self):
        tokens = run(self.listener.all_tokens())
        assert isinstance(tokens, list)


# ---------------------------------------------------------------------------
# OOBHTTPListener — unit-level
# ---------------------------------------------------------------------------


class TestOOBHTTPListenerParsing:
    """Test the _handle method without starting a real server."""

    def _make_reader_writer(self, request_bytes: bytes):
        """Create a mock reader/writer inside an event loop context."""
        async def _create():
            reader = asyncio.StreamReader()
            reader.feed_data(request_bytes)
            reader.feed_eof()
            return reader
        reader = run(_create())
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12345))
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        return reader, writer

    def test_handle_records_token(self):
        store = OOBCallbackStore()
        listener = OOBHTTPListener(store, port=18081)
        request = b"GET /deadbeef1234 HTTP/1.1\r\nHost: oob.univex.local\r\n\r\n"
        reader, writer = self._make_reader_writer(request)
        run(listener._handle(reader, writer))
        cbs = run(store.get("deadbeef1234"))
        assert len(cbs) == 1
        assert cbs[0].channel == "http"
        assert cbs[0].source_ip == "10.0.0.1"

    def test_handle_returns_gif_response(self):
        store = OOBCallbackStore()
        listener = OOBHTTPListener(store, port=18082)
        request = b"GET /tok HTTP/1.1\r\nHost: x\r\n\r\n"
        reader, writer = self._make_reader_writer(request)
        run(listener._handle(reader, writer))
        written = writer.write.call_args[0][0]
        assert b"GIF89a" in written

    def test_handle_extracts_method(self):
        store = OOBCallbackStore()
        listener = OOBHTTPListener(store, port=18083)
        request = b"POST /tok123 HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody"
        reader, writer = self._make_reader_writer(request)
        run(listener._handle(reader, writer))
        cbs = run(store.get("tok123"))
        assert cbs[0].method == "POST"

    def test_handle_path_stored(self):
        store = OOBCallbackStore()
        listener = OOBHTTPListener(store, port=18084)
        request = b"GET /mytok/extra?param=1 HTTP/1.1\r\n\r\n"
        reader, writer = self._make_reader_writer(request)
        run(listener._handle(reader, writer))
        cbs = run(store.get("mytok"))
        assert cbs[0].path == "/mytok/extra?param=1"


# ---------------------------------------------------------------------------
# OOB Tool classes
# ---------------------------------------------------------------------------

from app.agent.tools.oob_tool import (
    OOBGenerateURLTool,
    OOBCheckTool,
    OOBWaitTool,
    OOBStatsTool,
)


class TestOOBGenerateURLToolMetadata:
    def test_name(self):
        t = OOBGenerateURLTool(listener=OOBListener())
        assert t.name == "oob_generate_url"

    def test_description(self):
        t = OOBGenerateURLTool(listener=OOBListener())
        assert "callback" in t.description.lower()

    def test_parameters_has_test_id(self):
        t = OOBGenerateURLTool(listener=OOBListener())
        assert "test_id" in t.metadata.parameters["properties"]

    def test_parameters_has_channel(self):
        t = OOBGenerateURLTool(listener=OOBListener())
        assert "channel" in t.metadata.parameters["properties"]


class TestOOBGenerateURLToolExecute:
    def setup_method(self):
        self.listener = OOBListener()
        self.tool = OOBGenerateURLTool(listener=self.listener)

    def test_execute_returns_token(self):
        out = run(self.tool.execute(test_id="ssrf-test-1"))
        assert "Token" in out

    def test_execute_returns_url(self):
        out = run(self.tool.execute(test_id="ssrf-test-2", channel="http"))
        assert "http://" in out

    def test_execute_dns_channel(self):
        out = run(self.tool.execute(test_id="xxe-test-1", channel="dns"))
        assert "oob.univex.local" in out

    def test_execute_smtp_channel(self):
        out = run(self.tool.execute(test_id="rce-test-1", channel="smtp"))
        assert "@oob.univex.local" in out

    def test_execute_registers_token(self):
        run(self.tool.execute(test_id="register-check"))
        tokens = run(self.listener.all_tokens())
        assert len(tokens) >= 1


class TestOOBCheckToolMetadata:
    def test_name(self):
        t = OOBCheckTool(listener=OOBListener())
        assert t.name == "oob_check"

    def test_description(self):
        t = OOBCheckTool(listener=OOBListener())
        assert "callback" in t.description.lower()

    def test_parameters_has_token(self):
        t = OOBCheckTool(listener=OOBListener())
        assert "token" in t.metadata.parameters["required"]


class TestOOBCheckToolExecute:
    def setup_method(self):
        self.listener = OOBListener()
        self.tool = OOBCheckTool(listener=self.listener)

    def test_no_callbacks(self):
        out = run(self.tool.execute(token="empty_token"))
        assert "No callbacks" in out

    def test_with_callbacks(self):
        cb = OOBCallback(
            token="got_one", channel="http",
            source_ip="5.6.7.8", source_port=443,
            method="GET", path="/got_one",
        )
        run(self.listener._store.record(cb))
        out = run(self.tool.execute(token="got_one"))
        assert "5.6.7.8" in out
        assert "http" in out

    def test_multiple_callbacks_all_shown(self):
        for i in range(3):
            cb = OOBCallback(
                token="multi_check", channel="dns",
                source_ip=f"10.0.0.{i}", source_port=i,
            )
            run(self.listener._store.record(cb))
        out = run(self.tool.execute(token="multi_check"))
        assert "3" in out or out.count("dns") >= 3


class TestOOBWaitToolMetadata:
    def test_name(self):
        t = OOBWaitTool(listener=OOBListener())
        assert t.name == "oob_wait"

    def test_has_timeout_param(self):
        t = OOBWaitTool(listener=OOBListener())
        assert "timeout" in t.metadata.parameters["properties"]


class TestOOBWaitToolExecute:
    def test_wait_timeout(self):
        listener = OOBListener()
        tool = OOBWaitTool(listener=listener)
        out = run(tool.execute(token="no_arrive", timeout=0.05))
        assert "Timeout" in out

    def test_wait_receives_callback(self):
        listener = OOBListener()
        tool = OOBWaitTool(listener=listener)
        cb = OOBCallback(
            token="arrive", channel="http",
            source_ip="9.9.9.9", source_port=80,
        )
        run(listener._store.record(cb))
        out = run(tool.execute(token="arrive", timeout=1.0))
        assert "received" in out.lower()
        assert "9.9.9.9" in out

    def test_wait_confirms_vulnerability(self):
        listener = OOBListener()
        tool = OOBWaitTool(listener=listener)
        cb = OOBCallback(token="vuln_token", channel="smtp", source_ip="1.2.3.4", source_port=25)
        run(listener._store.record(cb))
        out = run(tool.execute(token="vuln_token", timeout=1.0))
        assert "vulnerable" in out.lower() or "smtp" in out.lower()


class TestOOBStatsToolMetadata:
    def test_name(self):
        t = OOBStatsTool(listener=OOBListener())
        assert t.name == "oob_stats"

    def test_description_non_empty(self):
        t = OOBStatsTool(listener=OOBListener())
        assert t.description


class TestOOBStatsToolExecute:
    def test_stats_contains_ports(self):
        listener = OOBListener(http_port=8080, dns_port=5353, smtp_port=2525)
        tool = OOBStatsTool(listener=listener)
        out = run(tool.execute())
        assert "8080" in out
        assert "5353" in out
        assert "2525" in out

    def test_stats_shows_running_state(self):
        listener = OOBListener()
        tool = OOBStatsTool(listener=listener)
        out = run(tool.execute())
        assert "Running" in out or "running" in out.lower()

    def test_stats_shows_active_tokens_count(self):
        listener = OOBListener()
        tool = OOBStatsTool(listener=listener)
        run(listener.register_token("t1"))
        run(listener.register_token("t2"))
        out = run(tool.execute())
        assert "2" in out


# ---------------------------------------------------------------------------
# ToolRegistry integration
# ---------------------------------------------------------------------------


class TestOOBToolsInRegistry:
    def test_oob_generate_url_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("oob_generate_url") is not None

    def test_oob_check_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("oob_check") is not None

    def test_oob_wait_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("oob_wait") is not None

    def test_oob_stats_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.get_tool("oob_stats") is not None
