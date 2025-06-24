"""
Tests for Day 8 — Proxy WebSocket Support & Browser Integration

Coverage (65 tests):
  TestWebSocketFrame            (10 tests) — dataclass, serialisation, raw_bytes
  TestWebSocketSession          (5 tests)  — dataclass, to_dict
  TestWebSocketInterceptorSessions (8 tests) — open/close/get/list sessions
  TestWebSocketInterceptorFrames   (15 tests) — capture, retrieve, filter, evict
  TestWebSocketInterceptorModify   (6 tests)  — modify, mutation callbacks
  TestWebSocketInterceptorReplay   (8 tests)  — replay single, replay session
  TestWebSocketInterceptorBulk     (4 tests)  — clear, clear_all, export, stats
  TestBrowserBridge                (9 tests)  — PAC, chrome_config, firefox, json_config

All tests use asyncio.run(); no live network calls.
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
from unittest.mock import MagicMock, patch

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


for _pkg in ["app", "app.proxy"]:
    _ensure_stub(_pkg)


def _load(rel: str, module_name: str):
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    path = os.path.join(repo, "backend", rel)
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


ws_mod = _load("app/proxy/websocket_interceptor.py", "app.proxy.websocket_interceptor")
bb_mod = _load("app/proxy/browser_bridge.py", "app.proxy.browser_bridge")

WebSocketFrame = ws_mod.WebSocketFrame
WebSocketSession = ws_mod.WebSocketSession
WebSocketInterceptor = ws_mod.WebSocketInterceptor
FrameDirection = ws_mod.FrameDirection
FrameType = ws_mod.FrameType
BrowserBridge = bb_mod.BrowserBridge


# ===========================================================================
# Helpers
# ===========================================================================


def make_frame(**kwargs) -> WebSocketFrame:
    defaults = dict(
        id="f1",
        session_id="s1",
        timestamp=1000.0,
        direction=FrameDirection.CLIENT_TO_SERVER,
        frame_type=FrameType.TEXT,
        payload="hello",
        is_binary=False,
        length=5,
    )
    defaults.update(kwargs)
    return WebSocketFrame(**defaults)


def make_interceptor() -> WebSocketInterceptor:
    return WebSocketInterceptor(max_frames_per_session=10)


# ===========================================================================
# TestWebSocketFrame
# ===========================================================================


class TestWebSocketFrame:
    def test_text_raw_bytes(self):
        f = make_frame(payload="hello")
        assert f.raw_bytes() == b"hello"

    def test_binary_raw_bytes(self):
        data = b"\x01\x02\x03"
        encoded = base64.b64encode(data).decode()
        f = make_frame(payload=encoded, is_binary=True)
        assert f.raw_bytes() == data

    def test_to_dict_keys(self):
        f = make_frame()
        d = f.to_dict()
        assert "id" in d
        assert "session_id" in d
        assert "direction" in d
        assert "frame_type" in d
        assert "payload" in d

    def test_to_dict_direction_is_string(self):
        f = make_frame(direction=FrameDirection.SERVER_TO_CLIENT)
        d = f.to_dict()
        assert d["direction"] == "server_to_client"

    def test_to_dict_frame_type_is_string(self):
        f = make_frame(frame_type=FrameType.BINARY)
        d = f.to_dict()
        assert d["frame_type"] == "binary"

    def test_from_dict_roundtrip(self):
        f = make_frame()
        d = f.to_dict()
        f2 = WebSocketFrame.from_dict(d)
        assert f2.id == f.id
        assert f2.payload == f.payload
        assert f2.direction == FrameDirection.CLIENT_TO_SERVER

    def test_modified_flag_default_false(self):
        f = make_frame()
        assert f.modified is False

    def test_length_field(self):
        f = make_frame(length=42)
        assert f.length == 42

    def test_notes_default_empty(self):
        f = make_frame()
        assert f.notes == ""

    def test_frame_type_close(self):
        f = make_frame(frame_type=FrameType.CLOSE)
        d = f.to_dict()
        assert d["frame_type"] == "close"


# ===========================================================================
# TestWebSocketSession
# ===========================================================================


class TestWebSocketSession:
    def test_basic_fields(self):
        s = WebSocketSession(id="s1", url="wss://example.com", started_at=1000.0)
        assert s.url == "wss://example.com"
        assert s.ended_at is None
        assert s.frame_count == 0

    def test_to_dict(self):
        s = WebSocketSession(id="s1", url="wss://example.com", started_at=1000.0)
        d = s.to_dict()
        assert d["id"] == "s1"
        assert d["url"] == "wss://example.com"

    def test_ended_at_none_by_default(self):
        s = WebSocketSession(id="x", url="wss://x.com", started_at=0.0)
        assert s.to_dict()["ended_at"] is None

    def test_extra_field_default_empty(self):
        s = WebSocketSession(id="x", url="wss://x.com", started_at=0.0)
        assert s.extra == {}

    def test_client_addr_default_empty(self):
        s = WebSocketSession(id="x", url="wss://x.com", started_at=0.0)
        assert s.client_addr == ""


# ===========================================================================
# TestWebSocketInterceptorSessions
# ===========================================================================


class TestWebSocketInterceptorSessions:
    def test_open_session_returns_session(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://example.com")
        assert s.url == "wss://example.com"
        assert s.id

    def test_open_session_stores_session(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://example.com")
        assert interceptor.get_session(s.id) is s

    def test_list_sessions_empty(self):
        interceptor = make_interceptor()
        assert interceptor.list_sessions() == []

    def test_list_sessions_after_open(self):
        interceptor = make_interceptor()
        interceptor.open_session("wss://a.com")
        interceptor.open_session("wss://b.com")
        assert len(interceptor.list_sessions()) == 2

    def test_close_session_sets_ended_at(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://example.com")
        assert s.ended_at is None
        interceptor.close_session(s.id)
        assert s.ended_at is not None

    def test_close_unknown_session_noop(self):
        interceptor = make_interceptor()
        interceptor.close_session("nonexistent")  # should not raise

    def test_get_unknown_session_returns_none(self):
        interceptor = make_interceptor()
        assert interceptor.get_session("nope") is None

    def test_client_addr_stored(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://example.com", client_addr="10.0.0.1:12345")
        assert s.client_addr == "10.0.0.1:12345"


# ===========================================================================
# TestWebSocketInterceptorFrames
# ===========================================================================


class TestWebSocketInterceptorFrames:
    def _make(self):
        interceptor = make_interceptor()
        session = interceptor.open_session("wss://example.com")
        return interceptor, session

    def test_capture_text_frame(self):
        interceptor, session = self._make()
        frame = interceptor.capture_frame(
            session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "hello"
        )
        assert frame is not None
        assert frame.payload == "hello"

    def test_capture_increments_session_frame_count(self):
        interceptor, session = self._make()
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "a")
        assert session.frame_count == 1

    def test_capture_returns_none_for_unknown_session(self):
        interceptor = make_interceptor()
        result = interceptor.capture_frame(
            "unknown", FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "x"
        )
        assert result is None

    def test_get_frame_by_id(self):
        interceptor, session = self._make()
        frame = interceptor.capture_frame(
            session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "test"
        )
        retrieved = interceptor.get_frame(frame.id)
        assert retrieved is frame

    def test_get_unknown_frame_returns_none(self):
        interceptor = make_interceptor()
        assert interceptor.get_frame("nope") is None

    def test_get_session_frames(self):
        interceptor, session = self._make()
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "a")
        interceptor.capture_frame(session.id, FrameDirection.SERVER_TO_CLIENT, FrameType.TEXT, "b")
        frames = interceptor.get_session_frames(session.id)
        assert len(frames) == 2

    def test_filter_by_direction(self):
        interceptor, session = self._make()
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "a")
        interceptor.capture_frame(session.id, FrameDirection.SERVER_TO_CLIENT, FrameType.TEXT, "b")
        frames = interceptor.get_session_frames(session.id, direction=FrameDirection.CLIENT_TO_SERVER)
        assert len(frames) == 1
        assert frames[0].payload == "a"

    def test_filter_by_frame_type(self):
        interceptor, session = self._make()
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "t")
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.BINARY, "b")
        frames = interceptor.get_session_frames(session.id, frame_type=FrameType.BINARY)
        assert len(frames) == 1

    def test_ring_buffer_evicts_oldest(self):
        interceptor = WebSocketInterceptor(max_frames_per_session=3)
        session = interceptor.open_session("wss://x.com")
        for i in range(5):
            interceptor.capture_frame(
                session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, str(i)
            )
        frames = interceptor.get_session_frames(session.id, limit=100)
        # Only 3 remain (latest 3: "2","3","4")
        assert len(frames) == 3
        payloads = {f.payload for f in frames}
        assert "4" in payloads

    def test_list_all_frames_order(self):
        interceptor, session = self._make()
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "first")
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "second")
        all_frames = interceptor.list_all_frames()
        # Newest first
        assert all_frames[0].payload == "second"

    def test_on_frame_callback(self):
        received = []
        interceptor = WebSocketInterceptor(on_frame=received.append)
        session = interceptor.open_session("wss://x.com")
        interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "cb")
        assert len(received) == 1
        assert received[0].payload == "cb"

    def test_binary_frame_length(self):
        interceptor, session = self._make()
        data = b"\x00\x01\x02\x03"
        encoded = base64.b64encode(data).decode()
        frame = interceptor.capture_frame(
            session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.BINARY, encoded, is_binary=True
        )
        assert frame.length == 4

    def test_frame_pagination_offset(self):
        interceptor, session = self._make()
        for i in range(5):
            interceptor.capture_frame(
                session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, str(i)
            )
        frames = interceptor.get_session_frames(session.id, limit=2, offset=2)
        assert len(frames) == 2


# ===========================================================================
# TestWebSocketInterceptorModify
# ===========================================================================


class TestWebSocketInterceptorModify:
    def test_modify_frame_payload(self):
        interceptor, session = make_interceptor(), make_interceptor().open_session("wss://x")
        interceptor2 = make_interceptor()
        s2 = interceptor2.open_session("wss://x.com")
        frame = interceptor2.capture_frame(s2.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "original")
        result = interceptor2.modify_frame(frame.id, "modified")
        assert result.payload == "modified"
        assert result.modified is True

    def test_modify_unknown_frame_returns_none(self):
        interceptor = make_interceptor()
        assert interceptor.modify_frame("nope", "x") is None

    def test_mutation_callback_applied(self):
        interceptor = make_interceptor()
        session = interceptor.open_session("wss://x.com")

        def mutation(frame):
            return frame.payload.upper()

        interceptor.add_mutation("uppercase", mutation)
        frame = interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "hello")
        assert frame.payload == "HELLO"
        assert frame.modified is True

    def test_mutation_returning_none_keeps_original(self):
        interceptor = make_interceptor()
        session = interceptor.open_session("wss://x.com")
        interceptor.add_mutation("noop", lambda f: None)
        frame = interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "keep")
        assert frame.payload == "keep"
        assert frame.modified is False

    def test_remove_mutation(self):
        interceptor = make_interceptor()
        interceptor.add_mutation("test_mut", lambda f: "X")
        assert interceptor.remove_mutation("test_mut") is True

    def test_clear_mutations(self):
        interceptor = make_interceptor()
        interceptor.add_mutation("a", lambda f: "A")
        interceptor.add_mutation("b", lambda f: "B")
        interceptor.clear_mutations()
        session = interceptor.open_session("wss://x.com")
        frame = interceptor.capture_frame(session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "orig")
        assert frame.modified is False


# ===========================================================================
# TestWebSocketInterceptorReplay
# ===========================================================================


class TestWebSocketInterceptorReplay:
    def _setup(self):
        interceptor = make_interceptor()
        session = interceptor.open_session("wss://x.com")
        frame = interceptor.capture_frame(
            session.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "payload"
        )
        return interceptor, session, frame

    def test_replay_dry_run_success(self):
        interceptor, session, frame = self._setup()
        result = asyncio.run(interceptor.replay_frame(frame.id))
        assert result["success"] is True
        assert result["dry_run"] is True

    def test_replay_with_new_payload(self):
        interceptor, session, frame = self._setup()
        result = asyncio.run(interceptor.replay_frame(frame.id, new_payload="new"))
        assert result["replayed_payload"] == "new"

    def test_replay_unknown_frame(self):
        interceptor = make_interceptor()
        result = asyncio.run(interceptor.replay_frame("nope"))
        assert result["success"] is False

    def test_replay_with_send_fn(self):
        sent = []

        async def send(data: bytes):
            sent.append(data)

        interceptor, session, frame = self._setup()
        result = asyncio.run(interceptor.replay_frame(frame.id, send_fn=send))
        assert result["success"] is True
        assert result["dry_run"] is False
        assert b"payload" in sent[0]

    def test_replay_session_returns_list(self):
        interceptor, session, frame = self._setup()
        results = asyncio.run(interceptor.replay_session(session.id))
        assert isinstance(results, list)
        assert len(results) == 1

    def test_replay_session_direction_filter(self):
        interceptor, session, frame = self._setup()
        interceptor.capture_frame(
            session.id, FrameDirection.SERVER_TO_CLIENT, FrameType.TEXT, "server"
        )
        results = asyncio.run(
            interceptor.replay_session(session.id, direction=FrameDirection.CLIENT_TO_SERVER)
        )
        assert len(results) == 1

    def test_replay_frame_metadata(self):
        interceptor, session, frame = self._setup()
        result = asyncio.run(interceptor.replay_frame(frame.id))
        assert result["frame_id"] == frame.id
        assert result["session_id"] == session.id

    def test_replay_send_fn_error(self):
        async def bad_send(data: bytes):
            raise ConnectionError("closed")

        interceptor, session, frame = self._setup()
        result = asyncio.run(interceptor.replay_frame(frame.id, send_fn=bad_send))
        assert result["success"] is False
        assert "closed" in result["error"]


# ===========================================================================
# TestWebSocketInterceptorBulk
# ===========================================================================


class TestWebSocketInterceptorBulk:
    def test_clear_session(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://x.com")
        interceptor.capture_frame(s.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "a")
        count = interceptor.clear_session(s.id)
        assert count == 1
        assert interceptor.get_session_frames(s.id) == []

    def test_clear_all(self):
        interceptor = make_interceptor()
        s1 = interceptor.open_session("wss://a.com")
        s2 = interceptor.open_session("wss://b.com")
        interceptor.capture_frame(s1.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "x")
        interceptor.capture_frame(s2.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "y")
        interceptor.clear_all()
        assert interceptor.list_sessions() == []
        assert interceptor.list_all_frames() == []

    def test_export_session_json(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://export.com")
        interceptor.capture_frame(s.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "data")
        exported = interceptor.export_session_json(s.id)
        parsed = json.loads(exported)
        assert parsed["session"]["url"] == "wss://export.com"
        assert len(parsed["frames"]) == 1

    def test_stats(self):
        interceptor = make_interceptor()
        s = interceptor.open_session("wss://x.com")
        interceptor.capture_frame(s.id, FrameDirection.CLIENT_TO_SERVER, FrameType.TEXT, "f")
        stats = interceptor.get_stats()
        assert stats["total_sessions"] == 1
        assert stats["active_sessions"] == 1
        assert stats["total_frames"] == 1


# ===========================================================================
# TestBrowserBridge
# ===========================================================================


class TestBrowserBridge:
    def _make(self) -> BrowserBridge:
        return BrowserBridge(proxy_host="127.0.0.1", proxy_port=8080)

    def test_pac_contains_proxy_host(self):
        bridge = self._make()
        pac = bridge.generate_pac()
        assert "127.0.0.1:8080" in pac

    def test_pac_contains_function(self):
        bridge = self._make()
        pac = bridge.generate_pac()
        assert "function FindProxyForURL" in pac

    def test_pac_bypass_includes_localhost(self):
        bridge = self._make()
        pac = bridge.generate_pac()
        assert "localhost" in pac

    def test_chrome_config_keys(self):
        bridge = self._make()
        config = bridge.chrome_config()
        assert "proxy_server" in config
        assert "flags" in config
        assert "launch_command" in config
        assert "pac_url" in config

    def test_chrome_config_proxy_server(self):
        bridge = self._make()
        assert bridge.chrome_config()["proxy_server"] == "127.0.0.1:8080"

    def test_firefox_user_js_contains_proxy_host(self):
        bridge = self._make()
        js = bridge.firefox_user_js()
        assert "127.0.0.1" in js
        assert "8080" in js

    def test_firefox_user_js_pref_format(self):
        bridge = self._make()
        js = bridge.firefox_user_js()
        assert 'user_pref("network.proxy.type", 1)' in js

    def test_json_config_keys(self):
        bridge = self._make()
        config = bridge.json_config()
        for key in ("http_proxy", "https_proxy", "no_proxy", "pac_url", "environment_variables"):
            assert key in config

    def test_add_remove_bypass(self):
        bridge = self._make()
        bridge.add_bypass("*.internal.corp")
        assert "*.internal.corp" in bridge.bypass_list
        removed = bridge.remove_bypass("*.internal.corp")
        assert removed is True
        assert "*.internal.corp" not in bridge.bypass_list
