"""
Comprehensive tests for Day 9: MockLLM, MockToolServer, MockMode
────────────────────────────────────────────────────────────────
Covers:
  - MockLLMProvider: sequential responses, keyword map, streaming, error injection
  - MockToolServer: default outputs, custom outputs, error tools, dynamic handlers
  - MockMode: activate/deactivate, context manager, summary, global singleton
  - Integration: full agent → LLM → tool pipeline simulation
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup — import mock modules DIRECTLY to bypass app.agent.__init__
# (which has heavy pydantic/langgraph deps not needed for mock tests)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]  # UniVex/
_BACKEND = _REPO_ROOT / "backend"
_MOCK_DIR = _BACKEND / "app" / "agent" / "mock"

for p in (str(_BACKEND),):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load_mock_module(name: str, path: Path) -> Any:
    """Load a mock module directly from its file without package init side-effects."""
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load mock modules directly, bypassing app.agent.__init__
_mock_llm_mod = _load_mock_module("_mock_llm", _MOCK_DIR / "mock_llm.py")
_mock_tools_mod = _load_mock_module("_mock_tools", _MOCK_DIR / "mock_tools.py")

MockLLMProvider = _mock_llm_mod.MockLLMProvider
MockLLMResponse = _mock_llm_mod.MockLLMResponse
MockLLMCall = _mock_llm_mod.MockLLMCall

MockToolServer = _mock_tools_mod.MockToolServer
MockToolResult = _mock_tools_mod.MockToolResult
MockToolCall = _mock_tools_mod.MockToolCall


# MockMode imports mock_llm and mock_tools — patch sys.modules before loading
sys.modules["app.agent.mock.mock_llm"] = _mock_llm_mod
sys.modules["app.agent.mock.mock_tools"] = _mock_tools_mod

_mock_mode_mod = _load_mock_module("_mock_mode", _MOCK_DIR / "mock_mode.py")
MockMode = _mock_mode_mod.MockMode
is_mock_mode = _mock_mode_mod.is_mock_mode
get_global_mock_mode = _mock_mode_mod.get_global_mock_mode
activate_global_mock_mode = _mock_mode_mod.activate_global_mock_mode
deactivate_global_mock_mode = _mock_mode_mod.deactivate_global_mock_mode
MOCK_MODE_ENV_VAR = _mock_mode_mod.MOCK_MODE_ENV_VAR


# ===========================================================================
# MockLLMProvider — basic responses
# ===========================================================================


class TestMockLLMProviderBasic:
    def test_default_response(self):
        mock = MockLLMProvider(default_response="Hello from mock")
        resp = asyncio.run(mock.chat(messages=[{"role": "user", "content": "Hi"}]))
        assert resp.content == "Hello from mock"

    def test_sequential_responses(self):
        mock = MockLLMProvider(responses=["First", "Second", "Third"])
        resp1 = asyncio.run(mock.chat(messages=[{"role": "user", "content": "q1"}]))
        resp2 = asyncio.run(mock.chat(messages=[{"role": "user", "content": "q2"}]))
        resp3 = asyncio.run(mock.chat(messages=[{"role": "user", "content": "q3"}]))
        assert resp1.content == "First"
        assert resp2.content == "Second"
        assert resp3.content == "Third"

    def test_fallback_to_default_after_responses_exhausted(self):
        mock = MockLLMProvider(responses=["Only one"], default_response="Default")
        asyncio.run(mock.chat(messages=[{"role": "user", "content": "q1"}]))
        resp = asyncio.run(mock.chat(messages=[{"role": "user", "content": "q2"}]))
        assert resp.content == "Default"

    def test_keyword_map_match(self):
        mock = MockLLMProvider(keyword_map={"port scan": "Found 3 open ports"})
        resp = asyncio.run(
            mock.chat(messages=[{"role": "user", "content": "Please do a port scan now"}])
        )
        assert resp.content == "Found 3 open ports"

    def test_keyword_map_no_match_returns_default(self):
        mock = MockLLMProvider(
            keyword_map={"port scan": "Found 3 open ports"},
            default_response="No match",
        )
        resp = asyncio.run(
            mock.chat(messages=[{"role": "user", "content": "unrelated question"}])
        )
        assert resp.content == "No match"

    def test_keyword_map_case_insensitive(self):
        mock = MockLLMProvider(keyword_map={"PORT SCAN": "Found ports"})
        resp = asyncio.run(
            mock.chat(messages=[{"role": "user", "content": "port scan target"}])
        )
        assert resp.content == "Found ports"

    def test_response_is_mock_llm_response(self):
        mock = MockLLMProvider()
        resp = asyncio.run(mock.chat(messages=[]))
        assert isinstance(resp, MockLLMResponse)

    def test_response_has_usage(self):
        mock = MockLLMProvider()
        resp = asyncio.run(mock.chat(messages=[]))
        assert "total_tokens" in resp.usage
        assert resp.usage["total_tokens"] > 0

    def test_custom_token_usage(self):
        usage = {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
        mock = MockLLMProvider(token_usage=usage)
        resp = asyncio.run(mock.chat(messages=[]))
        assert resp.usage["total_tokens"] == 30

    def test_response_provider_is_mock(self):
        mock = MockLLMProvider()
        resp = asyncio.run(mock.chat(messages=[]))
        assert resp.provider == "mock"

    def test_response_model_returned(self):
        mock = MockLLMProvider(model="test-gpt-4")
        resp = asyncio.run(mock.chat(messages=[], model="custom-model"))
        assert resp.model == "custom-model"

    def test_finish_reason(self):
        mock = MockLLMProvider()
        resp = asyncio.run(mock.chat(messages=[]))
        assert resp.finish_reason == "stop"


# ===========================================================================
# MockLLMProvider — call recording
# ===========================================================================


class TestMockLLMProviderCallRecording:
    def test_calls_recorded(self):
        mock = MockLLMProvider()
        asyncio.run(mock.chat(messages=[{"role": "user", "content": "test"}]))
        assert mock.call_count == 1

    def test_multiple_calls_recorded(self):
        mock = MockLLMProvider()
        for _ in range(5):
            asyncio.run(mock.chat(messages=[]))
        assert mock.call_count == 5

    def test_call_object_stored(self):
        mock = MockLLMProvider(responses=["Answer"])
        asyncio.run(mock.chat(messages=[{"role": "user", "content": "Hello"}]))
        assert len(mock.calls) == 1
        call = mock.calls[0]
        assert isinstance(call, MockLLMCall)
        assert call.call_id

    def test_assert_called_once_passes(self):
        mock = MockLLMProvider()
        asyncio.run(mock.chat(messages=[]))
        mock.assert_called_once()  # Should not raise

    def test_assert_called_once_fails(self):
        mock = MockLLMProvider()
        asyncio.run(mock.chat(messages=[]))
        asyncio.run(mock.chat(messages=[]))
        with pytest.raises(AssertionError):
            mock.assert_called_once()

    def test_assert_called_n_times(self):
        mock = MockLLMProvider()
        for _ in range(3):
            asyncio.run(mock.chat(messages=[]))
        mock.assert_called_n_times(3)

    def test_assert_last_message_contains(self):
        mock = MockLLMProvider()
        asyncio.run(mock.chat(messages=[{"role": "user", "content": "scan ports now"}]))
        mock.assert_last_message_contains("port")

    def test_assert_last_message_contains_fails(self):
        mock = MockLLMProvider()
        asyncio.run(mock.chat(messages=[{"role": "user", "content": "hello world"}]))
        with pytest.raises(AssertionError):
            mock.assert_last_message_contains("XYZZY_NOT_PRESENT")

    def test_reset_clears_calls(self):
        mock = MockLLMProvider()
        asyncio.run(mock.chat(messages=[]))
        asyncio.run(mock.chat(messages=[]))
        mock.reset()
        assert mock.call_count == 0
        assert mock.calls == []

    def test_reset_resets_index(self):
        mock = MockLLMProvider(responses=["First", "Second"])
        asyncio.run(mock.chat(messages=[]))  # uses "First"
        mock.reset()
        resp = asyncio.run(mock.chat(messages=[]))
        assert resp.content == "First"  # back to start


# ===========================================================================
# MockLLMProvider — error injection
# ===========================================================================


class TestMockLLMProviderErrors:
    def test_fail_after_n_calls(self):
        mock = MockLLMProvider(fail_after=2)
        asyncio.run(mock.chat(messages=[]))  # call 0 → ok
        asyncio.run(mock.chat(messages=[]))  # call 1 → ok
        with pytest.raises(RuntimeError):
            asyncio.run(mock.chat(messages=[]))  # call 2 → fail

    def test_custom_error_message(self):
        mock = MockLLMProvider(fail_after=0, error_message="API quota exceeded")
        with pytest.raises(RuntimeError, match="API quota exceeded"):
            asyncio.run(mock.chat(messages=[]))

    def test_fail_after_0_always_fails(self):
        mock = MockLLMProvider(fail_after=0)
        with pytest.raises(RuntimeError):
            asyncio.run(mock.chat(messages=[]))


# ===========================================================================
# MockLLMProvider — streaming
# ===========================================================================


class TestMockLLMProviderStreaming:
    def test_stream_yields_content(self):
        mock = MockLLMProvider(responses=["Hello world stream test"])

        async def collect():
            chunks = []
            async for chunk in mock.chat_stream(messages=[]):
                chunks.append(chunk)
            return "".join(chunks)

        result = asyncio.run(collect())
        assert result == "Hello world stream test"

    def test_stream_chunk_size(self):
        mock = MockLLMProvider(responses=["ABCDE"], stream_chunk_size=2)

        async def collect():
            chunks = []
            async for chunk in mock.chat_stream(messages=[]):
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(collect())
        assert chunks[0] == "AB"
        assert chunks[1] == "CD"
        assert chunks[2] == "E"

    def test_stream_records_call(self):
        mock = MockLLMProvider(responses=["streamed"])

        async def run():
            async for _ in mock.chat_stream(messages=[]):
                pass

        asyncio.run(run())
        assert mock.call_count == 1
        assert mock.calls[0].stream is True


# ===========================================================================
# MockLLMProvider — from_fixture
# ===========================================================================


class TestMockLLMProviderFixture:
    def test_from_fixture_yaml(self, tmp_path):
        fixture = tmp_path / "llm.yaml"
        fixture.write_text(
            yaml.dump(
                {
                    "responses": ["First", "Second"],
                    "keyword_map": {"scan": "Found vulnerabilities"},
                    "default_response": "Default answer",
                }
            )
        )
        mock = MockLLMProvider.from_fixture(str(fixture))
        resp = asyncio.run(mock.chat(messages=[]))
        assert resp.content == "First"

    def test_from_fixture_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            MockLLMProvider.from_fixture("/tmp/no_such_fixture_llm.yaml")


# ===========================================================================
# MockToolServer — basic functionality
# ===========================================================================


class TestMockToolServerBasic:
    def test_invoke_known_tool(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("naabu", {"host": "192.168.1.1"}))
        assert result.success is True
        assert "ports" in result.output

    def test_invoke_naabu_returns_ports(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("naabu", {}))
        assert isinstance(result.output["ports"], list)
        assert len(result.output["ports"]) > 0

    def test_invoke_curl_returns_status(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("curl", {}))
        assert result.output["status_code"] == 200

    def test_invoke_nuclei_returns_findings(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("nuclei", {}))
        assert "findings" in result.output

    def test_invoke_ffuf_fuzz_dirs(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("ffuf_fuzz_dirs", {}))
        assert "found" in result.output
        assert len(result.output["found"]) > 0

    def test_invoke_web_search(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("web_search", {"query": "test"}))
        assert "results" in result.output

    def test_invoke_unknown_tool_fails(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("nonexistent_tool", {}))
        assert result.success is False
        assert "Unknown tool" in (result.error or "")

    def test_invoke_returns_mock_tool_result(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("naabu", {}))
        assert isinstance(result, MockToolResult)

    def test_result_has_call_id(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("curl", {}))
        assert result.call_id

    def test_result_has_execution_time(self):
        server = MockToolServer()
        result = asyncio.run(server.invoke("curl", {}))
        assert result.execution_time_ms >= 0


# ===========================================================================
# MockToolServer — custom outputs and errors
# ===========================================================================


class TestMockToolServerCustom:
    def test_custom_tool_output(self):
        custom = {"naabu": {"ports": [{"port": 9999, "state": "open"}]}}
        server = MockToolServer(tool_outputs=custom)
        result = asyncio.run(server.invoke("naabu", {}))
        assert result.output["ports"][0]["port"] == 9999

    def test_fail_tool_configured(self):
        server = MockToolServer(fail_tools={"naabu": "connection refused"})
        result = asyncio.run(server.invoke("naabu", {}))
        assert result.success is False
        assert "connection refused" in (result.error or "")

    def test_register_tool_override(self):
        server = MockToolServer()
        server.register_tool("curl", {"status_code": 404})
        result = asyncio.run(server.invoke("curl", {}))
        assert result.output["status_code"] == 404

    def test_set_tool_error(self):
        server = MockToolServer()
        server.set_tool_error("naabu", "scan timed out")
        result = asyncio.run(server.invoke("naabu", {}))
        assert result.success is False
        assert "scan timed out" in (result.error or "")

    def test_dynamic_handler(self):
        def my_handler(args):
            return {"host": args.get("host", "unknown"), "ports": [80]}

        server = MockToolServer(dynamic_handlers={"naabu": my_handler})
        result = asyncio.run(server.invoke("naabu", {"host": "10.0.0.5"}))
        assert result.success is True
        assert result.output["host"] == "10.0.0.5"

    def test_dynamic_handler_exception(self):
        def bad_handler(args):
            raise ValueError("handler failed")

        server = MockToolServer(dynamic_handlers={"naabu": bad_handler})
        result = asyncio.run(server.invoke("naabu", {}))
        assert result.success is False
        assert "handler failed" in (result.error or "")

    def test_register_handler(self):
        server = MockToolServer()
        server.register_handler("new_tool", lambda args: {"custom": True})
        result = asyncio.run(server.invoke("new_tool", {}))
        assert result.success is True
        assert result.output["custom"] is True

    def test_list_tools_returns_all_registered(self):
        server = MockToolServer()
        tools = server.list_tools()
        assert "naabu" in tools
        assert "curl" in tools
        assert "nuclei" in tools


# ===========================================================================
# MockToolServer — call recording
# ===========================================================================


class TestMockToolServerCallRecording:
    def test_calls_recorded(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        assert server.call_count == 1

    def test_multiple_tools_recorded(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        asyncio.run(server.invoke("curl", {}))
        asyncio.run(server.invoke("nuclei", {}))
        assert server.call_count == 3

    def test_was_called(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        assert server.was_called("naabu") is True
        assert server.was_called("curl") is False

    def test_call_count_for(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        asyncio.run(server.invoke("naabu", {}))
        asyncio.run(server.invoke("curl", {}))
        assert server.call_count_for("naabu") == 2
        assert server.call_count_for("curl") == 1

    def test_last_call_for(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {"host": "10.0.0.1"}))
        asyncio.run(server.invoke("naabu", {"host": "10.0.0.2"}))
        last = server.last_call_for("naabu")
        assert last is not None
        assert last.arguments["host"] == "10.0.0.2"

    def test_assert_tool_called(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        server.assert_tool_called("naabu")  # Should not raise

    def test_assert_tool_called_fails(self):
        server = MockToolServer()
        with pytest.raises(AssertionError):
            server.assert_tool_called("naabu")

    def test_assert_tool_not_called(self):
        server = MockToolServer()
        server.assert_tool_not_called("naabu")  # Should not raise

    def test_assert_tool_not_called_fails(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        with pytest.raises(AssertionError):
            server.assert_tool_not_called("naabu")

    def test_reset_clears_calls(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {}))
        server.reset()
        assert server.call_count == 0

    def test_call_stores_arguments(self):
        server = MockToolServer()
        asyncio.run(server.invoke("naabu", {"host": "192.168.1.1", "ports": "80,443"}))
        call = server.last_call_for("naabu")
        assert call.arguments["host"] == "192.168.1.1"


# ===========================================================================
# MockToolServer — from_fixture
# ===========================================================================


class TestMockToolServerFixture:
    def test_from_fixture_yaml(self, tmp_path):
        fixture = tmp_path / "tools.yaml"
        fixture.write_text(
            yaml.dump(
                {
                    "tool_outputs": {
                        "naabu": {"ports": [{"port": 8080}]},
                    },
                    "fail_tools": {
                        "searchsploit": "binary not found",
                    },
                }
            )
        )
        server = MockToolServer.from_fixture(str(fixture))
        result = asyncio.run(server.invoke("naabu", {}))
        assert result.output["ports"][0]["port"] == 8080

        fail_result = asyncio.run(server.invoke("searchsploit", {}))
        assert fail_result.success is False

    def test_from_fixture_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            MockToolServer.from_fixture("/tmp/no_such_tool_fixture.yaml")


# ===========================================================================
# is_mock_mode
# ===========================================================================


class TestIsMockMode:
    def test_false_by_default(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        assert is_mock_mode() is False

    def test_true_when_set_to_true(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "true")
        assert is_mock_mode() is True

    def test_true_when_set_to_1(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "1")
        assert is_mock_mode() is True

    def test_true_when_set_to_yes(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "yes")
        assert is_mock_mode() is True

    def test_false_when_set_to_false(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "false")
        assert is_mock_mode() is False

    def test_false_when_set_to_empty(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "")
        assert is_mock_mode() is False

    def test_true_when_set_to_on(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "on")
        assert is_mock_mode() is True


# ===========================================================================
# MockMode
# ===========================================================================


class TestMockMode:
    def test_activate_sets_env_var(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mock_mode = MockMode()
        mock_mode.activate()
        try:
            assert os.environ.get(MOCK_MODE_ENV_VAR) == "true"
        finally:
            mock_mode.deactivate()

    def test_deactivate_removes_env_var(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mock_mode = MockMode()
        mock_mode.activate()
        mock_mode.deactivate()
        assert os.environ.get(MOCK_MODE_ENV_VAR) is None

    def test_deactivate_restores_original_value(self, monkeypatch):
        monkeypatch.setenv(MOCK_MODE_ENV_VAR, "original")
        mock_mode = MockMode()
        mock_mode.activate()
        mock_mode.deactivate()
        assert os.environ.get(MOCK_MODE_ENV_VAR) == "original"

    def test_is_active_property(self):
        mock_mode = MockMode()
        assert mock_mode.is_active is False
        mock_mode.activate()
        try:
            assert mock_mode.is_active is True
        finally:
            mock_mode.deactivate()
        assert mock_mode.is_active is False

    def test_context_manager_activates(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mock_mode = MockMode()
        with mock_mode:
            assert mock_mode.is_active is True
            assert os.environ.get(MOCK_MODE_ENV_VAR) == "true"
        assert mock_mode.is_active is False

    def test_llm_property_returns_mock_llm(self):
        mock_mode = MockMode()
        assert isinstance(mock_mode.llm, MockLLMProvider)

    def test_tools_property_returns_mock_server(self):
        mock_mode = MockMode()
        assert isinstance(mock_mode.tools, MockToolServer)

    def test_get_llm_provider_requires_active(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mock_mode = MockMode()
        with pytest.raises(RuntimeError):
            mock_mode.get_llm_provider()

    def test_get_llm_provider_when_active(self):
        mock_mode = MockMode()
        with mock_mode:
            provider = mock_mode.get_llm_provider()
            assert isinstance(provider, MockLLMProvider)

    def test_get_tool_server_when_active(self):
        mock_mode = MockMode()
        with mock_mode:
            server = mock_mode.get_tool_server()
            assert isinstance(server, MockToolServer)

    def test_summary_structure(self):
        mock_mode = MockMode()
        with mock_mode:
            asyncio.run(mock_mode.llm.chat(messages=[{"role": "user", "content": "test"}]))
            asyncio.run(mock_mode.tools.invoke("naabu", {}))
            summary = mock_mode.summary()
        assert summary["llm_calls"] == 1
        assert summary["tool_calls"] == 1
        assert "naabu" in summary["tools_invoked"]

    def test_reset_clears_histories(self):
        mock_mode = MockMode()
        with mock_mode:
            asyncio.run(mock_mode.llm.chat(messages=[]))
            asyncio.run(mock_mode.tools.invoke("naabu", {}))
            mock_mode.reset()
            assert mock_mode.llm.call_count == 0
            assert mock_mode.tools.call_count == 0

    def test_with_custom_responses(self):
        mock_mode = MockMode(llm_responses=["Custom response"])
        with mock_mode:
            resp = asyncio.run(mock_mode.llm.chat(messages=[]))
            assert resp.content == "Custom response"

    def test_with_custom_keyword_map(self):
        mock_mode = MockMode(llm_keyword_map={"naabu": "Port scan result"})
        with mock_mode:
            resp = asyncio.run(
                mock_mode.llm.chat(messages=[{"role": "user", "content": "run naabu scan"}])
            )
            assert resp.content == "Port scan result"

    def test_with_custom_tool_outputs(self):
        mock_mode = MockMode(tool_outputs={"naabu": {"ports": [{"port": 1337}]}})
        with mock_mode:
            result = asyncio.run(mock_mode.tools.invoke("naabu", {}))
            assert result.output["ports"][0]["port"] == 1337

    def test_double_activate_is_idempotent(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mock_mode = MockMode()
        mock_mode.activate()
        mock_mode.activate()  # Should not raise
        mock_mode.deactivate()

    def test_double_deactivate_is_safe(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mock_mode = MockMode()
        mock_mode.activate()
        mock_mode.deactivate()
        mock_mode.deactivate()  # Should not raise

    def test_activate_returns_self(self):
        mock_mode = MockMode()
        result = mock_mode.activate()
        try:
            assert result is mock_mode
        finally:
            mock_mode.deactivate()


# ===========================================================================
# MockMode — global singleton
# ===========================================================================


class TestGlobalMockMode:
    def teardown_method(self, method):
        """Ensure global mock mode is deactivated after each test."""
        deactivate_global_mock_mode()

    def test_activate_global_returns_mock_mode(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mm = activate_global_mock_mode()
        assert isinstance(mm, MockMode)
        assert mm.is_active

    def test_get_global_returns_active_instance(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mm = activate_global_mock_mode()
        retrieved = get_global_mock_mode()
        assert retrieved is mm

    def test_deactivate_global_clears_singleton(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        activate_global_mock_mode()
        deactivate_global_mock_mode()
        assert get_global_mock_mode() is None

    def test_get_global_returns_none_when_not_active(self):
        deactivate_global_mock_mode()
        assert get_global_mock_mode() is None

    def test_activate_global_twice_returns_same_instance(self, monkeypatch):
        monkeypatch.delenv(MOCK_MODE_ENV_VAR, raising=False)
        mm1 = activate_global_mock_mode()
        mm2 = activate_global_mock_mode()
        assert mm1 is mm2


# ===========================================================================
# Integration — full pipeline simulation
# ===========================================================================


class TestMockModeIntegration:
    """
    Integration tests that simulate the full agent → LLM → tool pipeline
    using mock mode, without any live network calls.
    """

    def test_pipeline_llm_then_tool(self):
        """Simulate: agent asks LLM, then invokes a tool based on response."""
        mock_mode = MockMode(
            llm_responses=["You should run a port scan on 192.168.1.1"],
            tool_outputs={"naabu": {"ports": [{"port": 22}, {"port": 80}]}},
        )
        with mock_mode:
            llm_resp = asyncio.run(
                mock_mode.llm.chat(
                    messages=[{"role": "user", "content": "What should I do first?"}]
                )
            )
            assert "port scan" in llm_resp.content.lower()

            tool_result = asyncio.run(
                mock_mode.tools.invoke("naabu", {"host": "192.168.1.1"})
            )
            assert tool_result.success is True
            assert len(tool_result.output["ports"]) == 2

        # Verify call records
        assert mock_mode.llm.call_count == 1
        assert mock_mode.tools.was_called("naabu")

    def test_multi_tool_pipeline(self):
        """Simulate: scan → probe → fuzz pipeline."""
        mock_mode = MockMode()
        with mock_mode:
            # Step 1: port scan
            naabu_r = asyncio.run(mock_mode.tools.invoke("naabu", {"host": "10.0.0.1"}))
            assert naabu_r.success

            # Step 2: HTTP probe
            curl_r = asyncio.run(mock_mode.tools.invoke("curl", {"url": "http://10.0.0.1"}))
            assert curl_r.output["status_code"] == 200

            # Step 3: directory fuzz
            ffuf_r = asyncio.run(
                mock_mode.tools.invoke("ffuf_fuzz_dirs", {"url": "http://10.0.0.1"})
            )
            assert len(ffuf_r.output["found"]) > 0

        summary = mock_mode.summary()
        assert summary["tool_calls"] == 3
        assert "naabu" in summary["tools_invoked"]
        assert "curl" in summary["tools_invoked"]

    def test_llm_keyword_routing(self):
        """Simulate agent using LLM to decide which tool to run."""
        mock_mode = MockMode(
            llm_keyword_map={
                "recon": "Start with port scanning using naabu",
                "exploit": "Attempt SQL injection using sqlmap patterns",
            }
        )
        with mock_mode:
            recon_resp = asyncio.run(
                mock_mode.llm.chat(
                    messages=[{"role": "user", "content": "perform recon on target"}]
                )
            )
            exploit_resp = asyncio.run(
                mock_mode.llm.chat(
                    messages=[{"role": "user", "content": "exploit the login form"}]
                )
            )

        assert "naabu" in recon_resp.content.lower()
        assert "sql" in exploit_resp.content.lower()

    def test_tool_error_handling_in_pipeline(self):
        """Simulate graceful handling of a failed tool in the pipeline."""
        mock_mode = MockMode(fail_tools={"naabu": "network unreachable"})
        with mock_mode:
            result = asyncio.run(mock_mode.tools.invoke("naabu", {"host": "10.0.0.1"}))
            assert result.success is False
            assert "network unreachable" in result.error

            # Fallback to alternative tool
            curl_result = asyncio.run(
                mock_mode.tools.invoke("curl", {"url": "http://10.0.0.1"})
            )
            assert curl_result.success is True

    def test_streaming_llm_in_pipeline(self):
        """Simulate streaming response being consumed by a pipeline step."""
        mock_mode = MockMode(
            llm_responses=["Port scan completed. Found ports 22, 80, 443."]
        )

        async def run_stream():
            chunks = []
            with mock_mode:
                mock_mode.activate()
                async for chunk in mock_mode.llm.chat_stream(messages=[]):
                    chunks.append(chunk)
            return "".join(chunks)

        result = asyncio.run(run_stream())
        assert "port scan" in result.lower()

    def test_mock_mode_summary_after_full_pipeline(self):
        """Summary should capture all interactions."""
        mock_mode = MockMode(
            llm_responses=["Run naabu then nuclei"],
        )
        with mock_mode:
            asyncio.run(mock_mode.llm.chat(messages=[{"role": "user", "content": "plan"}]))
            asyncio.run(mock_mode.tools.invoke("naabu", {}))
            asyncio.run(mock_mode.tools.invoke("nuclei", {}))
            summary = mock_mode.summary()

        assert summary["llm_calls"] == 1
        assert summary["tool_calls"] == 2
        assert set(summary["tools_invoked"]) == {"naabu", "nuclei"}
        assert len(summary["llm_call_details"]) == 1
        assert len(summary["tool_call_details"]) == 2
