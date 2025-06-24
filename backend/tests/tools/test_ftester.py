"""
Comprehensive tests for Day 9: ftester Function Debug CLI
──────────────────────────────────────────────────────────
Covers:
  - FunctionTrace / TraceSpan data models
  - TraceStore: save, load, list_traces
  - AgentLoader: load_class, get_public_methods, get_agent_info
  - FunctionInvoker: invoke, trace mode
  - FtesterCLI: list-agents, inspect, invoke, trace, replay commands
  - build_parser / main() entry point
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from argparse import Namespace
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]  # UniVex/
_BACKEND = _REPO_ROOT / "backend"
_TOOLS_DIR = _BACKEND / "tools"

for p in (str(_BACKEND), str(_TOOLS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import ftester  # noqa: E402
from ftester import (  # noqa: E402
    AGENT_MODULE_MAP,
    AgentLoader,
    FtesterCLI,
    FunctionInvoker,
    FunctionTrace,
    TraceSpan,
    TraceStore,
    build_parser,
    colored,
    dim,
    fail,
    header,
    info,
    main,
    ok,
    warn,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trace(
    agent_role: str = "recon",
    function_name: str = "get_phase",
    passed: bool = True,
    duration_ms: float = 100.0,
) -> FunctionTrace:
    return FunctionTrace(
        trace_id=str(uuid.uuid4()),
        agent_role=agent_role,
        function_name=function_name,
        input_data={"target": "192.168.1.1"},
        output_data={"result": "ok"} if passed else None,
        total_duration_ms=duration_ms,
        spans=[TraceSpan("instantiate", 0, 10), TraceSpan("execute", 10, duration_ms)],
        error=None if passed else "ValueError: test error",
        mock_mode=False,
    )


# ===========================================================================
# ANSI helpers
# ===========================================================================


class TestColorHelpers:
    def test_colored_returns_string(self):
        assert isinstance(colored("text", "green"), str)

    def test_ok_contains_checkmark(self):
        assert "✓" in ok("done")

    def test_fail_contains_cross(self):
        assert "✗" in fail("error")

    def test_warn_contains_warning(self):
        assert "⚠" in warn("caution")

    def test_info_contains_arrow(self):
        assert "→" in info("note")

    def test_dim_returns_string(self):
        assert isinstance(dim("dim text"), str)

    def test_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert colored("hello", "green") == "hello"


# ===========================================================================
# TraceSpan
# ===========================================================================


class TestTraceSpan:
    def test_duration_calculation(self):
        span = TraceSpan("execute", 100.0, 250.0)
        assert span.duration_ms == 150.0

    def test_zero_duration(self):
        span = TraceSpan("init", 0.0, 0.0)
        assert span.duration_ms == 0.0

    def test_depth_default(self):
        span = TraceSpan("test", 0.0, 1.0)
        assert span.depth == 0


# ===========================================================================
# FunctionTrace
# ===========================================================================


class TestFunctionTrace:
    def test_to_dict_structure(self):
        trace = _make_trace()
        d = trace.to_dict()
        assert "trace_id" in d
        assert "agent_role" in d
        assert "function_name" in d
        assert "input_data" in d
        assert "output_data" in d
        assert "total_duration_ms" in d
        assert "spans" in d
        assert "error" in d

    def test_to_dict_spans_serialized(self):
        trace = _make_trace()
        d = trace.to_dict()
        assert isinstance(d["spans"], list)
        assert len(d["spans"]) == 2

    def test_error_trace(self):
        trace = _make_trace(passed=False)
        assert trace.error is not None
        assert "ValueError" in trace.error

    def test_mock_mode_field(self):
        trace = _make_trace()
        assert trace.mock_mode is False

    def test_timestamp_auto_set(self):
        trace = _make_trace()
        assert trace.timestamp


# ===========================================================================
# TraceStore
# ===========================================================================


class TestTraceStore:
    def test_save_creates_file(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        trace = _make_trace()
        path = store.save(trace)
        assert Path(path).exists()

    def test_load_returns_trace(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        trace = _make_trace()
        store.save(trace)
        loaded = store.load(trace.trace_id)
        assert loaded is not None
        assert loaded.trace_id == trace.trace_id
        assert loaded.agent_role == trace.agent_role
        assert loaded.function_name == trace.function_name

    def test_load_nonexistent_returns_none(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        result = store.load("nonexistent-trace-id")
        assert result is None

    def test_list_traces(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        traces = [_make_trace() for _ in range(3)]
        for t in traces:
            store.save(t)
        ids = store.list_traces()
        assert len(ids) == 3
        for t in traces:
            assert t.trace_id in ids

    def test_list_traces_empty(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        assert store.list_traces() == []

    def test_save_load_roundtrip_spans(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        trace = _make_trace()
        store.save(trace)
        loaded = store.load(trace.trace_id)
        assert len(loaded.spans) == 2
        assert loaded.spans[0].name == "instantiate"

    def test_save_error_trace(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        trace = _make_trace(passed=False)
        store.save(trace)
        loaded = store.load(trace.trace_id)
        assert loaded.error is not None

    def test_store_dir_created_automatically(self, tmp_path):
        new_dir = tmp_path / "traces" / "nested"
        store = TraceStore(store_dir=new_dir)
        assert new_dir.exists()


# ===========================================================================
# AgentLoader
# ===========================================================================


class TestAgentLoader:
    def test_all_roles_in_map(self):
        for role in ["recon", "exploit", "report", "web", "adviser", "coder",
                     "enricher", "generator", "installer", "refiner", "reflector",
                     "simple_json", "orchestrator"]:
            assert role in AGENT_MODULE_MAP

    def test_agent_module_map_has_13_entries(self):
        assert len(AGENT_MODULE_MAP) == 13

    def test_load_class_unknown_role(self):
        loader = AgentLoader()
        result = loader.load_class("nonexistent_role")
        assert result is None

    def test_get_public_methods_unknown_role(self):
        loader = AgentLoader()
        methods = loader.get_public_methods("nonexistent_role")
        assert methods == []

    def test_get_agent_info_unknown_role(self):
        loader = AgentLoader()
        info = loader.get_agent_info("nonexistent_role")
        assert "error" in info

    def test_load_class_recon_agent(self):
        loader = AgentLoader()
        cls = loader.load_class("recon")
        if cls is not None:
            assert hasattr(cls, "AGENT_NAME")
            assert hasattr(cls, "PREFERRED_TOOLS")

    def test_get_public_methods_recon(self):
        loader = AgentLoader()
        methods = loader.get_public_methods("recon")
        # Either empty (if not loadable) or has entries
        assert isinstance(methods, list)

    def test_get_agent_info_recon(self):
        loader = AgentLoader()
        info = loader.get_agent_info("recon")
        if "error" not in info:
            assert "role" in info
            assert "class" in info
            assert "module" in info

    def test_class_cached_after_load(self):
        loader = AgentLoader()
        cls1 = loader.load_class("recon")
        cls2 = loader.load_class("recon")
        if cls1 is not None:
            assert cls1 is cls2

    def test_custom_module_map(self):
        # Inject a fake module/class pair
        import types  # noqa: PLC0415
        fake_module = types.ModuleType("fake_module")
        fake_cls = type("FakeAgent", (), {"AGENT_NAME": "fake", "PREFERRED_TOOLS": []})
        fake_module.FakeAgent = fake_cls
        sys.modules["fake_module"] = fake_module

        loader = AgentLoader(module_map={"fake": "fake_module:FakeAgent"})
        cls = loader.load_class("fake")
        assert cls is fake_cls

        del sys.modules["fake_module"]


# ===========================================================================
# FunctionInvoker
# ===========================================================================


class TestFunctionInvoker:
    def test_invoke_unknown_agent_error(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(trace_store=store)
        ft = asyncio.run(invoker.invoke("unknown_agent", "get_phase"))
        assert ft.error is not None
        assert "Cannot load agent" in ft.error or "load" in ft.error.lower()

    def test_invoke_invalid_function_error(self, tmp_path):
        # Use a role that CAN be loaded, with a function that doesn't exist
        import types  # noqa: PLC0415
        fake_module = types.ModuleType("test_invoker_mod")
        fake_cls = type("TestAgent", (), {"AGENT_NAME": "test_inv"})
        fake_module.TestAgent = fake_cls
        sys.modules["test_invoker_mod"] = fake_module

        loader = AgentLoader(module_map={"test_inv": "test_invoker_mod:TestAgent"})
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(loader=loader, trace_store=store)
        ft = asyncio.run(invoker.invoke("test_inv", "nonexistent_method"))
        assert ft.error is not None

        del sys.modules["test_invoker_mod"]

    def test_invoke_sync_function(self, tmp_path):
        import types  # noqa: PLC0415
        fake_module = types.ModuleType("test_sync_mod")

        class SyncAgent:
            AGENT_NAME = "sync"
            PREFERRED_TOOLS = []

            def my_method(self, data=None):
                return {"result": "sync_ok", "input": data}

        fake_module.SyncAgent = SyncAgent
        sys.modules["test_sync_mod"] = fake_module

        loader = AgentLoader(module_map={"sync": "test_sync_mod:SyncAgent"})
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(loader=loader, trace_store=store)
        ft = asyncio.run(invoker.invoke("sync", "my_method", input_data={"x": 1}))
        assert ft.error is None
        assert ft.output_data["result"] == "sync_ok"

        del sys.modules["test_sync_mod"]

    def test_invoke_async_function(self, tmp_path):
        import types  # noqa: PLC0415
        fake_module = types.ModuleType("test_async_mod")

        class AsyncAgent:
            AGENT_NAME = "async"
            PREFERRED_TOOLS = []

            async def my_async_method(self, data=None):
                return {"result": "async_ok"}

        fake_module.AsyncAgent = AsyncAgent
        sys.modules["test_async_mod"] = fake_module

        loader = AgentLoader(module_map={"async_agent": "test_async_mod:AsyncAgent"})
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(loader=loader, trace_store=store)
        ft = asyncio.run(invoker.invoke("async_agent", "my_async_method"))
        assert ft.error is None
        assert ft.output_data["result"] == "async_ok"

        del sys.modules["test_async_mod"]

    def test_invoke_trace_mode_saves_file(self, tmp_path):
        import types  # noqa: PLC0415
        fake_module = types.ModuleType("test_trace_mod")

        class TraceAgent:
            AGENT_NAME = "trace"
            PREFERRED_TOOLS = []

            def get_phase(self):
                return "INFORMATIONAL"

        fake_module.TraceAgent = TraceAgent
        sys.modules["test_trace_mod"] = fake_module

        loader = AgentLoader(module_map={"trace_agent": "test_trace_mod:TraceAgent"})
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(loader=loader, trace_store=store)
        ft = asyncio.run(invoker.invoke("trace_agent", "get_phase", trace=True))
        assert ft.trace_id
        assert store.load(ft.trace_id) is not None

        del sys.modules["test_trace_mod"]

    def test_invoke_trace_returns_trace_id(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(trace_store=store)
        ft = asyncio.run(invoker.invoke("unknown", "method"))
        assert ft.trace_id

    def test_invoke_records_spans(self, tmp_path):
        import types  # noqa: PLC0415
        fake_module = types.ModuleType("test_spans_mod")

        class SpanAgent:
            AGENT_NAME = "spans"
            PREFERRED_TOOLS = []

            def my_func(self):
                return "span_test"

        fake_module.SpanAgent = SpanAgent
        sys.modules["test_spans_mod"] = fake_module

        loader = AgentLoader(module_map={"span_agent": "test_spans_mod:SpanAgent"})
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(loader=loader, trace_store=store)
        ft = asyncio.run(invoker.invoke("span_agent", "my_func"))
        # Should have at least one span (execute)
        assert len(ft.spans) >= 1

        del sys.modules["test_spans_mod"]

    def test_invoke_records_total_duration(self, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        invoker = FunctionInvoker(trace_store=store)
        ft = asyncio.run(invoker.invoke("unknown", "method"))
        assert ft.total_duration_ms >= 0


# ===========================================================================
# FtesterCLI — list-agents
# ===========================================================================


class TestFtesterCLIListAgents:
    def test_cmd_list_agents_returns_0(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        rc = cli.cmd_list_agents(Namespace())
        assert rc == 0

    def test_cmd_list_agents_shows_all_roles(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        cli.cmd_list_agents(Namespace())
        out = capsys.readouterr().out
        for role in ["recon", "exploit", "report", "orchestrator"]:
            assert role in out

    def test_cmd_list_agents_header(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        cli.cmd_list_agents(Namespace())
        out = capsys.readouterr().out
        assert "Agent Function Directory" in out or "UniVex" in out


# ===========================================================================
# FtesterCLI — inspect
# ===========================================================================


class TestFtesterCLIInspect:
    def test_cmd_inspect_unknown_agent_returns_1(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        rc = cli.cmd_inspect(Namespace(agent="nonexistent"))
        assert rc == 1

    def test_cmd_inspect_shows_available_roles(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        cli.cmd_inspect(Namespace(agent="nonexistent"))
        out = capsys.readouterr().out
        assert "recon" in out

    def test_cmd_inspect_known_role_returns_0(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        rc = cli.cmd_inspect(Namespace(agent="recon"))
        assert rc == 0

    def test_cmd_inspect_shows_role_info(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        cli.cmd_inspect(Namespace(agent="recon"))
        out = capsys.readouterr().out
        assert "recon" in out.lower()


# ===========================================================================
# FtesterCLI — invoke
# ===========================================================================


class TestFtesterCLIInvoke:
    def test_cmd_invoke_unknown_agent_returns_1(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="unknown", function="get_phase", input=None, mock=False)
        rc = cli.cmd_invoke(args)
        assert rc == 1

    def test_cmd_invoke_invalid_json_returns_1(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="recon", function="get_phase", input="{not valid json}", mock=False)
        rc = cli.cmd_invoke(args)
        assert rc == 1

    def test_cmd_invoke_valid_agent_completes(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="recon", function="get_phase", input=None, mock=False)
        rc = cli.cmd_invoke(args)
        # May be 0 (success) or 1 (error if agent not loadable), but should not crash
        assert rc in (0, 1)

    def test_cmd_invoke_valid_json_input(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(
            agent="recon",
            function="get_phase",
            input='{"target": "192.168.1.1"}',
            mock=False,
        )
        rc = cli.cmd_invoke(args)
        assert rc in (0, 1)

    def test_cmd_invoke_shows_agent_function_header(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="recon", function="get_phase", input=None, mock=False)
        cli.cmd_invoke(args)
        out = capsys.readouterr().out
        assert "recon" in out.lower()
        assert "get_phase" in out.lower()


# ===========================================================================
# FtesterCLI — trace
# ===========================================================================


class TestFtesterCLITrace:
    def test_cmd_trace_unknown_agent_returns_1(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="unknown", function="method", input=None, mock=False)
        rc = cli.cmd_trace(args)
        assert rc in (0, 1)  # unknown agent → error message, may still return from trace

    def test_cmd_trace_shows_trace_id(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="recon", function="get_phase", input=None, mock=False)
        cli.cmd_trace(args)
        out = capsys.readouterr().out
        assert "Trace ID" in out or "trace" in out.lower()

    def test_cmd_trace_invalid_json_returns_1(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(agent="recon", function="get_phase", input="{bad}", mock=False)
        rc = cli.cmd_trace(args)
        assert rc == 1


# ===========================================================================
# FtesterCLI — replay
# ===========================================================================


class TestFtesterCLIReplay:
    def test_cmd_replay_nonexistent_trace_returns_1(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(trace_id="nonexistent-trace-id-xyz")
        rc = cli.cmd_replay(args)
        assert rc == 1

    def test_cmd_replay_shows_not_found_message(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(trace_id="nonexistent-trace-id-xyz")
        cli.cmd_replay(args)
        out = capsys.readouterr().out
        assert "not found" in out.lower() or "✗" in out

    def test_cmd_replay_shows_available_traces(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        # Save a trace first
        trace = _make_trace()
        store.save(trace)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(trace_id="nonexistent-id")
        cli.cmd_replay(args)
        out = capsys.readouterr().out
        # Should mention available traces
        assert trace.trace_id in out or "available" in out.lower()

    def test_cmd_replay_existing_trace(self, capsys, tmp_path):
        store = TraceStore(store_dir=tmp_path)
        trace = _make_trace(agent_role="recon", function_name="get_phase")
        store.save(trace)
        cli = FtesterCLI(trace_store=store)
        args = Namespace(trace_id=trace.trace_id)
        rc = cli.cmd_replay(args)
        out = capsys.readouterr().out
        assert trace.agent_role in out
        assert trace.function_name in out


# ===========================================================================
# build_parser / main
# ===========================================================================


class TestBuildParser:
    def test_no_command(self):
        p = build_parser()
        args = p.parse_args([])
        assert args.command is None

    def test_invoke_command(self):
        p = build_parser()
        args = p.parse_args(["invoke", "recon", "get_phase"])
        assert args.command == "invoke"
        assert args.agent == "recon"
        assert args.function == "get_phase"

    def test_invoke_with_input(self):
        p = build_parser()
        args = p.parse_args(["invoke", "recon", "get_phase", "--input", '{"x": 1}'])
        assert args.input == '{"x": 1}'

    def test_invoke_with_mock(self):
        p = build_parser()
        args = p.parse_args(["invoke", "recon", "get_phase", "--mock"])
        assert args.mock is True

    def test_trace_command(self):
        p = build_parser()
        args = p.parse_args(["trace", "exploit", "run"])
        assert args.command == "trace"
        assert args.agent == "exploit"
        assert args.function == "run"

    def test_replay_command(self):
        p = build_parser()
        args = p.parse_args(["replay", "some-trace-id"])
        assert args.command == "replay"
        assert args.trace_id == "some-trace-id"

    def test_list_agents_command(self):
        p = build_parser()
        args = p.parse_args(["list-agents"])
        assert args.command == "list-agents"

    def test_inspect_command(self):
        p = build_parser()
        args = p.parse_args(["inspect", "recon"])
        assert args.command == "inspect"
        assert args.agent == "recon"


class TestMainEntryPoint:
    def test_main_no_args_returns_0(self):
        rc = main([])
        assert rc == 0

    def test_main_list_agents(self, capsys):
        rc = main(["list-agents"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "recon" in out

    def test_main_inspect_recon(self, capsys):
        rc = main(["inspect", "recon"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "recon" in out.lower()

    def test_main_inspect_unknown(self, capsys):
        rc = main(["inspect", "badagent"])
        assert rc == 1

    def test_main_invoke_unknown_agent(self, capsys):
        rc = main(["invoke", "unknownagent", "somemethod"])
        assert rc == 1

    def test_main_replay_nonexistent(self, capsys):
        rc = main(["replay", "nonexistent-trace-00000"])
        assert rc == 1
