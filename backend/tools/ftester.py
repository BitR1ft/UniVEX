#!/usr/bin/env python3
"""
ftester — UniVex Function Debug CLI

Usage:
  ftester invoke <agent> <function> [--input <json>]   Call an agent method
  ftester trace <agent> <function> [--input <json>]    Trace execution with timing
  ftester replay <trace_id>                             Replay a captured trace
  ftester list-agents                                   List agents and callable methods
  ftester inspect <agent>                               Show agent configuration

Enables debugging agent functions in isolation without a live LLM or tool server.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_COLOURS: Dict[str, str] = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def colored(text: str, colour: str) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    code = _COLOURS.get(colour, "")
    return f"{code}{text}{_COLOURS['reset']}" if code else text


def ok(msg: str) -> str:
    return colored(f"✓ {msg}", "green")


def fail(msg: str) -> str:
    return colored(f"✗ {msg}", "red")


def warn(msg: str) -> str:
    return colored(f"⚠ {msg}", "yellow")


def info(msg: str) -> str:
    return colored(f"→ {msg}", "cyan")


def header(msg: str) -> str:
    return colored(msg, "bold")


def dim(msg: str) -> str:
    return colored(msg, "dim")


# ---------------------------------------------------------------------------
# Agent registry — all 13 UniVex agent roles
# ---------------------------------------------------------------------------

AGENT_MODULE_MAP: Dict[str, str] = {
    "recon": "app.agent.agents.recon_agent:ReconAgent",
    "exploit": "app.agent.agents.exploit_agent:ExploitAgent",
    "report": "app.agent.agents.report_agent:ReportAgent",
    "web": "app.agent.agents.web_agent:WebAgent",
    "adviser": "app.agent.agents.adviser_agent:AdviserAgent",
    "coder": "app.agent.agents.coder_agent:CoderAgent",
    "enricher": "app.agent.agents.enricher_agent:EnricherAgent",
    "generator": "app.agent.agents.generator_agent:GeneratorAgent",
    "installer": "app.agent.agents.installer_agent:InstallerAgent",
    "refiner": "app.agent.agents.refiner_agent:RefinerAgent",
    "reflector": "app.agent.agents.reflector_agent:ReflectorAgent",
    "simple_json": "app.agent.agents.simple_json_agent:SimpleJSONAgent",
    "orchestrator": "app.agent.orchestrator:OrchestratorAgent",
}


# ---------------------------------------------------------------------------
# Trace models
# ---------------------------------------------------------------------------


@dataclass
class TraceSpan:
    """A single timing span within a function trace."""

    name: str
    start_ms: float
    end_ms: float
    depth: int = 0

    @property
    def duration_ms(self) -> float:
        return self.end_ms - self.start_ms


@dataclass
class FunctionTrace:
    """Complete trace of a single function invocation."""

    trace_id: str
    agent_role: str
    function_name: str
    input_data: Any
    output_data: Any
    total_duration_ms: float
    spans: List[TraceSpan] = field(default_factory=list)
    error: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    mock_mode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Trace store (in-memory with optional file persistence)
# ---------------------------------------------------------------------------

_TRACE_STORE_DIR = Path(os.environ.get("FTESTER_TRACE_DIR", "/tmp/ftester_traces"))


class TraceStore:
    """Simple file-backed store for captured traces."""

    def __init__(self, store_dir: Optional[Path] = None) -> None:
        self._dir = store_dir or _TRACE_STORE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, trace: FunctionTrace) -> str:
        path = self._dir / f"{trace.trace_id}.json"
        path.write_text(json.dumps(trace.to_dict(), indent=2, default=str))
        return str(path)

    def load(self, trace_id: str) -> Optional[FunctionTrace]:
        path = self._dir / f"{trace_id}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return FunctionTrace(
            trace_id=data["trace_id"],
            agent_role=data["agent_role"],
            function_name=data["function_name"],
            input_data=data["input_data"],
            output_data=data["output_data"],
            total_duration_ms=data["total_duration_ms"],
            spans=[TraceSpan(**s) for s in data.get("spans", [])],
            error=data.get("error"),
            timestamp=data.get("timestamp", ""),
            mock_mode=data.get("mock_mode", False),
        )

    def list_traces(self) -> List[str]:
        return [p.stem for p in sorted(self._dir.glob("*.json"), reverse=True)]


# ---------------------------------------------------------------------------
# AgentLoader
# ---------------------------------------------------------------------------


class AgentLoader:
    """Dynamically load UniVex agent classes from their module paths."""

    def __init__(self, module_map: Optional[Dict[str, str]] = None) -> None:
        self._map = module_map or AGENT_MODULE_MAP
        self._cache: Dict[str, Any] = {}

    def load_class(self, agent_role: str) -> Optional[Any]:
        """Return the agent class for the given role, or None if unavailable."""
        if agent_role in self._cache:
            return self._cache[agent_role]
        module_path = self._map.get(agent_role)
        if not module_path:
            return None
        module_str, class_name = module_path.rsplit(":", 1)
        try:
            import importlib  # noqa: PLC0415
            mod = importlib.import_module(module_str)
            cls = getattr(mod, class_name)
            self._cache[agent_role] = cls
            return cls
        except Exception:  # noqa: BLE001
            return None

    def get_public_methods(self, agent_role: str) -> List[Dict[str, Any]]:
        """Return all callable public methods for an agent class."""
        cls = self.load_class(agent_role)
        if cls is None:
            return []
        methods = []
        for name, obj in inspect.getmembers(cls, predicate=inspect.isfunction):
            if name.startswith("_"):
                continue
            sig = inspect.signature(obj)
            params = [
                {
                    "name": p,
                    "kind": str(v.kind.name),
                    "has_default": v.default is not inspect.Parameter.empty,
                }
                for p, v in sig.parameters.items()
                if p not in ("self", "cls")
            ]
            methods.append(
                {
                    "name": name,
                    "params": params,
                    "is_coroutine": asyncio.iscoroutinefunction(obj),
                    "doc": (inspect.getdoc(obj) or "").split("\n")[0],
                }
            )
        return methods

    def get_agent_info(self, agent_role: str) -> Dict[str, Any]:
        """Return configuration info for an agent class."""
        cls = self.load_class(agent_role)
        if cls is None:
            return {"error": f"Cannot load agent '{agent_role}'"}
        return {
            "role": agent_role,
            "class": cls.__name__,
            "module": cls.__module__,
            "agent_name": getattr(cls, "AGENT_NAME", agent_role),
            "preferred_tools": getattr(cls, "PREFERRED_TOOLS", []),
            "docstring": (inspect.getdoc(cls) or "").split("\n")[0],
            "method_count": len(self.get_public_methods(agent_role)),
        }


# ---------------------------------------------------------------------------
# FunctionInvoker
# ---------------------------------------------------------------------------


class FunctionInvoker:
    """Invoke individual agent functions in isolation with tracing."""

    def __init__(
        self,
        loader: Optional[AgentLoader] = None,
        trace_store: Optional[TraceStore] = None,
        use_mock_mode: bool = False,
    ) -> None:
        self._loader = loader or AgentLoader()
        self._store = trace_store or TraceStore()
        self._use_mock_mode = use_mock_mode

    def _activate_mock_mode(self) -> Any:
        """Activate mock mode if requested."""
        if not self._use_mock_mode:
            return None
        try:
            from app.agent.mock.mock_mode import MockMode  # noqa: PLC0415
            mock = MockMode()
            mock.activate()
            return mock
        except ImportError:
            return None

    def _deactivate_mock_mode(self, mock: Any) -> None:
        if mock is not None:
            try:
                mock.deactivate()
            except Exception:  # noqa: BLE001
                pass

    async def invoke(
        self,
        agent_role: str,
        function_name: str,
        input_data: Any = None,
        trace: bool = False,
    ) -> FunctionTrace:
        """Invoke an agent function and return a FunctionTrace."""
        trace_id = str(uuid.uuid4())
        spans: List[TraceSpan] = []
        mock = self._activate_mock_mode()

        start_total = time.monotonic() * 1000
        output_data: Any = None
        error: Optional[str] = None

        try:
            cls = self._loader.load_class(agent_role)
            if cls is None:
                raise ValueError(f"Cannot load agent '{agent_role}'")

            # Build agent instance (no args constructor with defaults)
            s0 = time.monotonic() * 1000
            try:
                agent_instance = cls()
            except TypeError:
                # Some agents need args — build a minimal instance
                agent_instance = object.__new__(cls)
            spans.append(TraceSpan("instantiate", s0, time.monotonic() * 1000))

            method = getattr(agent_instance, function_name, None)
            if method is None or not callable(method):
                raise ValueError(
                    f"Method '{function_name}' not found on agent '{agent_role}'"
                )

            s1 = time.monotonic() * 1000
            if asyncio.iscoroutinefunction(method):
                if input_data is not None:
                    output_data = await method(input_data)
                else:
                    output_data = await method()
            else:
                if input_data is not None:
                    output_data = method(input_data)
                else:
                    output_data = method()
            spans.append(TraceSpan("execute", s1, time.monotonic() * 1000))

        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
        finally:
            self._deactivate_mock_mode(mock)

        total_ms = (time.monotonic() * 1000) - start_total
        ft = FunctionTrace(
            trace_id=trace_id,
            agent_role=agent_role,
            function_name=function_name,
            input_data=input_data,
            output_data=output_data,
            total_duration_ms=round(total_ms, 2),
            spans=spans,
            error=error,
            mock_mode=self._use_mock_mode,
        )

        if trace:
            self._store.save(ft)

        return ft


# ---------------------------------------------------------------------------
# FtesterCLI
# ---------------------------------------------------------------------------


class FtesterCLI:
    """
    Command implementations for the ``ftester`` CLI tool.
    """

    def __init__(
        self,
        loader: Optional[AgentLoader] = None,
        invoker: Optional[FunctionInvoker] = None,
        trace_store: Optional[TraceStore] = None,
    ) -> None:
        self._loader = loader or AgentLoader()
        self._store = trace_store or TraceStore()
        self._invoker = invoker or FunctionInvoker(
            loader=self._loader, trace_store=self._store
        )

    # ------------------------------------------------------------------
    # list-agents
    # ------------------------------------------------------------------

    def cmd_list_agents(self, args: argparse.Namespace) -> int:
        """List all agents and their callable public methods."""
        print(header("\n  UniVex Agent Function Directory"))
        print("  " + "─" * 60)

        for role in sorted(AGENT_MODULE_MAP.keys()):
            methods = self._loader.get_public_methods(role)
            if not methods:
                print(
                    f"  {colored(role, 'cyan'):<30} "
                    f"{dim('(unavailable in current environment)')}"
                )
                continue
            print(f"\n  {colored(role, 'cyan')} — {len(methods)} public methods")
            for m in methods:
                coro_tag = colored("async", "yellow") if m["is_coroutine"] else "sync"
                print(
                    f"    {m['name']:<35} [{coro_tag}] {dim(m['doc'][:50])}"
                )

        print()
        return 0

    # ------------------------------------------------------------------
    # inspect
    # ------------------------------------------------------------------

    def cmd_inspect(self, args: argparse.Namespace) -> int:
        """Show agent configuration, model, tools, and system prompt."""
        agent_role = args.agent
        if agent_role not in AGENT_MODULE_MAP:
            print(fail(f"Unknown agent: '{agent_role}'"))
            print(info(f"Available: {', '.join(sorted(AGENT_MODULE_MAP.keys()))}"))
            return 1

        agent_info = self._loader.get_agent_info(agent_role)
        if "error" in agent_info:
            print(warn(f"  {agent_info['error']}"))
            print(dim("  (Agent class is not importable in the current environment)"))
            # Still show what we know from the registry
            print(header(f"\n  Agent: {agent_role}"))
            print(f"  Module path: {AGENT_MODULE_MAP.get(agent_role, 'unknown')}")
            return 0

        methods = self._loader.get_public_methods(agent_role)

        print(header(f"\n  ── Agent: {agent_info['class']} ──"))
        print(f"  Role:         {agent_info['agent_name']}")
        print(f"  Module:       {agent_info['module']}")
        print(f"  Description:  {agent_info['docstring']}")
        print(f"  Methods:      {agent_info['method_count']} public callable")

        tools = agent_info.get("preferred_tools", [])
        if tools:
            print(f"\n  Preferred tools ({len(tools)}):")
            for t in tools:
                print(f"    • {t}")

        if methods:
            print(f"\n  Public methods:")
            for m in methods:
                coro_tag = "async" if m["is_coroutine"] else "sync"
                params = ", ".join(
                    p["name"]
                    + ("=..." if p["has_default"] else "")
                    for p in m["params"]
                )
                print(f"    {m['name']}({params})  [{coro_tag}]")
                if m["doc"]:
                    print(f"      {dim(m['doc'])}")

        print()
        return 0

    # ------------------------------------------------------------------
    # invoke
    # ------------------------------------------------------------------

    def cmd_invoke(self, args: argparse.Namespace) -> int:
        """Call a specific agent method with custom input."""
        agent_role = args.agent
        function_name = args.function
        input_json = getattr(args, "input", None)
        use_mock = getattr(args, "mock", False)

        if agent_role not in AGENT_MODULE_MAP:
            print(fail(f"Unknown agent: '{agent_role}'"))
            return 1

        input_data: Any = None
        if input_json:
            try:
                input_data = json.loads(input_json)
            except json.JSONDecodeError as exc:
                print(fail(f"Invalid JSON input: {exc}"))
                return 1

        print(header(f"\n  Invoking {agent_role}.{function_name}()"))
        if input_data is not None:
            print(info(f"  Input: {json.dumps(input_data)[:200]}"))
        if use_mock:
            print(info("  Mock mode: enabled"))
        print()

        invoker = FunctionInvoker(loader=self._loader, use_mock_mode=use_mock)
        ft = asyncio.run(
            invoker.invoke(agent_role, function_name, input_data=input_data)
        )

        if ft.error:
            print(fail(f"  Error: {ft.error}"))
            return 1

        print(ok(f"  Completed in {ft.total_duration_ms:.1f}ms"))
        print()
        print(header("  Output:"))
        try:
            output_str = json.dumps(ft.output_data, indent=2, default=str)
        except Exception:  # noqa: BLE001
            output_str = str(ft.output_data)
        print(output_str)
        print()
        return 0

    # ------------------------------------------------------------------
    # trace
    # ------------------------------------------------------------------

    def cmd_trace(self, args: argparse.Namespace) -> int:
        """Trace full execution path with timing breakdown."""
        agent_role = args.agent
        function_name = args.function
        input_json = getattr(args, "input", None)
        use_mock = getattr(args, "mock", False)

        if agent_role not in AGENT_MODULE_MAP:
            print(fail(f"Unknown agent: '{agent_role}'"))
            return 1

        input_data: Any = None
        if input_json:
            try:
                input_data = json.loads(input_json)
            except json.JSONDecodeError as exc:
                print(fail(f"Invalid JSON input: {exc}"))
                return 1

        print(header(f"\n  Tracing {agent_role}.{function_name}()"))
        print()

        invoker = FunctionInvoker(
            loader=self._loader,
            trace_store=self._store,
            use_mock_mode=use_mock,
        )
        ft = asyncio.run(
            invoker.invoke(agent_role, function_name, input_data=input_data, trace=True)
        )

        # Print flame-graph-style trace
        print(header(f"  Trace ID: {ft.trace_id}"))
        print(f"  Agent:    {ft.agent_role}")
        print(f"  Function: {ft.function_name}")
        print(f"  Total:    {ft.total_duration_ms:.2f}ms")
        print()
        print(header("  Execution Spans:"))
        for span in ft.spans:
            bar_width = min(60, max(1, int(span.duration_ms / ft.total_duration_ms * 50)))
            bar = colored("█" * bar_width, "cyan")
            indent = "  " * (span.depth + 1)
            print(
                f"  {indent}{span.name:<20} {bar} {span.duration_ms:>8.2f}ms"
            )

        if ft.error:
            print()
            print(fail(f"  Error: {ft.error}"))
            return 1

        print()
        trace_path = self._store.save(ft)
        print(ok(f"  Trace saved: {trace_path}"))
        print(dim(f"  Replay with: ftester replay {ft.trace_id}"))
        print()
        return 0

    # ------------------------------------------------------------------
    # replay
    # ------------------------------------------------------------------

    def cmd_replay(self, args: argparse.Namespace) -> int:
        """Replay a captured trace for debugging."""
        trace_id = args.trace_id
        trace = self._store.load(trace_id)
        if trace is None:
            print(fail(f"Trace not found: {trace_id}"))
            available = self._store.list_traces()[:10]
            if available:
                print(info(f"Available traces: {', '.join(available)}"))
            return 1

        print(header(f"\n  Replaying Trace: {trace_id}"))
        print(f"  Agent:    {trace.agent_role}")
        print(f"  Function: {trace.function_name}")
        print(f"  Recorded: {trace.timestamp}")
        print(f"  Duration: {trace.total_duration_ms:.2f}ms")
        print(f"  MockMode: {trace.mock_mode}")
        print()

        if trace.error:
            print(colored(f"  Original error: {trace.error}", "red"))
        else:
            print(ok("  Original execution succeeded"))

        print(header("\n  Input:"))
        try:
            print("  " + json.dumps(trace.input_data, indent=2, default=str))
        except Exception:  # noqa: BLE001
            print(f"  {trace.input_data}")

        print(header("\n  Output:"))
        try:
            print("  " + json.dumps(trace.output_data, indent=2, default=str))
        except Exception:  # noqa: BLE001
            print(f"  {trace.output_data}")

        if trace.spans:
            print(header("\n  Execution Spans:"))
            for span in trace.spans:
                print(f"    {span.name:<20} {span.duration_ms:>8.2f}ms")

        print()

        # Re-run the function with the same input
        print(header("  Re-executing..."))
        use_mock = trace.mock_mode
        invoker = FunctionInvoker(
            loader=self._loader, trace_store=self._store, use_mock_mode=use_mock
        )
        new_ft = asyncio.run(
            invoker.invoke(
                trace.agent_role,
                trace.function_name,
                input_data=trace.input_data,
            )
        )

        if new_ft.error:
            print(fail(f"  Re-execution failed: {new_ft.error}"))
        else:
            print(ok(f"  Re-execution succeeded in {new_ft.total_duration_ms:.2f}ms"))

        print()
        return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ftester",
        description="UniVex Function Debug CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # invoke
    invoke_p = sub.add_parser("invoke", help="Call a specific agent method")
    invoke_p.add_argument("agent", help="Agent role name")
    invoke_p.add_argument("function", help="Function/method name")
    invoke_p.add_argument("--input", metavar="JSON", help="JSON-encoded input argument")
    invoke_p.add_argument("--mock", action="store_true", help="Use mock LLM and tools")

    # trace
    trace_p = sub.add_parser("trace", help="Trace execution with timing breakdown")
    trace_p.add_argument("agent", help="Agent role name")
    trace_p.add_argument("function", help="Function/method name")
    trace_p.add_argument("--input", metavar="JSON", help="JSON-encoded input argument")
    trace_p.add_argument("--mock", action="store_true", help="Use mock LLM and tools")

    # replay
    replay_p = sub.add_parser("replay", help="Replay a captured trace")
    replay_p.add_argument("trace_id", help="Trace ID to replay")

    # list-agents
    sub.add_parser("list-agents", help="List all agents and their callable methods")

    # inspect
    inspect_p = sub.add_parser("inspect", help="Show agent configuration and methods")
    inspect_p.add_argument("agent", help="Agent role name")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    cli = FtesterCLI()

    command_map = {
        "invoke": cli.cmd_invoke,
        "trace": cli.cmd_trace,
        "replay": cli.cmd_replay,
        "list-agents": cli.cmd_list_agents,
        "inspect": cli.cmd_inspect,
    }
    handler = command_map.get(args.command)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
