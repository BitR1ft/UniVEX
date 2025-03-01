"""
MockToolServer — in-memory mock for all UniVex MCP tool servers
───────────────────────────────────────────────────────────────
Provides a drop-in replacement for MCP tool servers that:
  - Returns scripted tool results from fixture files or inline dicts
  - Records all tool invocations for assertion in tests
  - Supports simulated errors and latency
  - Enables full agent → tool → result pipeline testing without Docker
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import yaml


# ---------------------------------------------------------------------------
# Tool result model
# ---------------------------------------------------------------------------


@dataclass
class MockToolResult:
    """Result returned by a mock tool invocation."""

    tool_name: str
    success: bool
    output: Any
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class MockToolCall:
    """Record of a single tool invocation."""

    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    result: MockToolResult
    timestamp: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Built-in scripted outputs for common UniVex tools
# ---------------------------------------------------------------------------

_DEFAULT_TOOL_OUTPUTS: Dict[str, Any] = {
    "naabu": {
        "ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
        ],
        "host": "192.168.1.1",
        "scan_time_ms": 1200,
    },
    "curl": {
        "status_code": 200,
        "headers": {"Server": "nginx/1.24", "Content-Type": "text/html"},
        "body_snippet": "<!DOCTYPE html><html><head><title>Target</title>",
        "redirect_chain": [],
        "time_ms": 45,
    },
    "nuclei": {
        "findings": [
            {
                "template": "cve-2021-44228",
                "severity": "critical",
                "matched": "http://target.local/",
                "info": "Apache Log4Shell RCE",
            }
        ],
        "total_scanned": 150,
    },
    "ffuf_fuzz_dirs": {
        "found": [
            {"path": "/admin", "status": 200, "size": 4096},
            {"path": "/.git", "status": 403, "size": 0},
            {"path": "/backup", "status": 200, "size": 8192},
        ],
        "total_requests": 2000,
    },
    "ffuf_fuzz_files": {
        "found": [
            {"path": "/config.php.bak", "status": 200, "size": 512},
            {"path": "/.env", "status": 200, "size": 256},
        ],
        "total_requests": 1500,
    },
    "ffuf_fuzz_params": {
        "found": [
            {"parameter": "debug", "value": "true", "response_diff": True},
        ],
        "total_requests": 500,
    },
    "web_search": {
        "results": [
            {
                "title": "Target Corp - LinkedIn",
                "url": "https://linkedin.com/company/target",
                "snippet": "Technology company with 500+ employees",
            }
        ],
        "query_time_ms": 300,
    },
    "query_graph": {
        "nodes": [
            {"id": "host-1", "type": "host", "ip": "192.168.1.1", "ports": [22, 80, 443]},
        ],
        "edges": [],
        "total_nodes": 1,
    },
    "wpscan": {
        "version": "WordPress 6.4.2",
        "plugins": [
            {"name": "contact-form-7", "version": "5.8", "vulnerabilities": []},
            {
                "name": "wp-file-manager",
                "version": "6.0",
                "vulnerabilities": [{"cve": "CVE-2020-25213", "severity": "critical"}],
            },
        ],
        "themes": [{"name": "twentytwentyfour", "version": "1.0"}],
    },
    "snmp": {
        "community_strings": ["public", "private"],
        "oid_data": {
            "sysDescr": "Linux target 5.15.0 #1 SMP",
            "sysLocation": "Server Room",
        },
    },
    "ldap_enum": {
        "users": ["admin", "alice", "bob", "charlie"],
        "groups": ["Domain Admins", "Domain Users", "IT"],
        "domain": "corp.local",
        "dc": "dc.corp.local",
    },
    "enum4linux": {
        "shares": ["ADMIN$", "C$", "IPC$", "public"],
        "users": ["admin", "guest"],
        "domain": "WORKGROUP",
    },
    "kerberoute": {
        "kerberoastable_users": ["svc_sql", "svc_web"],
        "asrep_roastable": ["asrep_user"],
    },
    "searchsploit": {
        "exploits": [
            {
                "title": "Apache Log4j 2 - Remote Code Execution",
                "path": "exploits/java/remote/50592.py",
                "edb_id": 50592,
            }
        ]
    },
    "nikto_agent": {
        "findings": [
            {"id": "999103", "description": "Apache mod_negotiation enabled", "severity": "info"},
        ],
        "total_checks": 6700,
    },
    "anonymous_ftp": {
        "allowed": True,
        "files": ["/pub/readme.txt", "/pub/data.zip"],
    },
}


# ---------------------------------------------------------------------------
# MockToolServer
# ---------------------------------------------------------------------------


class MockToolServer:
    """
    In-memory mock for all UniVex MCP tool servers.

    Usage — basic::

        server = MockToolServer()
        result = await server.invoke("naabu", {"host": "192.168.1.1"})
        assert result.success is True
        assert result.output["ports"]

    Usage — custom response::

        server = MockToolServer(tool_outputs={"naabu": {"ports": [{"port": 8080}]}})
        result = await server.invoke("naabu", {"host": "10.0.0.1"})

    Usage — YAML fixture::

        server = MockToolServer.from_fixture("tests/fixtures/tool_outputs.yaml")

    Usage — error simulation::

        server = MockToolServer(fail_tools={"naabu": "connection refused"})
        result = await server.invoke("naabu", {})
        assert result.success is False
    """

    def __init__(
        self,
        tool_outputs: Optional[Dict[str, Any]] = None,
        fail_tools: Optional[Dict[str, str]] = None,
        simulate_latency_ms: int = 0,
        dynamic_handlers: Optional[Dict[str, Callable[..., Any]]] = None,
    ) -> None:
        # Merge defaults with any overrides
        self._tool_outputs: Dict[str, Any] = {
            **_DEFAULT_TOOL_OUTPUTS,
            **(tool_outputs or {}),
        }
        self._fail_tools: Dict[str, str] = fail_tools or {}
        self._simulate_latency_ms = simulate_latency_ms
        self._dynamic_handlers: Dict[str, Callable[..., Any]] = dynamic_handlers or {}
        self.calls: List[MockToolCall] = []

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_fixture(
        cls,
        fixture_path: Union[str, Path],
        **kwargs: Any,
    ) -> "MockToolServer":
        """
        Load tool outputs from a YAML fixture file.

        Fixture format::

            tool_outputs:
              naabu:
                ports:
                  - {port: 22, protocol: tcp, state: open, service: ssh}
              curl:
                status_code: 200
            fail_tools:
              searchsploit: "searchsploit binary not found"
        """
        path = Path(fixture_path)
        if not path.exists():
            raise FileNotFoundError(f"Tool fixture file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls(
            tool_outputs=data.get("tool_outputs", {}),
            fail_tools=data.get("fail_tools", {}),
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Core invoke
    # ------------------------------------------------------------------

    async def invoke(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> MockToolResult:
        """Invoke a mock tool and return its scripted result."""
        args = arguments or {}

        if self._simulate_latency_ms > 0:
            await asyncio.sleep(self._simulate_latency_ms / 1000)

        start = time.monotonic()

        # Dynamic handler takes priority
        if tool_name in self._dynamic_handlers:
            try:
                handler = self._dynamic_handlers[tool_name]
                output = handler(args)
                if asyncio.iscoroutine(output):
                    output = await output
                result = MockToolResult(
                    tool_name=tool_name,
                    success=True,
                    output=output,
                    execution_time_ms=(time.monotonic() - start) * 1000,
                )
            except Exception as exc:  # noqa: BLE001
                result = MockToolResult(
                    tool_name=tool_name,
                    success=False,
                    output=None,
                    error=str(exc),
                    execution_time_ms=(time.monotonic() - start) * 1000,
                )
        elif tool_name in self._fail_tools:
            result = MockToolResult(
                tool_name=tool_name,
                success=False,
                output=None,
                error=self._fail_tools[tool_name],
                execution_time_ms=(time.monotonic() - start) * 1000,
            )
        elif tool_name in self._tool_outputs:
            result = MockToolResult(
                tool_name=tool_name,
                success=True,
                output=self._tool_outputs[tool_name],
                execution_time_ms=(time.monotonic() - start) * 1000,
            )
        else:
            result = MockToolResult(
                tool_name=tool_name,
                success=False,
                output=None,
                error=f"Unknown tool: '{tool_name}' — not registered in MockToolServer",
                execution_time_ms=(time.monotonic() - start) * 1000,
            )

        call = MockToolCall(
            call_id=result.call_id,
            tool_name=tool_name,
            arguments=args,
            result=result,
        )
        self.calls.append(call)
        return result

    # ------------------------------------------------------------------
    # Registry-style helpers
    # ------------------------------------------------------------------

    def register_tool(self, tool_name: str, output: Any) -> None:
        """Register or override a tool's scripted output."""
        self._tool_outputs[tool_name] = output

    def register_handler(self, tool_name: str, handler: Callable[..., Any]) -> None:
        """Register a dynamic callable handler for a tool."""
        self._dynamic_handlers[tool_name] = handler

    def set_tool_error(self, tool_name: str, error_message: str) -> None:
        """Configure a tool to always fail with a given error."""
        self._fail_tools[tool_name] = error_message

    def list_tools(self) -> List[str]:
        """Return all registered tool names."""
        return sorted(
            set(self._tool_outputs.keys())
            | set(self._fail_tools.keys())
            | set(self._dynamic_handlers.keys())
        )

    # ------------------------------------------------------------------
    # Assertion helpers
    # ------------------------------------------------------------------

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def was_called(self, tool_name: str) -> bool:
        return any(c.tool_name == tool_name for c in self.calls)

    def call_count_for(self, tool_name: str) -> int:
        return sum(1 for c in self.calls if c.tool_name == tool_name)

    def last_call_for(self, tool_name: str) -> Optional[MockToolCall]:
        for call in reversed(self.calls):
            if call.tool_name == tool_name:
                return call
        return None

    def assert_tool_called(self, tool_name: str) -> None:
        assert self.was_called(tool_name), (
            f"Expected tool '{tool_name}' to be called, "
            f"but only these tools were called: {[c.tool_name for c in self.calls]}"
        )

    def assert_tool_not_called(self, tool_name: str) -> None:
        assert not self.was_called(tool_name), (
            f"Expected tool '{tool_name}' NOT to be called, but it was."
        )

    def reset(self) -> None:
        """Clear call history."""
        self.calls.clear()
