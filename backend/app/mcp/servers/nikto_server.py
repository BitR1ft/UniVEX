"""
Nikto MCP Server

Wraps the `nikto` web server scanner to expose three tools:

  web_scan     — standard web server vulnerability scan
  plugin_scan  — run specific Nikto plugin categories
  tuning_scan  — tuning-specific scan (e.g. injection, files, authentication)

Port: 8007

Safety controls
---------------
* Targets are validated; RFC-1918 addresses are blocked unless allow_internal=True.
* All results are normalised into the canonical Vulnerability schema.
* Nikto output is written to a temp file in JSON format to enable reliable parsing.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import tempfile
from typing import Any, Dict, List, Optional

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

NIKTO_BINARY = os.environ.get("NIKTO_PATH", "nikto")

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def _is_internal(host: str) -> bool:
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _validate_host(host: str, allow_internal: bool) -> None:
    if not allow_internal and _is_internal(host):
        raise ValueError(
            f"Target host '{host}' is internal/localhost. "
            "Pass allow_internal=true for lab environments."
        )


async def _run_nikto(args: List[str], timeout: int = 300) -> str:
    """Run nikto with the given arguments and return stdout+stderr."""
    cmd = [NIKTO_BINARY] + args
    logger.debug("nikto command: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace") + stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        raise TimeoutError(f"nikto timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError(
            "nikto binary not found. "
            "Set NIKTO_PATH or install nikto in PATH."
        )


def _parse_nikto_json(json_path: str) -> List[Dict[str, Any]]:
    """Parse nikto JSON output file into a list of vulnerability dicts."""
    vulns: List[Dict[str, Any]] = []
    try:
        with open(json_path) as fh:
            data = json.load(fh)
        # nikto JSON has a 'vulnerabilities' list under 'host'
        hosts = data.get("host", [data]) if isinstance(data, dict) else data
        for host_entry in (hosts if isinstance(hosts, list) else [hosts]):
            for item in host_entry.get("vulnerabilities", []):
                vulns.append(
                    {
                        "id": item.get("id", ""),
                        "title": item.get("msg", ""),
                        "url": item.get("uri", ""),
                        "method": item.get("method", "GET"),
                        "reference": item.get("references", {}).get("url", ""),
                        "source": "nikto",
                    }
                )
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as exc:
        logger.debug("Could not parse nikto JSON: %s", exc)
    return vulns


def _parse_nikto_text(output: str) -> List[Dict[str, Any]]:
    """Fallback: parse nikto text output when JSON file is unavailable."""
    vulns: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("+ ") and len(line) > 3:
            vulns.append(
                {
                    "id": "",
                    "title": line[2:],
                    "url": "",
                    "method": "",
                    "reference": "",
                    "source": "nikto",
                }
            )
    return vulns


class NiktoServer(MCPServer):
    """
    MCP Server wrapping the Nikto web server scanner.

    Provides:
    - web_scan    : full web server vulnerability scan
    - plugin_scan : targeted plugin-based scan
    - tuning_scan : tuning-category scan
    """

    def __init__(self):
        super().__init__(
            name="nikto",
            description="Web server vulnerability scanning using Nikto",
            port=8007,
        )

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="web_scan",
                description=(
                    "Scan a web server for known vulnerabilities, misconfigurations, "
                    "and interesting files using Nikto. Returns a list of findings."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "Target hostname or IP (e.g. '10.10.10.1')",
                        },
                        "port": {
                            "type": "integer",
                            "description": "Target port (default: 80)",
                            "default": 80,
                        },
                        "ssl": {
                            "type": "boolean",
                            "description": "Use SSL/TLS (default: false)",
                            "default": False,
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Scan timeout in seconds (default: 180)",
                            "default": 180,
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow RFC-1918 targets (HTB labs)",
                            "default": False,
                        },
                    },
                    "required": ["host"],
                },
            ),
            MCPTool(
                name="plugin_scan",
                description="Run specific Nikto plugin categories against a target.",
                parameters={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "default": 80},
                        "plugins": {
                            "type": "string",
                            "description": (
                                "Comma-separated plugin names (e.g. 'headers,robots'). "
                                "Available: headers, robots, dictionary, cgi, auth, enumerate"
                            ),
                            "default": "headers,robots",
                        },
                        "ssl": {"type": "boolean", "default": False},
                        "timeout": {"type": "integer", "default": 180},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["host"],
                },
            ),
            MCPTool(
                name="tuning_scan",
                description=(
                    "Run a Nikto scan focused on specific vulnerability categories via -Tuning. "
                    "Categories: 1=interesting files, 2=misconfig, 3=info disclosure, "
                    "4=injection, 5=remote file retrieval, 9=SQL injection, b=auth bypass"
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "default": 80},
                        "tuning": {
                            "type": "string",
                            "description": "Tuning category string (e.g. '9' for SQL, '4' for injection)",
                            "default": "4",
                        },
                        "ssl": {"type": "boolean", "default": False},
                        "timeout": {"type": "integer", "default": 180},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["host"],
                },
            ),
        ]

    async def _handle_tool_call(self, tool_name: str, params: Dict[str, Any]) -> Any:
        handlers = {
            "web_scan": self._web_scan,
            "plugin_scan": self._plugin_scan,
            "tuning_scan": self._tuning_scan,
        }
        handler = handlers.get(tool_name)
        if not handler:
            raise ValueError(f"Unknown tool: {tool_name}")
        return await handler(params)

    # ------------------------------------------------------------------
    # Common scan runner
    # ------------------------------------------------------------------

    async def _run_scan(
        self,
        host: str,
        port: int,
        ssl: bool,
        timeout: int,
        allow_internal: bool,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        _validate_host(host, allow_internal)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as jf:
            json_out = jf.name

        try:
            args = [
                "-h", host,
                "-p", str(port),
                "-Format", "json",
                "-output", json_out,
                "-nointeractive",
            ]
            if ssl:
                args.append("-ssl")
            if extra_args:
                args.extend(extra_args)

            raw_output = await _run_nikto(args, timeout=timeout)

            # Prefer JSON, fall back to text parsing
            vulns = _parse_nikto_json(json_out)
            if not vulns:
                vulns = _parse_nikto_text(raw_output)

        finally:
            try:
                os.unlink(json_out)
            except OSError:
                pass

        return {
            "host": host,
            "port": port,
            "vulnerabilities": vulns,
            "count": len(vulns),
            "raw_summary": raw_output[:2000],
        }

    async def _web_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return await self._run_scan(
            host=params["host"],
            port=params.get("port", 80),
            ssl=params.get("ssl", False),
            timeout=params.get("timeout", 180),
            allow_internal=params.get("allow_internal", False),
        )

    async def _plugin_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        plugins = params.get("plugins", "headers,robots")
        return await self._run_scan(
            host=params["host"],
            port=params.get("port", 80),
            ssl=params.get("ssl", False),
            timeout=params.get("timeout", 180),
            allow_internal=params.get("allow_internal", False),
            extra_args=["-Plugins", plugins],
        )

    async def _tuning_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tuning = params.get("tuning", "4")
        return await self._run_scan(
            host=params["host"],
            port=params.get("port", 80),
            ssl=params.get("ssl", False),
            timeout=params.get("timeout", 180),
            allow_internal=params.get("allow_internal", False),
            extra_args=["-Tuning", tuning],
        )
