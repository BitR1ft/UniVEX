"""
SQLMap MCP Server

Wraps the `sqlmap` binary (available in the Kali Docker container) to expose
five tools over JSON-RPC:

  detect_sqli   — detect SQL injection vulnerabilities in a URL
  dump_database — list all accessible databases
  get_tables    — list tables in a specific database
  get_columns   — list columns in a specific table
  dump_data     — dump data from a table (requires approval)

Port: 8005

Safety controls
---------------
* Requests targeting localhost / RFC-1918 addresses are rejected by default
  unless ``allow_internal=True`` is passed (for lab / HTB environments).
* ``dump_data`` always sets ``requires_approval=True`` — the agent must
  receive human confirmation before exfiltrating data.
* sqlmap is run with ``--batch`` (no interactive prompts) and a bounded
  ``--time-sec`` to prevent indefinite hangs.
* Output is written to a temp directory and parsed from JSON format.

Output schema
-------------
All tools return findings in the canonical application schemas:
  SQLiResult    — injection point, technique, DBMS, confidence
  DbDumpResult  — database → tables → columns → rows
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import tempfile
from typing import Any, Dict, List

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC-1918 / loopback guard (same pattern as ffuf_server)
# ---------------------------------------------------------------------------

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


def _validate_url(url: str, allow_internal: bool) -> None:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must start with http:// or https://: {url}")
    match = re.match(r"https?://([^/:?#]+)", url)
    if not match:
        raise ValueError(f"Cannot extract host from URL: {url}")
    host = match.group(1)
    if not allow_internal and _is_internal(host):
        raise ValueError(
            f"Target host '{host}' appears to be internal/localhost. "
            "Pass allow_internal=true to target lab environments."
        )


# ---------------------------------------------------------------------------
# sqlmap binary path
# ---------------------------------------------------------------------------

SQLMAP_BINARY = os.environ.get("SQLMAP_PATH", "sqlmap")


async def _run_sqlmap(args: List[str], timeout: int = 300) -> str:
    """Run sqlmap with the given arguments and return combined stdout+stderr."""
    cmd = [SQLMAP_BINARY] + args
    logger.debug("sqlmap command: %s", " ".join(cmd))
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=timeout,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        return output
    except asyncio.TimeoutError:
        raise TimeoutError(f"sqlmap timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError(
            "sqlmap binary not found. "
            "Set SQLMAP_PATH environment variable or install sqlmap in PATH."
        )


def _parse_sqli_result(output: str, url: str) -> Dict[str, Any]:
    """Parse sqlmap console output into a SQLiResult dict."""
    injectable = bool(
        re.search(r"is vulnerable|injection point|Parameter:", output, re.IGNORECASE)
    )
    # Extract DBMS
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", output, re.IGNORECASE)
    dbms = dbms_match.group(1).strip() if dbms_match else "unknown"
    # Extract technique
    technique_match = re.search(
        r"(boolean-based blind|time-based blind|error-based|UNION query|stacked queries)",
        output,
        re.IGNORECASE,
    )
    technique = technique_match.group(1) if technique_match else None
    # Extract injectable parameters
    params: List[str] = re.findall(r"Parameter: ([^\s(]+)", output, re.IGNORECASE)

    return {
        "url": url,
        "injectable": injectable,
        "parameters": list(dict.fromkeys(params)),  # dedup, preserve order
        "dbms": dbms,
        "technique": technique,
        "raw_summary": output[:2000],
    }


def _parse_databases(output: str) -> List[str]:
    """Extract database names from sqlmap --dbs output."""
    section = False
    databases: List[str] = []
    for line in output.splitlines():
        if "available databases" in line.lower():
            section = True
            continue
        if section:
            stripped = line.strip()
            if stripped.startswith("*"):
                databases.append(stripped.lstrip("* ").strip())
            elif stripped and not stripped.startswith("["):
                # End of databases section
                if databases:
                    break
    return databases


def _parse_tables(output: str) -> List[str]:
    """Extract table names from sqlmap --tables output."""
    tables: List[str] = []
    in_table_section = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("+") and in_table_section:
            continue
        if "Database:" in line:
            in_table_section = True
            continue
        if in_table_section and stripped.startswith("|"):
            name = stripped.strip("| ").strip()
            if name and name != "Tables":
                tables.append(name)
    return tables


def _parse_columns(output: str) -> List[Dict[str, str]]:
    """Extract column info from sqlmap --columns output."""
    columns: List[Dict[str, str]] = []
    header_seen = False
    for line in output.splitlines():
        stripped = line.strip()
        if "Column" in stripped and "Type" in stripped:
            header_seen = True
            continue
        if header_seen and stripped.startswith("|"):
            parts = [p.strip() for p in stripped.split("|") if p.strip()]
            if len(parts) >= 2:
                columns.append({"column": parts[0], "type": parts[1]})
    return columns


class SQLMapServer(MCPServer):
    """
    MCP Server wrapping the sqlmap SQL injection scanner.

    Provides:
    - detect_sqli   : detect injection points
    - dump_database : list databases
    - get_tables    : list tables in a database
    - get_columns   : list columns in a table
    - dump_data     : dump table data (approval required)
    """

    def __init__(self):
        super().__init__(
            name="sqlmap",
            description="SQL injection detection and exploitation using sqlmap",
            port=8005,
        )

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="detect_sqli",
                description=(
                    "Detect SQL injection vulnerabilities in a URL. "
                    "Returns injectable parameters, DBMS type, and technique."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL with GET parameters (e.g. 'http://10.10.10.1/page?id=1')",
                        },
                        "level": {
                            "type": "integer",
                            "description": "Detection level 1-5 (default 1 = fastest/safest)",
                            "default": 1,
                            "minimum": 1,
                            "maximum": 5,
                        },
                        "risk": {
                            "type": "integer",
                            "description": "Risk level 1-3 (default 1 = lowest impact)",
                            "default": 1,
                            "minimum": 1,
                            "maximum": 3,
                        },
                        "data": {
                            "type": "string",
                            "description": "POST data string (for testing POST parameters)",
                            "default": "",
                        },
                        "cookie": {
                            "type": "string",
                            "description": "HTTP cookie header value",
                            "default": "",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Per-request timeout in seconds (default: 10)",
                            "default": 10,
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow targeting RFC-1918/localhost (for HTB labs)",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="dump_database",
                description="List all accessible databases on the target (requires confirmed SQLi).",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "data": {"type": "string", "description": "POST data", "default": ""},
                        "cookie": {"type": "string", "description": "Cookie header", "default": ""},
                        "dbms": {
                            "type": "string",
                            "description": "DBMS to target (e.g. 'mysql', 'postgresql', 'mssql')",
                            "default": "",
                        },
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="get_tables",
                description="List tables in a specific database.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "database": {"type": "string", "description": "Database name to enumerate"},
                        "data": {"type": "string", "default": ""},
                        "cookie": {"type": "string", "default": ""},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url", "database"],
                },
            ),
            MCPTool(
                name="get_columns",
                description="List columns in a specific table.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "database": {"type": "string"},
                        "table": {"type": "string"},
                        "data": {"type": "string", "default": ""},
                        "cookie": {"type": "string", "default": ""},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url", "database", "table"],
                },
            ),
            MCPTool(
                name="dump_data",
                description=(
                    "Dump data from a specific table. "
                    "⚠️ Requires human approval — this exfiltrates database content."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "database": {"type": "string"},
                        "table": {"type": "string"},
                        "columns": {
                            "type": "string",
                            "description": "Comma-separated column names to dump (empty = all)",
                            "default": "",
                        },
                        "limit_rows": {
                            "type": "integer",
                            "description": "Maximum rows to dump (default: 50)",
                            "default": 50,
                        },
                        "data": {"type": "string", "default": ""},
                        "cookie": {"type": "string", "default": ""},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url", "database", "table"],
                },
                requires_approval=True,
            ),
        ]

    async def _handle_tool_call(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """Dispatch tool calls to handler methods."""
        handlers = {
            "detect_sqli": self._detect_sqli,
            "dump_database": self._dump_database,
            "get_tables": self._get_tables,
            "get_columns": self._get_columns,
            "dump_data": self._dump_data,
        }
        handler = handlers.get(tool_name)
        if not handler:
            raise ValueError(f"Unknown tool: {tool_name}")
        return await handler(params)

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _detect_sqli(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params["url"]
        level = params.get("level", 1)
        risk = params.get("risk", 1)
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        timeout_val = params.get("timeout", 10)
        allow_internal = params.get("allow_internal", False)

        _validate_url(url, allow_internal)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                "--url", url,
                "--batch",
                "--level", str(level),
                "--risk", str(risk),
                "--time-sec", str(timeout_val),
                "--output-dir", tmpdir,
                "--no-cast",
            ]
            if data:
                args += ["--data", data]
            if cookie:
                args += ["--cookie", cookie]

            output = await _run_sqlmap(args, timeout=timeout_val * 20 + 60)

        result = _parse_sqli_result(output, url)
        result["tool"] = "sqlmap"
        result["category"] = "sqli"
        return result

    async def _dump_database(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params["url"]
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        dbms = params.get("dbms", "")
        allow_internal = params.get("allow_internal", False)

        _validate_url(url, allow_internal)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                "--url", url,
                "--batch",
                "--dbs",
                "--output-dir", tmpdir,
            ]
            if data:
                args += ["--data", data]
            if cookie:
                args += ["--cookie", cookie]
            if dbms:
                args += ["--dbms", dbms]

            output = await _run_sqlmap(args, timeout=180)

        databases = _parse_databases(output)
        return {"url": url, "databases": databases, "raw_summary": output[:1500]}

    async def _get_tables(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params["url"]
        database = params["database"]
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        allow_internal = params.get("allow_internal", False)

        _validate_url(url, allow_internal)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                "--url", url,
                "--batch",
                "--tables",
                "-D", database,
                "--output-dir", tmpdir,
            ]
            if data:
                args += ["--data", data]
            if cookie:
                args += ["--cookie", cookie]

            output = await _run_sqlmap(args, timeout=180)

        tables = _parse_tables(output)
        return {"url": url, "database": database, "tables": tables, "raw_summary": output[:1500]}

    async def _get_columns(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params["url"]
        database = params["database"]
        table = params["table"]
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        allow_internal = params.get("allow_internal", False)

        _validate_url(url, allow_internal)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                "--url", url,
                "--batch",
                "--columns",
                "-D", database,
                "-T", table,
                "--output-dir", tmpdir,
            ]
            if data:
                args += ["--data", data]
            if cookie:
                args += ["--cookie", cookie]

            output = await _run_sqlmap(args, timeout=180)

        columns = _parse_columns(output)
        return {
            "url": url,
            "database": database,
            "table": table,
            "columns": columns,
            "raw_summary": output[:1500],
        }

    async def _dump_data(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params["url"]
        database = params["database"]
        table = params["table"]
        columns = params.get("columns", "")
        limit_rows = params.get("limit_rows", 50)
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        allow_internal = params.get("allow_internal", False)

        _validate_url(url, allow_internal)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                "--url", url,
                "--batch",
                "--dump",
                "-D", database,
                "-T", table,
                "--output-dir", tmpdir,
                "--stop", str(limit_rows),
            ]
            if columns:
                args += ["-C", columns]
            if data:
                args += ["--data", data]
            if cookie:
                args += ["--cookie", cookie]

            output = await _run_sqlmap(args, timeout=300)

        # Try to parse CSV from output dir
        rows: List[Dict[str, str]] = []
        csv_dir = os.path.join(tmpdir, "dump", database)
        if os.path.isdir(csv_dir):
            csv_file = os.path.join(csv_dir, f"{table}.csv")
            if os.path.isfile(csv_file):
                with open(csv_file) as fh:
                    import csv
                    reader = csv.DictReader(fh)
                    for i, row in enumerate(reader):
                        if i >= limit_rows:
                            break
                        rows.append(dict(row))

        return {
            "url": url,
            "database": database,
            "table": table,
            "rows": rows,
            "row_count": len(rows),
            "raw_summary": output[:1500],
        }
