"""
SQLMapTool

Agent tool adapter for the SQLMap MCP server.  Exposes five operations to the
LangGraph ReAct agent:

  sqlmap_detect    — detect SQL injection vulnerabilities
  sqlmap_databases — list accessible databases
  sqlmap_tables    — list tables in a database
  sqlmap_columns   — list columns in a table
  sqlmap_dump      — dump data from a table (requires approval)

All tools are registered for the INFORMATIONAL and EXPLOITATION phases and
added to the AttackPathRouter WEB_APP_ATTACK category.

AutoChain integration
---------------------
If Nuclei finds a vulnerability tagged ``sqli`` the AutoChain orchestrator
will automatically invoke ``sqlmap_detect`` on the affected endpoint.  If
credentials are found in dumped data they are fed to the credential-reuse
pipeline (SSH / FTP / HTTP form login).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_SQLMAP_URL = "http://kali-tools:8005"


class SQLMapDetectTool(BaseTool):
    """
    Detect SQL injection vulnerabilities using sqlmap.

    Returns injection points, DBMS type, and technique used.
    Adds findings to Neo4j as Vulnerability nodes with category 'sqli'.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_SQLMAP_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sqlmap_detect",
            description=(
                "Detect SQL injection vulnerabilities in a URL using sqlmap. "
                "Returns injectable parameters, DBMS type, and injection technique. "
                "Use this when you suspect a web form or URL parameter is vulnerable to SQLi."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL with parameters (e.g. 'http://10.10.10.1/page?id=1')",
                    },
                    "level": {
                        "type": "integer",
                        "description": "Detection thoroughness 1-5 (default 1 = fast & safe)",
                        "default": 1,
                    },
                    "risk": {
                        "type": "integer",
                        "description": "Risk of tests 1-3 (default 1 = lowest impact)",
                        "default": 1,
                    },
                    "data": {
                        "type": "string",
                        "description": "POST body data (for testing POST parameters)",
                        "default": "",
                    },
                    "cookie": {
                        "type": "string",
                        "description": "HTTP Cookie header value",
                        "default": "",
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow targeting RFC-1918 addresses (HTB labs)",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(360)
    async def execute(
        self,
        url: str,
        level: int = 1,
        risk: int = 1,
        data: str = "",
        cookie: str = "",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "level": level,
                "risk": risk,
                "allow_internal": allow_internal,
            }
            if data:
                params["data"] = data
            if cookie:
                params["cookie"] = cookie

            result = await self._client.call_tool("detect_sqli", params)

            if not result.get("success", True) and "error" in result:
                raise ToolExecutionError(result["error"])

            # Persist to Neo4j when project context is available
            if self._project_id and result.get("injectable"):
                await self._ingest_to_graph(url, result)

            return self._format_detect_result(result)

        except ToolExecutionError:
            raise
        except Exception as exc:
            logger.error("sqlmap_detect error: %s", exc, exc_info=True)
            raise ToolExecutionError(str(exc)) from exc

    async def _ingest_to_graph(self, url: str, result: Dict[str, Any]) -> None:
        """Persist SQLi finding to Neo4j attack graph."""
        try:
            from app.graph.ingestion import ingest_sqli_finding

            await ingest_sqli_finding(
                url=url,
                parameters=result.get("parameters", []),
                dbms=result.get("dbms", "unknown"),
                technique=result.get("technique"),
                project_id=self._project_id,
                user_id=self._user_id,
            )
        except Exception as exc:
            logger.warning("Failed to ingest SQLi finding to graph: %s", exc)

    @staticmethod
    def _format_detect_result(result: Dict[str, Any]) -> str:
        url = result.get("url", "")
        injectable = result.get("injectable", False)
        params = result.get("parameters", [])
        dbms = result.get("dbms", "unknown")
        technique = result.get("technique")

        lines = [f"SQLMap Detection Results for: {url}", "=" * 60]
        if injectable:
            lines += [
                "✅ VULNERABLE — SQL injection found!",
                f"   Injectable parameters : {', '.join(params) if params else 'unknown'}",
                f"   DBMS                  : {dbms}",
                f"   Technique             : {technique or 'unknown'}",
                "",
                "Next steps:",
                "  • sqlmap_databases — enumerate accessible databases",
                "  • sqlmap_tables    — list tables in a database",
                "  • sqlmap_dump      — extract credentials (requires approval)",
            ]
        else:
            lines.append("ℹ️  No SQL injection found at this level/risk setting.")
            lines.append("   Try increasing level (2-5) or risk (2-3) if you expect SQLi.")

        summary = result.get("raw_summary", "")
        if summary:
            lines += ["", "--- Raw Output (truncated) ---", summary[:500]]

        return "\n".join(lines)


class SQLMapDatabasesTool(BaseTool):
    """List all databases accessible via a confirmed SQL injection point."""

    def __init__(
        self,
        server_url: str = DEFAULT_SQLMAP_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sqlmap_databases",
            description=(
                "List all accessible databases on a SQL-injectable target. "
                "Run sqlmap_detect first to confirm injection exists."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "data": {"type": "string", "default": ""},
                    "cookie": {"type": "string", "default": ""},
                    "dbms": {
                        "type": "string",
                        "description": "Force DBMS type (e.g. 'mysql')",
                        "default": "",
                    },
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url"],
            },
        )

    @with_timeout(240)
    async def execute(
        self,
        url: str,
        data: str = "",
        cookie: str = "",
        dbms: str = "",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            params: Dict[str, Any] = {"url": url, "allow_internal": allow_internal}
            if data:
                params["data"] = data
            if cookie:
                params["cookie"] = cookie
            if dbms:
                params["dbms"] = dbms

            result = await self._client.call_tool("dump_database", params)

            databases: List[str] = result.get("databases", [])
            if not databases:
                return f"No databases found for {url}. Ensure SQLi is confirmed first."

            lines = [f"Databases on {url}:", "=" * 50]
            for i, db in enumerate(databases, 1):
                lines.append(f"  {i}. {db}")
            lines += [
                "",
                f"Found {len(databases)} database(s).",
                "Use sqlmap_tables to enumerate tables in a specific database.",
            ]
            return "\n".join(lines)

        except Exception as exc:
            logger.error("sqlmap_databases error: %s", exc, exc_info=True)
            raise ToolExecutionError(str(exc)) from exc


class SQLMapTablesTool(BaseTool):
    """List tables in a specific database via SQLi."""

    def __init__(
        self,
        server_url: str = DEFAULT_SQLMAP_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sqlmap_tables",
            description="List tables in a specific database via SQL injection.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "database": {
                        "type": "string",
                        "description": "Database name to enumerate (from sqlmap_databases output)",
                    },
                    "data": {"type": "string", "default": ""},
                    "cookie": {"type": "string", "default": ""},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url", "database"],
            },
        )

    @with_timeout(240)
    async def execute(
        self,
        url: str,
        database: str,
        data: str = "",
        cookie: str = "",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "database": database,
                "allow_internal": allow_internal,
            }
            if data:
                params["data"] = data
            if cookie:
                params["cookie"] = cookie

            result = await self._client.call_tool("get_tables", params)

            tables: List[str] = result.get("tables", [])
            if not tables:
                return f"No tables found in database '{database}' at {url}."

            lines = [f"Tables in database '{database}' ({url}):", "=" * 50]
            for i, tbl in enumerate(tables, 1):
                lines.append(f"  {i}. {tbl}")
            lines += [
                "",
                f"Found {len(tables)} table(s).",
                "Use sqlmap_columns to list columns, or sqlmap_dump to extract data.",
            ]
            return "\n".join(lines)

        except Exception as exc:
            logger.error("sqlmap_tables error: %s", exc, exc_info=True)
            raise ToolExecutionError(str(exc)) from exc


class SQLMapColumnsTool(BaseTool):
    """List columns in a specific table via SQLi."""

    def __init__(
        self,
        server_url: str = DEFAULT_SQLMAP_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sqlmap_columns",
            description="List columns in a specific database table via SQL injection.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "database": {"type": "string"},
                    "table": {"type": "string", "description": "Table name to inspect"},
                    "data": {"type": "string", "default": ""},
                    "cookie": {"type": "string", "default": ""},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url", "database", "table"],
            },
        )

    @with_timeout(240)
    async def execute(
        self,
        url: str,
        database: str,
        table: str,
        data: str = "",
        cookie: str = "",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "database": database,
                "table": table,
                "allow_internal": allow_internal,
            }
            if data:
                params["data"] = data
            if cookie:
                params["cookie"] = cookie

            result = await self._client.call_tool("get_columns", params)

            columns: List[Dict[str, str]] = result.get("columns", [])
            if not columns:
                return f"No columns found for '{database}.{table}'."

            lines = [f"Columns in '{database}.{table}' ({url}):", "=" * 50]
            for col in columns:
                lines.append(f"  {col.get('column', '?')}  ({col.get('type', '?')})")
            lines += ["", f"Found {len(columns)} column(s)."]
            return "\n".join(lines)

        except Exception as exc:
            logger.error("sqlmap_columns error: %s", exc, exc_info=True)
            raise ToolExecutionError(str(exc)) from exc


class SQLMapDumpTool(BaseTool):
    """
    Dump data from a database table via SQLi.

    ⚠️  This tool requires human approval because it exfiltrates data.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_SQLMAP_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="sqlmap_dump",
            description=(
                "⚠️ REQUIRES APPROVAL — Dump data from a database table via SQL injection. "
                "Use to extract credentials, hashes, or sensitive data from a confirmed SQLi target."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "database": {"type": "string"},
                    "table": {"type": "string"},
                    "columns": {
                        "type": "string",
                        "description": "Comma-separated columns to extract (empty = all)",
                        "default": "",
                    },
                    "limit_rows": {
                        "type": "integer",
                        "description": "Max rows to dump (default: 50)",
                        "default": 50,
                    },
                    "data": {"type": "string", "default": ""},
                    "cookie": {"type": "string", "default": ""},
                    "allow_internal": {"type": "boolean", "default": False},
                },
                "required": ["url", "database", "table"],
            },
        )

    @with_timeout(360)
    async def execute(
        self,
        url: str,
        database: str,
        table: str,
        columns: str = "",
        limit_rows: int = 50,
        data: str = "",
        cookie: str = "",
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "database": database,
                "table": table,
                "limit_rows": limit_rows,
                "allow_internal": allow_internal,
            }
            if columns:
                params["columns"] = columns
            if data:
                params["data"] = data
            if cookie:
                params["cookie"] = cookie

            result = await self._client.call_tool("dump_data", params)

            rows: List[Dict[str, str]] = result.get("rows", [])
            row_count = result.get("row_count", len(rows))

            if not rows:
                return f"No data dumped from '{database}.{table}'. Check that SQLi is confirmed."

            lines = [
                f"Data from '{database}.{table}' ({url}):",
                "=" * 60,
            ]
            if rows:
                # Header
                headers = list(rows[0].keys())
                lines.append("  " + " | ".join(headers))
                lines.append("  " + "-" * max(40, len(" | ".join(headers))))
                for row in rows:
                    lines.append("  " + " | ".join(str(row.get(h, "")) for h in headers))

            lines += ["", f"Dumped {row_count} row(s) from '{table}'."]

            # Hint for credential extraction
            credential_hints = {"password", "passwd", "hash", "pwd", "secret", "token"}
            col_names = {c.lower() for c in (list(rows[0].keys()) if rows else [])}
            if col_names & credential_hints:
                lines += [
                    "",
                    "🔑 Credential columns detected! Try these next steps:",
                    "  • hashcat / john to crack hashed passwords",
                    "  • Try credentials against SSH, FTP, or web login form",
                ]

            return truncate_output("\n".join(lines), max_chars=4000)

        except Exception as exc:
            logger.error("sqlmap_dump error: %s", exc, exc_info=True)
            raise ToolExecutionError(str(exc)) from exc
