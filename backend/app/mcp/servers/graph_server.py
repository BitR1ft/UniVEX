"""
Query Graph MCP Server.

Provides Neo4j attack-graph query capabilities via MCP:
  - query_graph_cypher       : Execute a raw (read-only) Cypher query
  - get_attack_surface       : Overview stats for a project
  - find_attack_paths        : Discover domain → exploit attack paths
  - get_vulnerabilities      : List vulnerabilities filtered by severity
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)


class GraphQueryServer(MCPServer):
    """
    MCP Server for Neo4j graph queries.

    Wraps the project's existing ``graph_queries`` module so the AI agent
    can inspect the attack surface without writing Cypher directly.

    Port: 8004
    """

    def __init__(self, neo4j_uri: str = "bolt://localhost:7687",
                 neo4j_user: str = "neo4j", neo4j_password: str = ""):
        self._neo4j_uri = neo4j_uri
        self._neo4j_user = neo4j_user
        self._neo4j_password = neo4j_password
        super().__init__(
            name="GraphQuery",
            description="Neo4j attack-surface graph query server",
            port=8004,
        )

    # ------------------------------------------------------------------
    # Tool definitions
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="query_graph_cypher",
                description=(
                    "Execute a read-only Cypher query against the Neo4j attack graph. "
                    "Returns up to 'limit' rows as JSON. Write queries are rejected."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "cypher": {
                            "type": "string",
                            "description": "Cypher MATCH query to execute (WRITE operations are blocked)",
                        },
                        "user_id": {"type": "string", "description": "Tenant user ID"},
                        "project_id": {"type": "string", "description": "Tenant project ID"},
                        "limit": {
                            "type": "integer",
                            "description": "Max rows to return (default: 20, max: 100)",
                            "default": 20,
                        },
                    },
                    "required": ["cypher", "user_id", "project_id"],
                },
                phase="scan",
            ),
            MCPTool(
                name="get_attack_surface",
                description=(
                    "Return an overview of the attack surface for a project: "
                    "domain/IP/subdomain/port/vulnerability counts and top exposed services."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                        "project_id": {"type": "string"},
                    },
                    "required": ["user_id", "project_id"],
                },
                phase="scan",
            ),
            MCPTool(
                name="find_attack_paths",
                description=(
                    "Discover attack paths from a domain to exploitable vulnerabilities. "
                    "Returns scored paths ordered by risk (highest first)."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                        "project_id": {"type": "string"},
                        "max_paths": {
                            "type": "integer",
                            "description": "Maximum paths to return (default: 10)",
                            "default": 10,
                        },
                        "min_cvss": {
                            "type": "integer",
                            "description": "Minimum CVSS score filter (0-10, default: 0)",
                            "default": 0,
                        },
                    },
                    "required": ["user_id", "project_id"],
                },
                phase="scan",
            ),
            MCPTool(
                name="get_vulnerabilities",
                description=(
                    "List vulnerabilities for a project, optionally filtered by severity. "
                    "Returns CVE IDs, CVSS scores, affected services, and exploit availability."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string"},
                        "project_id": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "description": "Filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "all"],
                            "default": "all",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max results (default: 50)",
                            "default": 50,
                        },
                    },
                    "required": ["user_id", "project_id"],
                },
                phase="scan",
            ),
        ]

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "query_graph_cypher":
            return await self._query_cypher(params)
        if tool_name == "get_attack_surface":
            return await self._get_attack_surface(params)
        if tool_name == "find_attack_paths":
            return await self._find_attack_paths(params)
        if tool_name == "get_vulnerabilities":
            return await self._get_vulnerabilities(params)
        raise ValueError(f"Unknown tool: {tool_name}")

    # ------------------------------------------------------------------
    # Implementations
    # ------------------------------------------------------------------

    def _get_driver(self):
        """Return a Neo4j AsyncDriver (lazy init)."""
        try:
            from neo4j import AsyncGraphDatabase
            return AsyncGraphDatabase.driver(
                self._neo4j_uri,
                auth=(self._neo4j_user, self._neo4j_password),
            )
        except ImportError:
            raise RuntimeError("neo4j package is not installed")

    def _tenant_filter(self, user_id: str, project_id: str) -> str:
        """Return a Cypher WHERE clause fragment for tenant isolation."""
        return f"n.user_id = '{user_id}' AND n.project_id = '{project_id}'"

    # CALL is intentionally excluded — it can invoke write-capable procedures
    _WRITE_KEYWORDS = {"CREATE", "MERGE", "DELETE", "DETACH", "SET", "REMOVE", "CALL", "DROP"}

    def _is_read_only(self, cypher: str) -> bool:
        """Return True if *cypher* appears to be read-only (starts with MATCH/RETURN/WITH/UNWIND)."""
        first_word = cypher.strip().split()[0].upper() if cypher.strip() else ""
        # CALL is excluded: it may invoke procedures with write side-effects
        return first_word in {"MATCH", "RETURN", "WITH", "UNWIND", "OPTIONAL"}

    def _has_write_op(self, cypher: str) -> bool:
        """Return True if any write keyword is present in the query."""
        upper = cypher.upper()
        return any(kw in upper for kw in self._WRITE_KEYWORDS)

    async def _query_cypher(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cypher: str = params["cypher"]
        params["user_id"]
        project_id: str = params["project_id"]
        limit: int = min(int(params.get("limit", 20)), 100)

        # Safety: reject write operations
        if self._has_write_op(cypher):
            return {
                "success": False,
                "error": "Write operations are not permitted via this tool. Use read-only MATCH queries.",
            }

        # Append tenant-scoping hint (informational; full isolation relies on ingestion)
        logger.info("graph_cypher query for project %s: %s", project_id, cypher[:120])

        try:
            driver = self._get_driver()
            async with driver.session() as session:
                result = await session.run(
                    cypher + f" LIMIT {limit}",
                )
                records = [dict(r) for r in await result.data()]
                await driver.close()
            return {"success": True, "rows": records, "count": len(records)}
        except Exception as exc:
            logger.error("Cypher query failed: %s", exc)
            return {"success": False, "error": str(exc), "rows": []}

    async def _get_attack_surface(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_id = params["user_id"]
        project_id = params["project_id"]

        try:
            from app.graph.graph_queries import AttackSurfaceQueries
            from app.graph.neo4j_client import Neo4jClient

            client = Neo4jClient()
            queries = AttackSurfaceQueries(client)
            overview = await queries.get_attack_surface_overview(user_id, project_id)
            await client.close()
            return {"success": True, "overview": overview}
        except Exception as exc:
            logger.error("get_attack_surface failed: %s", exc)
            return {
                "success": False,
                "error": str(exc),
                "overview": {
                    "domains": 0, "subdomains": 0, "ips": 0,
                    "open_ports": 0, "vulnerabilities": 0,
                },
            }

    async def _find_attack_paths(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_id = params["user_id"]
        project_id = params["project_id"]
        max_paths = int(params.get("max_paths", 10))
        min_cvss = float(params.get("min_cvss", 0))

        try:
            from app.graph.graph_queries import PathFindingQueries
            from app.graph.neo4j_client import Neo4jClient

            client = Neo4jClient()
            queries = PathFindingQueries(client)
            paths = await queries.discover_attack_paths(user_id, project_id)
            await client.close()

            # Filter by min CVSS and cap
            filtered = [
                p for p in paths
                if float(p.get("cvss_score", 0) or 0) >= min_cvss
            ][:max_paths]

            return {"success": True, "paths": filtered, "count": len(filtered)}
        except Exception as exc:
            logger.error("find_attack_paths failed: %s", exc)
            return {"success": False, "error": str(exc), "paths": []}

    async def _get_vulnerabilities(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_id = params["user_id"]
        project_id = params["project_id"]
        severity = params.get("severity", "all")
        limit = int(params.get("limit", 50))

        try:
            from app.graph.graph_queries import VulnerabilityQueries
            from app.graph.neo4j_client import Neo4jClient

            client = Neo4jClient()
            queries = VulnerabilityQueries(client)

            if severity == "all":
                vulns = await queries.get_vulnerabilities_by_severity(user_id, project_id)
            else:
                all_vulns = await queries.get_vulnerabilities_by_severity(user_id, project_id)
                vulns = [v for v in all_vulns if v.get("severity", "").upper() == severity.upper()]

            await client.close()
            return {"success": True, "vulnerabilities": vulns[:limit], "count": len(vulns[:limit])}
        except Exception as exc:
            logger.error("get_vulnerabilities failed: %s", exc)
            return {"success": False, "error": str(exc), "vulnerabilities": []}


if __name__ == "__main__":
    server = GraphQueryServer()
    server.run()
