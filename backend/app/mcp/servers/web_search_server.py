"""
Web Search MCP Server

Provides web search and CVE intelligence capabilities via MCP:
  - web_search           : General Tavily web search with result filtering
  - search_cve           : CVE-focused search returning structured NVD-style data
  - search_exploits      : Exploit-DB / PoC search for a product/CVE
  - enrich_technology    : Technology security advisory search
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)


class WebSearchServer(MCPServer):
    """
    MCP Server for web intelligence and CVE research.

    Uses Tavily AI Search when ``TAVILY_API_KEY`` is set; falls back to a
    stub response in test/offline environments so the rest of the system
    can still function without a live API key.

    Port: 8005
    """

    def __init__(self, api_key: Optional[str] = None):
        self._tavily_key = api_key or os.getenv("TAVILY_API_KEY", "")
        super().__init__(
            name="WebSearch",
            description="Web search and CVE intelligence server",
            port=8005,
        )

    # ------------------------------------------------------------------
    # Tool definitions
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="web_search",
                description=(
                    "Search the web using Tavily AI Search. Returns relevant results "
                    "with titles, URLs, and snippets. Useful for vulnerability research, "
                    "CVE details, and security advisories."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query string",
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return (default: 5, max: 20)",
                            "default": 5,
                        },
                        "search_depth": {
                            "type": "string",
                            "description": "Search depth: 'basic' (faster) or 'advanced' (more results)",
                            "enum": ["basic", "advanced"],
                            "default": "basic",
                        },
                        "include_domains": {
                            "type": "array",
                            "description": "Restrict results to these domains (optional)",
                            "default": [],
                        },
                    },
                    "required": ["query"],
                },
                phase="scan",
            ),
            MCPTool(
                name="search_cve",
                description=(
                    "Look up CVE details by CVE-ID or keyword. Returns CVSS score, "
                    "description, affected products, references, and known exploits."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "cve_id": {
                            "type": "string",
                            "description": "CVE identifier (e.g. 'CVE-2023-1234') or keyword",
                        },
                        "include_exploits": {
                            "type": "boolean",
                            "description": "Also search for known exploits (default: true)",
                            "default": True,
                        },
                    },
                    "required": ["cve_id"],
                },
                phase="scan",
            ),
            MCPTool(
                name="search_exploits",
                description=(
                    "Search for public exploits and proof-of-concept code for a product "
                    "or CVE. Returns links to Exploit-DB, GitHub PoCs, and Metasploit modules."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Product name, CVE-ID, or vulnerability description",
                        },
                        "include_poc": {
                            "type": "boolean",
                            "description": "Include proof-of-concept links (default: true)",
                            "default": True,
                        },
                    },
                    "required": ["target"],
                },
                phase="exploit",
                requires_approval=True,
            ),
            MCPTool(
                name="enrich_technology",
                description=(
                    "Search for security advisories, known vulnerabilities, and hardening "
                    "guides for a specific technology or product version."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "technology": {
                            "type": "string",
                            "description": "Technology name (e.g. 'Apache httpd 2.4.50')",
                        },
                        "version": {
                            "type": "string",
                            "description": "Version string for more targeted results (optional)",
                        },
                    },
                    "required": ["technology"],
                },
                phase="scan",
            ),
        ]

    # ------------------------------------------------------------------
    # Tool dispatch
    # ------------------------------------------------------------------

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "web_search":
            return await self._web_search(params)
        if tool_name == "search_cve":
            return await self._search_cve(params)
        if tool_name == "search_exploits":
            return await self._search_exploits(params)
        if tool_name == "enrich_technology":
            return await self._enrich_technology(params)
        raise ValueError(f"Unknown tool: {tool_name}")

    # ------------------------------------------------------------------
    # Implementations
    # ------------------------------------------------------------------

    async def _call_tavily(
        self,
        query: str,
        max_results: int = 5,
        search_depth: str = "basic",
        include_domains: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Call the Tavily search API.

        Falls back to a stub result when no API key is configured so that
        the server still functions in offline / test environments.
        """
        if not self._tavily_key:
            return [
                {
                    "title": f"[Offline] Result for: {query}",
                    "url": "https://example.com",
                    "content": (
                        "No Tavily API key configured. Set TAVILY_API_KEY to enable "
                        "live web search results."
                    ),
                    "score": 0.0,
                }
            ]

        try:
            from tavily import TavilyClient

            client = TavilyClient(api_key=self._tavily_key)
            kwargs: Dict[str, Any] = {
                "query": query,
                "max_results": min(max_results, 20),
                "search_depth": search_depth,
            }
            if include_domains:
                kwargs["include_domains"] = include_domains

            response = client.search(**kwargs)
            return response.get("results", [])
        except ImportError:
            logger.warning("tavily package not installed — returning stub results")
            return [
                {
                    "title": f"[Stub] {query}",
                    "url": "https://example.com",
                    "content": "tavily package not installed.",
                    "score": 0.0,
                }
            ]
        except Exception as exc:
            logger.error("Tavily search error: %s", exc)
            raise

    async def _web_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        query = params["query"]
        max_results = min(int(params.get("max_results", 5)), 20)
        search_depth = params.get("search_depth", "basic")
        include_domains = params.get("include_domains", [])

        try:
            results = await self._call_tavily(
                query,
                max_results=max_results,
                search_depth=search_depth,
                include_domains=include_domains or None,
            )
            return {
                "success": True,
                "query": query,
                "results": results,
                "count": len(results),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc), "query": query, "results": []}

    async def _search_cve(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = params["cve_id"]
        include_exploits = params.get("include_exploits", True)

        queries = [f"{cve_id} vulnerability CVSS details NVD"]
        if include_exploits:
            queries.append(f"{cve_id} exploit proof of concept")

        try:
            all_results: List[Dict[str, Any]] = []
            for q in queries:
                results = await self._call_tavily(q, max_results=3, search_depth="basic")
                all_results.extend(results)

            return {
                "success": True,
                "cve_id": cve_id,
                "results": all_results,
                "count": len(all_results),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc), "cve_id": cve_id, "results": []}

    async def _search_exploits(self, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params["target"]
        include_poc = params.get("include_poc", True)

        query_parts = [f"{target} exploit site:exploit-db.com OR site:github.com"]
        if include_poc:
            query_parts.append(f"{target} proof of concept PoC RCE")

        try:
            all_results: List[Dict[str, Any]] = []
            for q in query_parts:
                results = await self._call_tavily(q, max_results=5, search_depth="advanced",
                                                  include_domains=["exploit-db.com", "github.com",
                                                                    "packetstormsecurity.com"])
                all_results.extend(results)

            return {
                "success": True,
                "target": target,
                "results": all_results,
                "count": len(all_results),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc), "target": target, "results": []}

    async def _enrich_technology(self, params: Dict[str, Any]) -> Dict[str, Any]:
        technology = params["technology"]
        version = params.get("version", "")

        query = f"{technology} {version} security vulnerabilities CVE advisory".strip()

        try:
            results = await self._call_tavily(query, max_results=5, search_depth="basic")
            return {
                "success": True,
                "technology": technology,
                "version": version,
                "results": results,
                "count": len(results),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc), "technology": technology, "results": []}


if __name__ == "__main__":
    server = WebSearchServer()
    server.run()
