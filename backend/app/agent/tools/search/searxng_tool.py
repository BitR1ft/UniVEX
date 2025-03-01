"""
SearXNG Meta-Search Tool

Self-hosted privacy-preserving meta-search engine integration.
Points to SEARXNG_URL env var (default: http://searxng:8080).
"""

import logging
import os
from typing import Any

import httpx

from app.agent.tools.base_tool import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)

DEFAULT_SEARXNG_URL = "http://searxng:8080"


class SearxngTool(BaseTool):
    """
    Tool for searching via a self-hosted SearXNG instance.

    Aggregates results from multiple search engines while preserving privacy.
    Requires a running SearXNG instance pointed to by SEARXNG_URL.
    """

    def __init__(self):
        super().__init__()
        self.base_url = os.getenv("SEARXNG_URL", DEFAULT_SEARXNG_URL).rstrip("/")

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="searxng_search",
            description="""Search via self-hosted SearXNG meta-search engine aggregating multiple sources.

Supports category and engine filtering for targeted searches.

Examples:
- "CVE-2023-44487 HTTP/2 rapid reset"
- "SQL injection payloads"
- "Metasploit modules for Windows"

Uses SEARXNG_URL env var (default: http://searxng:8080).""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "categories": {
                        "type": "string",
                        "description": "Comma-separated search categories (e.g. 'general,it,news')",
                        "default": "general",
                    },
                    "engines": {
                        "type": "string",
                        "description": "Comma-separated engines to use (e.g. 'google,bing,duckduckgo')",
                        "default": "",
                    },
                    "language": {
                        "type": "string",
                        "description": "Language code (default: 'en')",
                        "default": "en",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        )

    async def execute(
        self,
        query: str,
        categories: str = "general",
        engines: str = "",
        language: str = "en",
        max_results: int = 10,
        **kwargs: Any,
    ) -> str:
        """
        Execute search via SearXNG.

        Args:
            query: Search query
            categories: Comma-separated category list
            engines: Comma-separated engine list
            language: Language code
            max_results: Maximum results to display

        Returns:
            Formatted search results as string
        """
        try:
            params: dict[str, Any] = {
                "q": query,
                "format": "json",
                "categories": categories,
                "language": language,
            }
            if engines:
                params["engines"] = engines

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(f"{self.base_url}/search", params=params)
                response.raise_for_status()
                data = response.json()

            return self._format_results(data, query, max_results)

        except httpx.HTTPStatusError as e:
            logger.error(f"SearXNG HTTP error: {e}", exc_info=True)
            return f"Error querying SearXNG (HTTP {e.response.status_code}): {e.response.text[:200]}"
        except httpx.RequestError as e:
            logger.error(f"SearXNG request error: {e}", exc_info=True)
            return f"Error connecting to SearXNG at {self.base_url}: {str(e)}"
        except Exception as e:
            logger.error(f"SearXNG unexpected error: {e}", exc_info=True)
            return f"Error querying SearXNG: {str(e)}"

    def _format_results(self, data: dict, query: str, max_results: int) -> str:
        """Format SearXNG API response into a readable string."""
        results = data.get("results", [])
        number_of_results = data.get("number_of_results", len(results))

        if not results:
            return f"No results found on SearXNG for query: '{query}'"

        output = [f"SearXNG search results for '{query}' ({number_of_results} total):\n"]

        for i, result in enumerate(results[:max_results], 1):
            title = result.get("title", "No title")
            url = result.get("url", "")
            content = result.get("content", "")
            engines_used = result.get("engines", [])
            score = result.get("score", None)

            output.append(f"{i}. {title}")
            if url:
                output.append(f"   URL: {url}")
            if content:
                snippet = content[:250] + "..." if len(content) > 250 else content
                output.append(f"   {snippet}")
            if engines_used:
                output.append(f"   Engines: {', '.join(engines_used)}")
            if score is not None:
                output.append(f"   Score: {score:.2f}")
            output.append("")

        return "\n".join(output)
